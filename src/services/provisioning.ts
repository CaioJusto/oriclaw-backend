import crypto from 'crypto';
import zlib from 'zlib';
import axios from 'axios';
import Stripe from 'stripe';
import { deleteDroplet, getDroplet, getDropletPrivateIP, getDropletPublicIP } from './digitalocean';
import {
  createInstance,
  getInstanceById,
  getInstanceBySubscriptionId,
  updateInstance,
  supabase,
} from './supabase';
import { CLOUD_INIT_SCRIPT } from './cloudInit';
import { ProvisionRequest, DODroplet, DODropletResponse } from '../types';
import { encrypt, decrypt } from './crypto';
import { AGENT_PRIVATE_CIDRS } from './agentNetwork';
import {
  buildPinnedAgentHttpsAgent,
  createProvisionedAgentTlsMaterial,
  type AgentTlsMaterial,
} from './agentTls';
import { VPS_AGENT_PACKAGE_JSON_GZIP_B64, VPS_AGENT_SERVER_JS_GZIP_B64 } from './vpsAgentAssets';

// ── DO API rate-limit guard ───────────────────────────────────────────────────
// Limits simultaneous droplet creations to avoid hitting DigitalOcean's rate
// limit (typically 10 droplets/minute). Counter tracks async createDropletAsync
// coroutines in flight; decremented in the finally block of each.
let activeProvisioningCount = 0;
const MAX_CONCURRENT_PROVISIONING = 2;

export async function provisionInstance(
  req: ProvisionRequest
): Promise<{ instance_id: string; status: string }> {
  console.log(`[provision] Starting for customer: ${req.customer_id}`);

  // Bug fix #5: Reject early if too many droplets are being provisioned simultaneously
  if (activeProvisioningCount >= MAX_CONCURRENT_PROVISIONING) {
    throw new Error(
      `Limite de provisionamentos simultâneos atingido (${MAX_CONCURRENT_PROVISIONING}). ` +
      'Tente novamente em alguns minutos.'
    );
  }

  // Bug fix: reserve the semaphore slot BEFORE any async operation so that two
  // concurrent calls can't both pass the >= check before either increments.
  activeProvisioningCount++;

  // Generate random agent secret for this instance
  const agentSecret = crypto.randomBytes(32).toString('hex');
  const agentTls = createProvisionedAgentTlsMaterial();

  let instance: Awaited<ReturnType<typeof createInstance>>;
  try {
    // Create DB record first (status='provisioning' — dashboard sees this immediately)
    instance = await createInstance({
      customer_id: req.customer_id,
      email: req.email,
      plan: req.plan,
      droplet_id: null,
      droplet_ip: null,
      status: 'provisioning',
      stripe_subscription_id: req.stripe_subscription_id ?? null,
      api_key_encrypted: req.api_key_anthropic ? encrypt(req.api_key_anthropic) : null,
      metadata: {
        agent_secret: encrypt(agentSecret),
        agent_tls_cert_pem: agentTls.certPem,
        agent_tls_fingerprint256: agentTls.fingerprint256,
      },
    });
  } catch (dbErr) {
    // If the DB insert fails, release the reserved slot before re-throwing
    activeProvisioningCount--;
    throw dbErr;
  }

  // Create DO Droplet (non-blocking — status will update async)
  createDropletAsync(instance.id, req.customer_id, agentSecret, agentTls, req.stripe_subscription_id ?? null)
    .catch(async (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[provision] Droplet creation failed for ${instance.id}:`, msg);
      // Attempt to cancel the Stripe subscription so the user isn't billed for a
      // failed provisioning. Re-fetch the instance to get the subscription ID in
      // case it was bound by customer.subscription.created after checkout.
      await cancelSubscriptionForInstance(instance.id, req.stripe_subscription_id ?? null);
      // Bug fix #2: preserve agent_secret and add suspended_reason
      updateInstance(instance.id, {
        status: 'suspended',
        metadata: {
          agent_secret: encrypt(agentSecret),
          agent_tls_cert_pem: agentTls.certPem,
          agent_tls_fingerprint256: agentTls.fingerprint256,
          error: msg,
          suspended_reason: 'provisioning_failed',
        },
      }).catch(console.error);
    })
    .finally(() => {
      activeProvisioningCount--;
    });

  return { instance_id: instance.id, status: 'provisioning' };
}

function wrapCloudInitScript(rawScript: string): string {
  const compressed = zlib.gzipSync(Buffer.from(rawScript, 'utf8'));
  const b64 = compressed.toString('base64');
  return `#!/bin/bash
echo '${b64}' | base64 -d | gunzip > /tmp/oriclaw-init.sh
chmod +x /tmp/oriclaw-init.sh
/tmp/oriclaw-init.sh
`;
}

const PLAN_SIZES: Record<string, string> = {
  'starter': 's-1vcpu-2gb',
  'pro': 's-2vcpu-4gb',
  'business': 's-4vcpu-8gb',
};

const DEFAULT_DROPLET_REGION = process.env.ORICLAW_DROPLET_REGION || 'nyc1';
const DEFAULT_VPC_ID = process.env.ORICLAW_VPC_ID || '';

// If set, provision from a pre-built snapshot instead of cloud-init.
// This reduces provisioning time from ~7 min to ~1 min.
const SNAPSHOT_ID = process.env.ORICLAW_SNAPSHOT_ID || '';

/**
 * Patch-oriented cloud-init for snapshot-based provisioning.
 * Refreshes the agent/runtime configuration at boot so golden snapshots do not
 * need to be rebuilt for every code deploy.
 */
function buildSnapshotCloudInit(
  agentSecret: string,
  gatewayToken: string,
  agentTls: AgentTlsMaterial
): string {
  return `#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export AGENT_PRIVATE_CIDRS='${AGENT_PRIVATE_CIDRS.join(',')}'
export GATEWAY_TOKEN='${gatewayToken}'

# Stop services before overwriting secrets
systemctl stop openclaw 2>/dev/null || true
systemctl stop oriclaw-agent 2>/dev/null || true

PUBLIC_IP=$(curl -s --max-time 5 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || true)
PRIVATE_IP=$(curl -s --max-time 5 http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address 2>/dev/null || true)
if [ -z "$PUBLIC_IP" ]; then
  PUBLIC_IP=$(hostname -I | awk '{print $1}')
fi
SSLIP_DOMAIN=""
if [ -n "$PUBLIC_IP" ]; then
  SSLIP_DOMAIN=$(echo "$PUBLIC_IP" | tr '.' '-').sslip.io
fi

apt-get update -y
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl wget git ufw nginx python3 python3-pip build-essential || true

if ! swapon --show | grep -q '/swapfile'; then
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
cat > /etc/sysctl.d/99-oriclaw-memory.conf << 'SYSCTLEOF'
vm.swappiness=10
vm.vfs_cache_pressure=50
SYSCTLEOF
sysctl --system >/dev/null 2>&1 || true

useradd -m -s /bin/bash openclaw 2>/dev/null || true
mkdir -p /home/openclaw/.openclaw /home/openclaw/.openclaw/.openclaw
mkdir -p /var/tmp/openclaw-compile-cache
chown -R openclaw:openclaw /home/openclaw /var/tmp/openclaw-compile-cache

if [ ! -x /home/openclaw/.npm-global/bin/openclaw ] && [ ! -x /home/openclaw/.local/bin/openclaw ]; then
  echo "[oriclaw] ERROR: openclaw binary not found under /home/openclaw" >&2
  exit 1
fi

cat > /usr/local/bin/openclaw << 'OPENCLAWEOF'
#!/bin/bash
set -e

OPENCLAW_BIN=""
for candidate in /home/openclaw/.npm-global/bin/openclaw /home/openclaw/.local/bin/openclaw; do
  if [ -x "$candidate" ]; then
    OPENCLAW_BIN="$candidate"
    break
  fi
done

if [ -z "$OPENCLAW_BIN" ]; then
  echo "openclaw binary not found under /home/openclaw" >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  exec sudo -u openclaw HOME=/home/openclaw OPENCLAW_HOME=/home/openclaw/.openclaw "$OPENCLAW_BIN" "$@"
fi

exec env HOME=/home/openclaw OPENCLAW_HOME=/home/openclaw/.openclaw "$OPENCLAW_BIN" "$@"
OPENCLAWEOF
chmod 755 /usr/local/bin/openclaw

useradd -r -s /usr/sbin/nologin oriclaw-agent 2>/dev/null || true
usermod -aG systemd-journal oriclaw-agent 2>/dev/null || true
usermod -aG openclaw oriclaw-agent 2>/dev/null || true

# Inject agent secret
cat > /etc/oriclaw-agent.env << 'ENVEOF'
AGENT_SECRET=${agentSecret}
PORT=8080
ENVEOF
chmod 600 /etc/oriclaw-agent.env
chown oriclaw-agent:oriclaw-agent /etc/oriclaw-agent.env

mkdir -p /opt/oriclaw-agent
cat <<'PKGB64' | base64 -d | gunzip > /opt/oriclaw-agent/package.json
${VPS_AGENT_PACKAGE_JSON_GZIP_B64}
PKGB64
cat <<'SERVERB64' | base64 -d | gunzip > /opt/oriclaw-agent/server.js
${VPS_AGENT_SERVER_JS_GZIP_B64}
SERVERB64
chown -R oriclaw-agent:oriclaw-agent /opt/oriclaw-agent

cd /opt/oriclaw-agent
for attempt in 1 2 3; do
  npm install --omit=dev --no-fund --no-audit && break
  echo "[oriclaw] npm install attempt $attempt failed, retrying in 10s..."
  sleep 10
done

mkdir -p /etc/oriclaw-agent/tls
echo '${agentTls.certPemB64}' | base64 -d > /etc/oriclaw-agent/tls/cert.pem
echo '${agentTls.keyPemB64}' | base64 -d > /etc/oriclaw-agent/tls/key.pem
chmod 600 /etc/oriclaw-agent/tls/key.pem
chmod 644 /etc/oriclaw-agent/tls/cert.pem

cat > /etc/systemd/system/openclaw.service << 'SVCEOF'
[Unit]
Description=OpenClaw Gateway
After=network.target

[Service]
Type=simple
User=openclaw
Group=openclaw
WorkingDirectory=/home/openclaw
Environment=HOME=/home/openclaw
Environment=OPENCLAW_HOME=/home/openclaw/.openclaw
Environment=OPENCLAW_NO_RESPAWN=1
Environment=NODE_OPTIONS=--max-old-space-size=1280
Environment=NODE_COMPILE_CACHE=/var/tmp/openclaw-compile-cache
EnvironmentFile=-/home/openclaw/.openclaw/.env
ExecStart=/usr/local/bin/openclaw gateway run --allow-unconfigured --bind lan
Restart=on-failure
RestartSec=10
TimeoutStartSec=90
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

mkdir -p /etc/systemd/system/openclaw.service.d
touch /etc/systemd/system/openclaw.service.d/openrouter.conf
chmod 600 /etc/systemd/system/openclaw.service.d/openrouter.conf

cat > /etc/sudoers.d/oriclaw-agent << 'SUDOEOF'
oriclaw-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart openclaw, /usr/bin/systemctl start openclaw, /usr/bin/systemctl stop openclaw, /usr/bin/systemctl reset-failed openclaw, /usr/bin/systemctl is-active openclaw, /usr/bin/systemctl status openclaw
Defaults:oriclaw-agent env_keep += "OPENCLAW_HOME HOME"
oriclaw-agent ALL=(openclaw) NOPASSWD: SETENV: /usr/local/bin/openclaw
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cat /home/openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cat /home/openclaw/.openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw/.openclaw
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/tee /home/openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/tee /home/openclaw/.openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cat /home/openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cat /home/openclaw/.openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw/credentials
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw/.openclaw/credentials
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/chmod 700 /home/openclaw/.openclaw/credentials
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/chmod 700 /home/openclaw/.openclaw/.openclaw/credentials
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/tee /home/openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/tee /home/openclaw/.openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/chmod 600 /home/openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/chmod 600 /home/openclaw/.openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/chmod 600 /home/openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/chmod 600 /home/openclaw/.openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mv /home/openclaw/.openclaw/* /home/openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mv /home/openclaw/.openclaw/.openclaw/* /home/openclaw/.openclaw/.openclaw/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mv /home/openclaw/.openclaw/credentials/* /home/openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mv /home/openclaw/.openclaw/.openclaw/credentials/* /home/openclaw/.openclaw/.openclaw/credentials/*
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw/credentials/whatsapp/default
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cp -r /tmp/oriclaw-wa-auth/. /home/openclaw/.openclaw/credentials/whatsapp/default
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw/.openclaw/channels/whatsapp/default/auth
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cp -r /tmp/oriclaw-wa-auth/. /home/openclaw/.openclaw/.openclaw/channels/whatsapp/default/auth
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/mkdir -p /home/openclaw/.openclaw/channels/whatsapp/default/auth
oriclaw-agent ALL=(openclaw) NOPASSWD: /usr/bin/cp -r /tmp/oriclaw-wa-auth/. /home/openclaw/.openclaw/channels/whatsapp/default/auth
oriclaw-agent ALL=(root) NOPASSWD: /bin/mkdir -p /etc/systemd/system/openclaw.service.d
oriclaw-agent ALL=(root) NOPASSWD: /usr/bin/tee /etc/systemd/system/openclaw.service.d/*
oriclaw-agent ALL=(root) NOPASSWD: /bin/chmod 600 /etc/systemd/system/openclaw.service.d/*
oriclaw-agent ALL=(root) NOPASSWD: /bin/systemctl daemon-reload
SUDOEOF
chmod 440 /etc/sudoers.d/oriclaw-agent

cat > /etc/systemd/system/oriclaw-agent.service << 'AGENTEOF'
[Unit]
Description=ConectaClaw VPS Agent
After=network.target

[Service]
Type=simple
User=oriclaw-agent
WorkingDirectory=/opt/oriclaw-agent
EnvironmentFile=/etc/oriclaw-agent.env
ExecStart=/usr/bin/node /opt/oriclaw-agent/server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
AGENTEOF

chmod 775 /home/openclaw/.openclaw
chmod 664 /home/openclaw/.openclaw/.env 2>/dev/null || true
chmod 664 /home/openclaw/.openclaw/config.json 2>/dev/null || true
chmod g+s /home/openclaw/.openclaw

python3 <<'PY'
import json
import os
from pathlib import Path

gateway_token = os.environ.get('GATEWAY_TOKEN', '')
public_ip = os.environ.get('PUBLIC_IP', '')
sslip_domain = os.environ.get('SSLIP_DOMAIN', '')
allowed_origins = []
if sslip_domain:
    allowed_origins.append(f"https://{sslip_domain}")

path_specs = [
    (Path('/home/openclaw/.openclaw/.openclaw/openclaw.json'), True),
    (Path('/home/openclaw/.openclaw/openclaw.json'), True),
    (Path('/home/openclaw/.openclaw/config.json'), False),
]

for config_path, native_only in path_specs:
    if not config_path.exists():
        continue
    try:
        raw = config_path.read_text()
        cfg = json.loads(raw) if raw.strip() else {}
    except Exception:
        cfg = {}

    cfg.setdefault('gateway', {})
    cfg['gateway']['mode'] = 'local'
    cfg['gateway']['bind'] = 'lan'
    cfg['gateway'].setdefault('auth', {})
    cfg['gateway']['auth']['mode'] = 'token'
    cfg['gateway']['auth']['token'] = gateway_token
    if allowed_origins:
        cfg['gateway'].setdefault('controlUi', {})
        cfg['gateway']['controlUi']['allowedOrigins'] = allowed_origins

    channels = cfg.setdefault('channels', {})
    for channel_name in ('telegram', 'discord'):
        channel_cfg = channels.setdefault(channel_name, {})
        if isinstance(channel_cfg, dict):
            channel_cfg.setdefault('enabled', False)
        else:
            channels[channel_name] = {'enabled': False}

    whatsapp_cfg = channels.get('whatsapp')
    if isinstance(whatsapp_cfg, dict):
        whatsapp_cfg['enabled'] = False
    elif whatsapp_cfg is not None:
        channels['whatsapp'] = {'enabled': False}

    plugins = cfg.setdefault('plugins', {})
    entries = plugins.setdefault('entries', {})
    whatsapp_plugin = entries.get('whatsapp')
    if isinstance(whatsapp_plugin, dict):
        whatsapp_plugin['enabled'] = False
    elif whatsapp_plugin is not None:
        entries['whatsapp'] = {'enabled': False}

    if native_only:
        for legacy_key in ('model', 'channel', 'ai_mode', 'assistant_name', 'system_prompt', 'language', 'timezone', 'discord_guild_id'):
            cfg.pop(legacy_key, None)
    else:
        if cfg.get('channel') not in ('telegram', 'discord'):
            cfg['channel'] = 'telegram'
        if cfg.get('model') == 'claude-sonnet-4-5':
            cfg['model'] = 'claude-sonnet-4.6'

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(cfg, indent=2))
PY
chown -R openclaw:openclaw /home/openclaw/.openclaw

# Clean any leftover state from snapshot
rm -rf /home/openclaw/.openclaw/session /home/openclaw/.openclaw/.wwebjs_auth /home/openclaw/.openclaw/.baileys 2>/dev/null || true
rm -rf /home/openclaw/.openclaw/credentials/whatsapp /home/openclaw/.openclaw/.openclaw/channels/whatsapp/default/auth /home/openclaw/.openclaw/channels/whatsapp/default/auth 2>/dev/null || true

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
IFS=',' read -r -a AGENT_CIDR_LIST <<< "$AGENT_PRIVATE_CIDRS"
for cidr in "\${AGENT_CIDR_LIST[@]}"; do
  cidr="$(echo "$cidr" | xargs)"
  [ -n "$cidr" ] || continue
  ufw allow from "$cidr" to any port 8080 proto tcp
done
ufw allow 443/tcp
ufw --force enable

if [ -n "$SSLIP_DOMAIN" ]; then
  apt-get install -y -o Dpkg::Options::="--force-confdef" certbot python3-certbot-nginx 2>/dev/null || true
  systemctl start nginx 2>/dev/null || true
  certbot certonly --nginx -d "$SSLIP_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email 2>/dev/null || true

  if [ -f "/etc/letsencrypt/live/$SSLIP_DOMAIN/fullchain.pem" ]; then
    SSL_CERT="/etc/letsencrypt/live/$SSLIP_DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$SSLIP_DOMAIN/privkey.pem"
    SSL_EXTRA="include /etc/letsencrypt/options-ssl-nginx.conf;
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;"
  else
    SSL_CERT="/etc/oriclaw-agent/tls/cert.pem"
    SSL_KEY="/etc/oriclaw-agent/tls/key.pem"
    SSL_EXTRA=""
  fi

  cat > /etc/nginx/sites-available/openclaw-gateway << NGXEOF
server {
    listen 443 ssl;
    server_name $SSLIP_DOMAIN;

    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    $SSL_EXTRA

    location / {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\\$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
NGXEOF
  ln -sf /etc/nginx/sites-available/openclaw-gateway /etc/nginx/sites-enabled/openclaw-gateway
  rm -f /etc/nginx/sites-enabled/default
fi

# Start services
systemctl daemon-reload
systemctl enable openclaw oriclaw-agent nginx 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl restart openclaw
systemctl start oriclaw-agent

echo "ORICLAW_READY" > /var/lib/cloud/instance/oriclaw-status
`;
}

/**
 * cancelSubscriptionForInstance — best-effort: cancel Stripe subscription for an
 * instance whose provisioning failed so the user isn't billed for a broken VPS.
 * Re-fetches the instance to get the latest stripe_subscription_id (it may have
 * been bound by customer.subscription.created after checkout.session.completed).
 */
async function cancelSubscriptionForInstance(
  instanceId: string,
  knownSubId: string | null
): Promise<void> {
  if (!process.env.STRIPE_SECRET_KEY) return;
  let subId = knownSubId;
  if (!subId) {
    try {
      const latest = await getInstanceById(instanceId);
      subId = latest?.stripe_subscription_id ?? null;
    } catch { /* ignore — best effort */ }
  }
  if (!subId) return;
  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2026-02-25.clover' });
  try {
    await stripe.subscriptions.cancel(subId);
    console.log(`[provision] Cancelled Stripe subscription ${subId} after provisioning failure for instance ${instanceId}`);
  } catch (cancelErr: unknown) {
    // 'already_cancelled' or similar errors are expected — just log and move on
    console.error(
      `[provision] Failed to cancel subscription ${subId}:`,
      cancelErr instanceof Error ? cancelErr.message : String(cancelErr)
    );
  }
}

async function createDropletAsync(
  instanceId: string,
  customerId: string,
  agentSecret: string,
  agentTls: AgentTlsMaterial,
  stripeSubId: string | null
): Promise<void> {
  // Generate gateway token for OpenClaw UI auth
  const gatewayToken = crypto.randomBytes(32).toString('hex');

  // Get instance to determine plan-based droplet size
  const instanceForPlan = await getInstanceById(instanceId);
  const planSize = PLAN_SIZES[instanceForPlan?.plan ?? 'starter'] ?? 's-1vcpu-2gb';

  let droplet: DODroplet;

  if (SNAPSHOT_ID) {
    // ── Snapshot-based provisioning (~1 min) ──
    // Uses a pre-built golden image plus a patch script that refreshes runtime files.
    console.log(`[provision] Using snapshot ${SNAPSHOT_ID} for instance ${instanceId}`);
    const cloudInit = wrapCloudInitScript(buildSnapshotCloudInit(agentSecret, gatewayToken, agentTls));
    droplet = await createDropletWithInit(customerId, cloudInit, planSize, SNAPSHOT_ID);
  } else {
    // ── Full cloud-init provisioning (~7 min) ──
    // Compresses the full script with gzip+base64 to stay under DO's 16KB user_data limit.
    const rawScript = CLOUD_INIT_SCRIPT
      .replace(/__AGENT_SECRET__/g, agentSecret)
      .replace(/__GATEWAY_TOKEN__/g, gatewayToken)
      .replace(/__AGENT_TLS_CERT_PEM_B64__/g, agentTls.certPemB64)
      .replace(/__AGENT_TLS_KEY_PEM_B64__/g, agentTls.keyPemB64);
    const cloudInit = wrapCloudInitScript(rawScript);
    droplet = await createDropletWithInit(customerId, cloudInit, planSize);
  }
  console.log(`[provision] Droplet created: ${droplet.id} (status=${droplet.status}) for instance ${instanceId}`);

  const currentAfterCreate = await getInstanceById(instanceId);
  if (!currentAfterCreate || currentAfterCreate.status === 'deleted') return;
  await updateInstance(instanceId, {
    droplet_id: droplet.id,
    metadata: { droplet_name: droplet.name, agent_secret: encrypt(agentSecret) },
  });

  // Poll for droplet IP (up to 3 minutes)
  let ip: string | null = null;
  let privateIp: string | null = null;
  for (let i = 0; i < 18; i++) {
    await sleep(10_000);
    try {
      const updated = await getDroplet(droplet.id);
      console.log(`[provision] Poll ${i+1}/18: droplet ${droplet.id} status=${updated.status}`);
      ip = getDropletPublicIP(updated);
      privateIp = getDropletPrivateIP(updated);
      if (ip && privateIp) break;
    } catch (pollErr: unknown) {
      const axErr = pollErr as { response?: { status?: number; data?: unknown }; message?: string };
      console.error(`[provision] Poll ${i+1}/18: GET droplet ${droplet.id} failed:`, {
        status: axErr.response?.status,
        data: axErr.response?.data,
        message: axErr.message ?? String(pollErr),
      });
      // If 404, droplet was destroyed — break early
      if (axErr.response?.status === 404) {
        console.error(`[provision] Droplet ${droplet.id} returned 404 — was likely destroyed by DigitalOcean`);
        break;
      }
    }
  }

  if (!ip) {
    // Cancel Stripe subscription — user shouldn't be billed for a VPS without IP
    await cancelSubscriptionForInstance(instanceId, stripeSubId);
    // Bug fix #2: add suspended_reason so dashboard can show meaningful message
    await updateInstance(instanceId, {
      status: 'suspended',
      metadata: {
        droplet_name: droplet.name,
        agent_secret: encrypt(agentSecret),
        error: 'Droplet não obteve IP em tempo hábil',
        suspended_reason: 'provisioning_failed_no_ip',
      },
    });
    return;
  }

  // Wait until VPS agent is responding on /health before exposing needs_config.
  // Snapshot deploys are much faster (~1 min), so use a shorter timeout.
  const agentTimeoutMs = SNAPSHOT_ID ? 5 * 60 * 1000 : 20 * 60 * 1000;
  const agentHosts = [privateIp, ip].filter((value): value is string => Boolean(value));
  const agentReady = await waitForAgentReadiness(agentHosts, agentSecret, agentTls.certPem, agentTls.fingerprint256, agentTimeoutMs);
  if (!agentReady) {
    // Cancel Stripe subscription — user shouldn't be billed for an unresponsive VPS
    await cancelSubscriptionForInstance(instanceId, stripeSubId);
    // Bug fix #2: add suspended_reason
    await updateInstance(instanceId, {
      droplet_ip: ip,
      status: 'suspended',
      metadata: {
        droplet_name: droplet.name,
        agent_secret: encrypt(agentSecret),
        agent_private_ip: privateIp,
        agent_public_ip: ip,
        error: 'VPS agent não respondeu após 20 minutos',
        suspended_reason: 'provisioning_failed_agent_timeout',
      },
    });
    return;
  }

  const current = await getInstanceById(instanceId);
  if (!current || current.status === 'suspended' || current.status === 'deleted') {
    console.warn(`[provision] Instance ${instanceId} is ${current?.status} — aborting needs_config transition`);
    return;
  }
  await updateInstance(instanceId, {
    droplet_ip: ip,
    status: 'needs_config',
    metadata: {
      droplet_name: droplet.name,
      agent_secret: encrypt(agentSecret),
      agent_private_ip: privateIp,
      agent_public_ip: ip,
    },
  });

  console.log(`[provision] Instance ${instanceId} ready for config at ${ip}`);
}

export async function deprovisionInstance(subscriptionId: string): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) {
    console.warn(`[deprovision] No instance found for subscription: ${subscriptionId}`);
    return;
  }

  if (instance.droplet_id) {
    try {
      await deleteDroplet(instance.droplet_id);
      console.log(`[deprovision] Droplet ${instance.droplet_id} deleted`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[deprovision] Failed to delete droplet: ${msg}`);
      await updateInstance(instance.id, {
        status: 'deletion_failed',
        metadata: { ...(instance.metadata ?? {}), error: msg },
      });
      return;
    }

    // Verify droplet is actually gone (DO API returns 404 for deleted droplets)
    try {
      await getDroplet(instance.droplet_id);
      // If we get here, droplet still exists — mark as deletion_failed
      console.warn(`[deprovision] Droplet ${instance.droplet_id} still exists after DELETE`);
      await updateInstance(instance.id, {
        status: 'deletion_failed',
        metadata: { ...(instance.metadata ?? {}), error: 'Droplet still exists after deletion request' },
      });
      return;
    } catch {
      // 404 = droplet is gone, which is what we want
    }
  }

  await updateInstance(instance.id, { status: 'deleted' });
}

export async function suspendInstance(subscriptionId: string, reason = 'payment_failed'): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) return;
  // Bug fix #2: preserve existing metadata and add suspended_reason so the
  // dashboard can distinguish "payment suspended" from "provisioning failed"
  const existingMeta = (instance.metadata ?? {}) as Record<string, unknown>;
  await updateInstance(instance.id, {
    status: 'suspended',
    metadata: { ...existingMeta, suspended_reason: reason },
  });
}

export async function reactivateInstance(subscriptionId: string): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) {
    console.log(`[reactivate] No instance found for subscription: ${subscriptionId}`);
    return;
  }
  if (instance.status === 'suspended') {
    // Não reativar se a VPS nunca chegou a ter IP (falha de provisionamento)
    const meta = instance.metadata as Record<string, unknown> | null;
    const provisioningFailed = meta?.error && !instance.droplet_ip;
    if (provisioningFailed) {
      console.warn(`[reactivate] Instance ${instance.id} was suspended due to provisioning failure — not reactivating automatically`);
      // Manter suspended — o suporte precisará intervir ou re-provisionar
      return;
    }
    const wasConfigured = !!(meta?.ai_mode);
    const newStatus = wasConfigured ? 'running' : 'needs_config';
    await updateInstance(instance.id, {
      status: newStatus,
      metadata: { ...(meta ?? {}), reactivated_at: new Date().toISOString(), error: undefined },
    });
    console.log(`[reactivate] Instance ${instance.id} reactivated to ${newStatus}`);
  }
}

export async function updateApiKey(instanceId: string, apiKey: string): Promise<void> {
  await updateInstance(instanceId, { api_key_encrypted: encrypt(apiKey) });
  console.log(`[updateApiKey] Stored new encrypted API key for instance ${instanceId} (configure via /proxy)`);
}

/**
 * Bug fix #3: retryPendingDeletions — called at startup to resolve instances
 * stuck in 'deletion_failed' state. deleteDroplet treats 404 as success, so
 * retrying is safe and idempotent.
 */
export async function retryPendingDeletions(): Promise<void> {
  try {
    const { data: failing } = await supabase
      .from('oriclaw_instances')
      .select('id, droplet_id, metadata')
      .eq('status', 'deletion_failed');

    if (!failing || failing.length === 0) return;

    console.log(`[startup] Found ${failing.length} deletion_failed instance(s), retrying`);

    for (const inst of failing) {
      try {
        if (inst.droplet_id) {
          await deleteDroplet(inst.droplet_id as number);
        }
        await updateInstance(inst.id, { status: 'deleted' });
        console.log(`[startup] Retry deletion succeeded for instance ${inst.id}`);
      } catch (err) {
        console.warn(
          `[startup] Retry deletion failed for ${inst.id}:`,
          err instanceof Error ? err.message : err
        );
      }
    }
  } catch (err) {
    console.warn('[startup] Could not check for deletion_failed instances:', err);
  }
}

export { decrypt };

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForAgentReadiness(
  hosts: string[],
  agentSecret: string,
  certPem: string,
  fingerprint256: string,
  maxWaitMs: number
): Promise<boolean> {
  if (hosts.length === 0) return false;
  const deadline = Date.now() + maxWaitMs;
  const httpsAgent = buildPinnedAgentHttpsAgent(certPem, fingerprint256);

  while (Date.now() < deadline) {
    for (const host of hosts) {
      try {
        const response = await axios.get(`https://${host}:8080/health`, {
          headers: { 'x-agent-secret': agentSecret },
          timeout: 2_000,
          httpsAgent,
        });

        if (response.status === 200) {
          return true;
        }
      } catch {
        // keep retrying until timeout
      }
    }

    await sleep(5_000);
  }

  return false;
}

// ── Internal: create droplet with custom cloud-init ──────────────────────────
const DO_API_BASE = 'https://api.digitalocean.com/v2';

function getHeaders() {
  return {
    Authorization: `Bearer ${process.env.DO_API_TOKEN}`,
    'Content-Type': 'application/json',
  };
}

async function createDropletWithInit(
  customerId: string,
  cloudInit: string,
  size: string = 's-1vcpu-2gb',
  snapshotId?: string
): Promise<DODroplet> {
  const image: string | number = snapshotId ? Number(snapshotId) : 'ubuntu-24-04-x64';
  console.log(`[provision] cloud-init size: ${Buffer.byteLength(cloudInit, 'utf8')} bytes`);
  console.log(`[provision] Creating droplet: region=${DEFAULT_DROPLET_REGION} size=${size} image=${image}${snapshotId ? ' (snapshot)' : ''}`);

  const dropletConfig = {
    name: `oriclaw-${customerId}`,
    region: DEFAULT_DROPLET_REGION,
    size,
    image,
    user_data: cloudInit,
    tags: ['oriclaw', `customer:${customerId}`],
    monitoring: true,
    ipv6: false,
    ...(DEFAULT_VPC_ID ? { vpc_uuid: DEFAULT_VPC_ID } : {}),
  };

  const response = await axios.post<DODropletResponse>(
    `${DO_API_BASE}/droplets`,
    dropletConfig,
    { headers: getHeaders(), timeout: 30_000 }
  );

  console.log(`[provision] DO API response status: ${response.status}`);

  // Verify immediately that we can read back the droplet
  try {
    await sleep(2_000);
    const verify = await axios.get(
      `${DO_API_BASE}/droplets/${response.data.droplet.id}`,
      { headers: getHeaders(), timeout: 15_000 }
    );
    console.log(`[provision] Immediate verify: droplet ${response.data.droplet.id} status=${verify.data.droplet.status}`);
  } catch (verifyErr: unknown) {
    const axErr = verifyErr as { response?: { status?: number; data?: unknown }; message?: string };
    console.error(`[provision] Immediate verify FAILED for droplet ${response.data.droplet.id}:`, {
      status: axErr.response?.status,
      data: JSON.stringify(axErr.response?.data),
      message: axErr.message,
    });
    // Also log the token prefix to verify it's the right token (first 8 chars only)
    const tokenPrefix = (process.env.DO_API_TOKEN ?? '').substring(0, 8);
    console.error(`[provision] DO_API_TOKEN prefix: ${tokenPrefix}...`);
  }

  return response.data.droplet;
}
