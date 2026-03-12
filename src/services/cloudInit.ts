/**
 * Cloud-init script for OriClaw droplets.
 * Installs OpenClaw + the OriClaw VPS agent side-by-side.
 *
 * __AGENT_SECRET__ is replaced at provision time with a random secret.
 */
export const CLOUD_INIT_SCRIPT = `#!/bin/bash
# OriClaw auto-provisioning script
set -e
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# ── System ───────────────────────────────────────────────────────────────────
apt-get update -y
# Skip apt-get upgrade — base image is already up-to-date, saves ~3 min
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl wget git || true

# ── Node.js 22 ───────────────────────────────────────────────────────────────
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nodejs

# ── Firewall ─────────────────────────────────────────────────────────────────
apt-get install -y ufw || true
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
# Port 8080 (VPS Agent) — rate-limited via agent, auth via agent_secret
# Ideally restrict to backend IP, but Railway uses dynamic IPs
ufw allow 8080/tcp
# Port 3000 (OpenClaw UI) — protected by OPENCLAW_GATEWAY_TOKEN
ufw allow 3000/tcp
ufw --force enable

# ── Harden SSH ──────────────────────────────────────────────────────────────
sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
if sshd -t -q 2>/dev/null; then systemctl restart sshd; fi

# ── OpenClaw (método oficial) ─────────────────────────────────────────────────
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" build-essential python3 python3-pip || true

# Cria usuário dedicado para openclaw
useradd -m -s /bin/bash openclaw || true
mkdir -p /home/openclaw/.openclaw

# Garante que npm global bin está no PATH do user openclaw
echo 'export PATH="/home/openclaw/.npm-global/bin:$PATH"' >> /home/openclaw/.bashrc
chown openclaw:openclaw /home/openclaw/.bashrc

# Instala openclaw como o usuário openclaw via script oficial (com retry)
for attempt in 1 2 3; do
  sudo -u openclaw bash -c '
    export HOME=/home/openclaw
    export OPENCLAW_HOME=/home/openclaw/.openclaw
    curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install.sh | bash -s -- --no-onboard
  ' && break
  echo "[oriclaw] openclaw install attempt $attempt failed, retrying in 15s..."
  sleep 15
done

# Symlink seguro — só cria se o binário existir
OPENCLAW_BIN=$(sudo -u openclaw bash -c 'export PATH="/home/openclaw/.npm-global/bin:$PATH"; which openclaw 2>/dev/null || echo ""')
if [ -z "$OPENCLAW_BIN" ]; then
  # Fallback paths where npm might have installed it
  for candidate in /home/openclaw/.npm-global/bin/openclaw /home/openclaw/.local/bin/openclaw; do
    if [ -f "$candidate" ]; then
      OPENCLAW_BIN="$candidate"
      break
    fi
  done
fi

if [ -f "$OPENCLAW_BIN" ]; then
  ln -sf "$OPENCLAW_BIN" /usr/local/bin/openclaw
  echo "[oriclaw] openclaw symlink created: $OPENCLAW_BIN"
else
  echo "[oriclaw] ERROR: openclaw binary not found after install" >&2
  exit 1
fi

cat > /home/openclaw/.openclaw/config.json << CONFIGEOF
{
  "model": "claude-sonnet-4-5",
  "channel": "whatsapp",
  "gateway": {
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "__GATEWAY_TOKEN__"
    }
  }
}
CONFIGEOF

touch /home/openclaw/.openclaw/.env
chown -R openclaw:openclaw /home/openclaw

# ── VPS Agent ────────────────────────────────────────────────────────────────
mkdir -p /opt/oriclaw-agent

# package.json
cat > /opt/oriclaw-agent/package.json << 'PKGEOF'
{
  "name": "oriclaw-vps-agent",
  "version": "1.0.0",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "qrcode": "^1.5.3"
  }
}
PKGEOF

# server.js
cat > /opt/oriclaw-agent/server.js << 'SERVEREOF'
'use strict';

const express = require('express');
const https = require('https');
const crypto = require('crypto');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;
const AGENT_SECRET = process.env.AGENT_SECRET || '';
const TLS_CERT = process.env.TLS_CERT_PATH || '/etc/oriclaw-agent/tls/cert.pem';
const TLS_KEY = process.env.TLS_KEY_PATH || '/etc/oriclaw-agent/tls/key.pem';
const OPENCLAW_CONFIG_DIR = '/home/openclaw/.openclaw';
const OPENCLAW_ENV_FILE = path.join(OPENCLAW_CONFIG_DIR, '.env');
const OPENCLAW_CONFIG_FILE = path.join(OPENCLAW_CONFIG_DIR, 'config.json');

// ── Concurrency locks ─────────────────────────────────────────────────────────
let isConfiguring = false;
let isRestarting = false;

// Safety valve: release locks after 60s to prevent permanent lockout
const LOCK_TIMEOUT_MS = 60_000;
let configuringTimer = null;
let restartingTimer = null;

// ── Auth rate limiting ───────────────────────────────────────────────────────
const authFailures = new Map(); // ip → { count, lastAttempt }
const AUTH_RATE_WINDOW_MS = 60_000;
const AUTH_MAX_FAILURES = 5;

function auth(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();

  // Check if IP is rate-limited
  const record = authFailures.get(ip);
  if (record && record.count >= AUTH_MAX_FAILURES && (now - record.lastAttempt) < AUTH_RATE_WINDOW_MS) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
  }

  const secret = req.headers['x-agent-secret'];
  if (!AGENT_SECRET || !secret || typeof secret !== 'string') {
    // Track failure
    const current = authFailures.get(ip) || { count: 0, lastAttempt: 0 };
    if (now - current.lastAttempt > AUTH_RATE_WINDOW_MS) {
      current.count = 1;
    } else {
      current.count++;
    }
    current.lastAttempt = now;
    authFailures.set(ip, current);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const secretBuf = Buffer.from(secret);
  const expectedBuf = Buffer.from(AGENT_SECRET);
  if (secretBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(secretBuf, expectedBuf)) {
    // Track failure
    const current = authFailures.get(ip) || { count: 0, lastAttempt: 0 };
    if (now - current.lastAttempt > AUTH_RATE_WINDOW_MS) {
      current.count = 1;
    } else {
      current.count++;
    }
    current.lastAttempt = now;
    authFailures.set(ip, current);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Successful auth — clear failures for this IP
  authFailures.delete(ip);
  next();
}

// Cleanup stale auth failure records every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of authFailures) {
    if (now - record.lastAttempt > AUTH_RATE_WINDOW_MS * 2) authFailures.delete(ip);
  }
}, 5 * 60_000);

// ── Helpers ──────────────────────────────────────────────────────────────────
function runCmd(cmd) {
  return execSync(cmd, { encoding: 'utf8', timeout: 30_000 });
}

function getOpenclawStatus() {
  try {
    const out = runCmd('systemctl is-active openclaw');
    return out.trim() === 'active' ? 'running' : 'stopped';
  } catch {
    return 'stopped';
  }
}

function getUptimeSeconds() {
  try {
    const out = runCmd('systemctl show openclaw --property=ActiveEnterTimestamp --value');
    const ts = out.trim();
    if (!ts || ts === 'n/a') return 0;
    const start = new Date(ts).getTime();
    return Math.floor((Date.now() - start) / 1000);
  } catch {
    return 0;
  }
}

function getJournalLogs(lines = 200) {
  try {
    return runCmd(\`journalctl -u openclaw -n \${lines} --no-pager --output=short-iso\`);
  } catch {
    return '';
  }
}

function getJournalLogsSinceLastStart(lines = 200) {
  try {
    const startTs = runCmd('systemctl show openclaw --property=ActiveEnterTimestamp --value').trim();
    if (startTs && startTs !== 'n/a' && startTs !== '') {
      return runCmd(\`journalctl -u openclaw -n \${lines} --no-pager --output=short-iso --since "\${startTs}"\`);
    }
    return runCmd(\`journalctl -u openclaw -n \${lines} --no-pager --output=short-iso\`);
  } catch {
    return '';
  }
}

/**
 * Read and parse the .env file into a plain object.
 */
function readEnvFile() {
  const envMap = {};
  try {
    const content = fs.readFileSync(OPENCLAW_ENV_FILE, 'utf8');
    content.split('\\n').filter(Boolean).forEach((line) => {
      const eq = line.indexOf('=');
      if (eq > 0) {
        const k = line.slice(0, eq).trim();
        const v = line.slice(eq + 1).trim();
        envMap[k] = v;
      }
    });
  } catch { /* file may not exist yet */ }
  return envMap;
}

/**
 * Sanitize env values — strip newlines and null bytes to prevent injection.
 */
function sanitizeEnvValue(v) {
  return String(v).replace(/[\\r\\n\\0]/g, '');
}

/**
 * Write a plain object back to the .env file, merging with existing values.
 */
function writeEnvFile(updates) {
  const existing = readEnvFile();
  const merged = { ...existing, ...updates };
  const content = Object.entries(merged).map(([k, v]) => \`\${k}=\${sanitizeEnvValue(v)}\`).join('\\n') + '\\n';
  fs.mkdirSync(OPENCLAW_CONFIG_DIR, { recursive: true });
  fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
  try { runCmd(\`chown -R openclaw:openclaw \${OPENCLAW_CONFIG_DIR}\`); } catch { /* ignore */ }
}

/**
 * Read config.json.
 */
function readConfig() {
  try { return JSON.parse(fs.readFileSync(OPENCLAW_CONFIG_FILE, 'utf8')); } catch { return {}; }
}

/**
 * Write config.json, merging with existing values.
 */
function writeConfig(updates) {
  const config = { ...readConfig(), ...updates };
  fs.mkdirSync(OPENCLAW_CONFIG_DIR, { recursive: true });
  fs.writeFileSync(OPENCLAW_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
  try { runCmd(\`chown -R openclaw:openclaw \${OPENCLAW_CONFIG_DIR}\`); } catch { /* ignore */ }
}

/**
 * Extract QR data from OpenClaw logs.
 */
function extractQRData(logs) {
  const lines = logs.split('\\n');

  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    const lower = line.toLowerCase();

    if (lower.includes('qr') || lower.includes('scan')) {
      const waQR = line.match(/\\d+@[A-Za-z0-9+/=,_-]{20,}/);
      if (waQR) return waQR[0];
      const b64 = line.match(/[A-Za-z0-9+/]{40,}={0,2}/);
      if (b64) return b64[0];
    }
  }

  const allWA = [...logs.matchAll(/\\d+@[A-Za-z0-9+/=,_-]{20,}/g)];
  if (allWA.length) return allWA[allWA.length - 1][0];

  return null;
}

// ── Routes ───────────────────────────────────────────────────────────────────

// GET /health
app.get('/health', auth, (req, res) => {
  const status = getOpenclawStatus();
  const uptime = getUptimeSeconds();
  res.json({ status: 'ok', openclaw: status, uptime });
});

// GET /health/detailed
app.get('/health/detailed', auth, (req, res) => {
  try {
    // Service status
    let openclaw = 'stopped';
    try {
      const activeOut = runCmd('systemctl is-active openclaw').trim();
      if (activeOut === 'active') openclaw = 'running';
      else if (activeOut === 'failed') openclaw = 'crashed';
      else openclaw = 'stopped';
    } catch { openclaw = 'stopped'; }

    // Restart count
    let restart_count = 0;
    try {
      const nrestartsOut = runCmd('systemctl show openclaw --property=NRestarts --value').trim();
      restart_count = parseInt(nrestartsOut, 10) || 0;
    } catch { restart_count = 0; }

    // If crash or many restarts, mark as crashed
    if (restart_count > 3 && openclaw !== 'running') openclaw = 'crashed';

    // Uptime
    const uptime_seconds = getUptimeSeconds();

    // RAM from /proc/meminfo
    let ram_used_mb = 0, ram_total_mb = 0;
    try {
      const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
      const memTotal = parseInt((meminfo.match(/MemTotal:\\s+(\\d+)/) || [])[1] || '0', 10);
      const memAvail = parseInt((meminfo.match(/MemAvailable:\\s+(\\d+)/) || [])[1] || '0', 10);
      ram_total_mb = Math.round(memTotal / 1024);
      ram_used_mb = Math.round((memTotal - memAvail) / 1024);
    } catch { /* ignore */ }

    // Disk from df
    let disk_used_gb = 0, disk_total_gb = 0;
    try {
      const dfOut = runCmd('df -BG / --output=size,used').trim();
      const lines = dfOut.split('\\n').filter(l => /^\\d/.test(l.trim()));
      const dataLine = lines.find(l => /\\d/.test(l)) || lines[lines.length - 1];
      if (dataLine) {
        const parts = dataLine.trim().split(/\\s+/);
        disk_total_gb = parseFloat(parts[0]) || 0;
        disk_used_gb = parseFloat(parts[1]) || 0;
      }
    } catch { /* ignore */ }

    // CPU from top
    let cpu_percent = 0;
    try {
      const topOut = runCmd("top -bn1 | grep 'Cpu(s)'");
      const match = topOut.match(/(\\d+[\\.,]\\d+)\\s*[%]?\\s*id/);
      if (match) {
        const idle = parseFloat(match[1].replace(',', '.'));
        cpu_percent = Math.round(100 - idle);
      } else {
        const usMatch = topOut.match(/(\\d+[\\.,]\\d+)\\s*[%]?\\s*us/);
        if (usMatch) cpu_percent = Math.round(parseFloat(usMatch[1].replace(',', '.')));
      }
    } catch { /* ignore */ }

    // Last message time from logs
    let last_message_at = null;
    try {
      const logs = getJournalLogs(100);
      const lines = logs.split('\\n').reverse();
      for (const line of lines) {
        if (line.toLowerCase().includes('message') || line.toLowerCase().includes('msg')) {
          const tsMatch = line.match(/^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}[^\\s]*)/);
          if (tsMatch) { last_message_at = tsMatch[1]; break; }
        }
      }
    } catch { /* ignore */ }

    res.json({
      openclaw,
      uptime_seconds,
      cpu_percent,
      ram_used_mb,
      ram_total_mb,
      disk_used_gb,
      disk_total_gb,
      last_message_at,
      restart_count,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── WhatsApp connection check helper ─────────────────────────────────────────
function isWhatsAppConnected(isRunning, logs) {
  if (!isRunning) return false;
  const lower = logs.toLowerCase();
  return (
    lower.includes('whatsapp connected') ||
    lower.includes('wa connected') ||
    lower.includes('[whatsapp] connected') ||
    lower.includes('client is ready') ||
    lower.includes('connection opened')
  );
}

// GET /qr  → base64 PNG of the current QR code (or { connected: true })
app.get('/qr', auth, async (req, res) => {
  const logs = getJournalLogsSinceLastStart(200);
  const isRunning = getOpenclawStatus() === 'running';

  if (isWhatsAppConnected(isRunning, logs)) {
    return res.json({ connected: true, qr: null });
  }

  const qrData = extractQRData(logs);
  if (!qrData) {
    return res.status(404).json({ error: 'QR not available yet', connected: false });
  }

  try {
    const pngBase64 = await QRCode.toDataURL(qrData, {
      errorCorrectionLevel: 'M',
      type: 'image/png',
      width: 300,
      margin: 2,
    });
    res.json({ connected: false, qr: pngBase64, generated_at: Date.now() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate QR: ' + err.message });
  }
});

// POST /configure
// body: { anthropic_key?, openai_key?, google_key?, openrouter_key?, openai_token?,
//         model?, assistant_name?, channel?,
//         credits_mode?, chatgpt_mode?,
//         system_prompt?, language?, timezone? }
app.post('/configure', auth, (req, res) => {
  if (isConfiguring) {
    return res.status(429).json({ error: 'Configuração já em andamento. Aguarde.' });
  }
  isConfiguring = true;
  configuringTimer = setTimeout(() => {
    console.error('[vps-agent] configure lock timed out — force-releasing');
    isConfiguring = false; configuringTimer = null;
  }, LOCK_TIMEOUT_MS);

  const {
    anthropic_key,
    openai_key,
    google_key,
    openrouter_key,
    openai_token,
    model,
    assistant_name,
    channel,
    credits_mode,
    chatgpt_mode,
    system_prompt,
    language,
    timezone,
  } = req.body || {};

  try {
    // Update config.json — Bug fix #7: validate model, channel, assistant_name inputs
    const VALID_MODELS = ['claude-sonnet-4-5', 'claude-3-5-haiku-latest', 'claude-opus-4', 'gpt-4o', 'gpt-4o-mini'];
    const VALID_CHANNELS = ['whatsapp', 'telegram', 'discord'];
    const safeModel = model && VALID_MODELS.includes(model) ? model : null;
    const safeChannel = channel && VALID_CHANNELS.includes(channel) ? channel : null;
    const safeName = assistant_name ? String(assistant_name).slice(0, 64).replace(/[^\w\s\-]/g, '') : null;
    const configUpdates = {};
    if (safeModel) configUpdates.model = safeModel;
    if (safeChannel) configUpdates.channel = safeChannel;
    if (safeName) configUpdates.assistant_name = safeName;
    if (credits_mode) configUpdates.ai_mode = 'credits';
    else if (chatgpt_mode) configUpdates.ai_mode = 'chatgpt';
    else if (anthropic_key || openai_key || google_key || openrouter_key) configUpdates.ai_mode = 'byok';
    if (system_prompt !== undefined) configUpdates.system_prompt = system_prompt;
    if (language) configUpdates.language = language;
    if (timezone) configUpdates.timezone = timezone;
    writeConfig(configUpdates);

    // Update .env
    const envUpdates = {};
    if (anthropic_key) envUpdates.ANTHROPIC_API_KEY = anthropic_key;
    if (openai_key) envUpdates.OPENAI_API_KEY = openai_key;
    if (google_key) envUpdates.GOOGLE_API_KEY = google_key;
    if (openrouter_key) envUpdates.OPENROUTER_API_KEY = openrouter_key;
    if (openai_token) envUpdates.OPENAI_ACCESS_TOKEN = openai_token;
    if (timezone) envUpdates.TZ = timezone;
    if (Object.keys(envUpdates).length > 0) writeEnvFile(envUpdates);

    exec('sudo systemctl restart openclaw', { timeout: 30000 }, (restartErr) => {
      if (restartErr) {
        clearTimeout(configuringTimer); configuringTimer = null; isConfiguring = false;
        return res.status(500).json({ success: false, error: 'Falha ao reiniciar o assistente: ' + restartErr.message });
      }
      // Poll até openclaw estar running ou timeout de 10s
      let attempts = 0;
      const poll = setInterval(() => {
        attempts++;
        const status = getOpenclawStatus();
        if (status === 'running') {
          clearInterval(poll);
          clearTimeout(configuringTimer); configuringTimer = null; isConfiguring = false;
          return res.json({ success: true, openclaw: 'running' });
        }
        if (attempts >= 10) {
          clearInterval(poll);
          clearTimeout(configuringTimer); configuringTimer = null; isConfiguring = false;
          return res.json({ success: true, openclaw: status, warning: 'Assistente ainda iniciando, aguarde alguns segundos.' });
        }
      }, 1000);
    });
  } catch (err) {
    clearTimeout(configuringTimer); configuringTimer = null; isConfiguring = false;
    res.status(500).json({ error: err.message });
  }
});

// POST /restart — with status detection and wait-for-up
app.post('/restart', auth, (req, res) => {
  if (isRestarting) {
    return res.status(429).json({ error: 'Reinicialização já em andamento. Aguarde.' });
  }
  isRestarting = true;
  restartingTimer = setTimeout(() => {
    console.error('[vps-agent] restart lock timed out — force-releasing');
    isRestarting = false; restartingTimer = null;
  }, LOCK_TIMEOUT_MS);

  const previous_status = getOpenclawStatus();

  exec('sudo systemctl restart openclaw', { timeout: 30000 }, (err) => {
    if (err) {
      clearTimeout(restartingTimer); restartingTimer = null; isRestarting = false;
      return res.status(500).json({ error: err.message, previous_status, restarted: false });
    }

    // Poll for service to come up (up to 10s)
    let attempts = 0;
    const maxAttempts = 10;
    const poll = setInterval(() => {
      attempts++;
      const new_status = getOpenclawStatus();
      if (new_status === 'running' || attempts >= maxAttempts) {
        clearInterval(poll);
        clearTimeout(restartingTimer); restartingTimer = null; isRestarting = false;
        res.json({ success: true, restarted: true, previous_status, new_status });
      }
    }, 1000);
  });
});

// GET /chat-url → returns the OpenClaw web UI URL and availability
app.get('/chat-url', auth, (req, res) => {
  try {
    // Get the public IP of this machine
    let publicIp = '';
    try {
      publicIp = runCmd("curl -s --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}'").trim();
    } catch {
      try { publicIp = runCmd("hostname -I | awk '{print $1}'").trim(); } catch { publicIp = 'localhost'; }
    }

    // Check if port 3000 is responding
    let available = false;
    try {
      runCmd('curl -s --max-time 2 http://localhost:3000/health > /dev/null 2>&1');
      available = true;
    } catch {
      try {
        runCmd('nc -z -w2 localhost 3000 2>/dev/null');
        available = true;
      } catch { available = false; }
    }

    const url = \`http://\${publicIp}:3000\`;
    res.json({ url, available });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /logs  → last 50 lines
app.get('/logs', auth, (req, res) => {
  try {
    const lines = runCmd('journalctl -u openclaw -n 50 --no-pager --output=short-iso');
    res.json({ logs: lines });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Channel routes ────────────────────────────────────────────────────────────

// GET /channels → status of each configured channel
app.get('/channels', auth, (req, res) => {
  try {
    const config = readConfig();
    const env = readEnvFile();
    const logs = getJournalLogsSinceLastStart(100);
    const isRunning = getOpenclawStatus() === 'running';
    const waConnected = isWhatsAppConnected(isRunning, logs);

    res.json({
      whatsapp: {
        status: waConnected ? 'connected' : (isRunning ? 'disconnected' : 'disconnected'),
        phone: config.whatsapp_phone || null,
      },
      telegram: {
        status: env.TELEGRAM_BOT_TOKEN ? 'configured' : 'not_configured',
        username: config.telegram_username || null,
      },
      discord: {
        status: (env.DISCORD_BOT_TOKEN && config.discord_guild_id) ? 'configured' : 'not_configured',
        guild: config.discord_guild_name || config.discord_guild_id || null,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /channels/telegram → body: { token }
app.post('/channels/telegram', auth, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token é obrigatório.' });

  // Validar token com a API do Telegram
  try {
    const tgRes = await fetch(\`https://api.telegram.org/bot\${token}/getMe\`);
    const tgData = await tgRes.json();
    if (!tgData.ok) {
      return res.status(400).json({ error: 'Token do Telegram inválido. Verifique e tente novamente.' });
    }
    console.log(\`[channels] Telegram bot verified: @\${tgData.result.username}\`);
  } catch (err) {
    return res.status(500).json({ error: 'Não foi possível verificar o token. Tente novamente.' });
  }

  try {
    writeEnvFile({ TELEGRAM_BOT_TOKEN: token });

    exec('sudo systemctl restart openclaw', { timeout: 30000 }, (err) => {
      if (err) console.error('[telegram] restart error:', err.message);
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /channels/discord → body: { token, guild_id }
// Bug fix #8: validate Discord bot token and guild_id before saving
app.post('/channels/discord', auth, async (req, res) => {
  const { token, guild_id } = req.body || {};
  if (!token || !guild_id) {
    return res.status(400).json({ error: 'Token e ID do servidor (guild_id) são obrigatórios.' });
  }

  // Validate guild_id is numeric
  if (!/^\d+$/.test(guild_id)) {
    return res.status(400).json({ error: 'guild_id deve ser um número.' });
  }

  // Validate Discord bot token against the API
  try {
    const discordRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: \`Bot \${token}\` }
    });
    if (!discordRes.ok) {
      return res.status(400).json({ error: 'Token Discord inválido. Verifique o bot token.' });
    }
    const botInfo = await discordRes.json();
    console.log(\`[channels] Discord bot verified: \${botInfo.username}\`);
  } catch (err) {
    return res.status(500).json({ error: 'Não foi possível verificar o token Discord. Tente novamente.' });
  }

  try {
    writeEnvFile({ DISCORD_BOT_TOKEN: token });
    if (guild_id) writeConfig({ discord_guild_id: guild_id });

    exec('sudo systemctl restart openclaw', { timeout: 30000 }, (err) => {
      if (err) console.error('[discord] restart error:', err.message);
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /channels/:channel → disconnect a channel
app.delete('/channels/:channel', auth, (req, res) => {
  const { channel } = req.params;
  const envKeyMap = {
    telegram: 'TELEGRAM_BOT_TOKEN',
    discord: 'DISCORD_BOT_TOKEN',
  };

  if (!envKeyMap[channel] && channel !== 'whatsapp') {
    return res.status(400).json({ error: \`Unknown channel: \${channel}\` });
  }

  try {
    if (channel === 'whatsapp') {
      // Delete WhatsApp session files so the bot doesn't auto-reconnect
      // Respond immediately, then fire-and-forget the restart
      res.json({ success: true });
      exec(
        'rm -rf /home/openclaw/.openclaw/session /home/openclaw/.openclaw/.wwebjs_auth /home/openclaw/.openclaw/.baileys && sudo systemctl restart openclaw',
        { timeout: 30000 },
        (err) => {
          if (err) console.error('[vps-agent] restart after whatsapp disconnect failed:', err.message);
        }
      );
      return;
    } else {
      const env = readEnvFile();
      delete env[envKeyMap[channel]];
      const content = Object.entries(env).map(([k, v]) => \`\${k}=\${sanitizeEnvValue(v)}\`).join('\\n') + '\\n';
      fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
      try { runCmd(\`chown -R openclaw:openclaw \${OPENCLAW_CONFIG_DIR}\`); } catch { /* ignore */ }

      exec('sudo systemctl restart openclaw', { timeout: 30000 }, (err) => {
        if (err) console.error('[disconnect] restart error:', err.message);
      });
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start (HTTPS with self-signed cert) ──────────────────────────────────────
try {
  const tlsOptions = {
    key: fs.readFileSync(TLS_KEY),
    cert: fs.readFileSync(TLS_CERT),
  };
  https.createServer(tlsOptions, app).listen(PORT, () => {
    console.log(\`🌀 OriClaw VPS Agent running on HTTPS port \${PORT}\`);
  });
} catch (tlsErr) {
  console.warn('[vps-agent] TLS cert not found, falling back to HTTP:', tlsErr.message);
  app.listen(PORT, () => {
    console.log(\`🌀 OriClaw VPS Agent running on HTTP port \${PORT} (no TLS)\`);
  });
}

SERVEREOF

cd /opt/oriclaw-agent && for attempt in 1 2 3; do
  npm install --omit=dev && break
  echo "[oriclaw] npm install attempt $attempt failed, retrying in 10s..."
  sleep 10
done

# ── OpenClaw systemd service ──────────────────────────────────────────────────
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
Environment=NODE_COMPILE_CACHE=/var/tmp/openclaw-compile-cache
EnvironmentFile=-/home/openclaw/.openclaw/.env
ExecStart=/home/openclaw/.npm-global/bin/openclaw gateway --allow-unconfigured
Restart=on-failure
RestartSec=10
TimeoutStartSec=90
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

mkdir -p /var/tmp/openclaw-compile-cache
chown openclaw:openclaw /var/tmp/openclaw-compile-cache

# ── Generate self-signed TLS certificate for VPS Agent ────────────────────────
mkdir -p /etc/oriclaw-agent/tls
openssl req -x509 -newkey rsa:2048 -keyout /etc/oriclaw-agent/tls/key.pem \
  -out /etc/oriclaw-agent/tls/cert.pem -days 3650 -nodes \
  -subj "/CN=oriclaw-vps-agent" 2>/dev/null
chmod 600 /etc/oriclaw-agent/tls/key.pem
chmod 644 /etc/oriclaw-agent/tls/cert.pem

# ── VPS Agent env file (seguro) ──────────────────────────────────────────────
cat > /etc/oriclaw-agent.env << 'ENVEOF'
AGENT_SECRET=__AGENT_SECRET__
PORT=8080
ENVEOF
chmod 600 /etc/oriclaw-agent.env
chown root:root /etc/oriclaw-agent.env

# ── Criar usuário dedicado para o agente ─────────────────────────────────────
useradd -r -s /usr/sbin/nologin oriclaw-agent 2>/dev/null || true
usermod -aG systemd-journal oriclaw-agent   # Bug 2: read journald logs for QR/status
usermod -aG openclaw oriclaw-agent           # Bug 1: write to /home/openclaw/.openclaw

# Set group-writable permissions on openclaw config dir (Bug 1)
chmod 775 /home/openclaw/.openclaw
chmod 664 /home/openclaw/.openclaw/.env 2>/dev/null || true
chmod 664 /home/openclaw/.openclaw/config.json 2>/dev/null || true
# Ensure new files created in that dir are also group-writable
chmod g+s /home/openclaw/.openclaw

# Sudoers limitado para o agente
cat > /etc/sudoers.d/oriclaw-agent << 'SUDOEOF'
oriclaw-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart openclaw, /usr/bin/systemctl start openclaw, /usr/bin/systemctl stop openclaw, /usr/bin/systemctl is-active openclaw, /usr/bin/systemctl status openclaw
SUDOEOF
chmod 440 /etc/sudoers.d/oriclaw-agent

# Ajustar permissões dos arquivos que o agente precisa acessar
chown oriclaw-agent:oriclaw-agent /etc/oriclaw-agent.env
chmod 600 /etc/oriclaw-agent.env
chown -R oriclaw-agent:oriclaw-agent /opt/oriclaw-agent 2>/dev/null || true
chown -R oriclaw-agent:oriclaw-agent /etc/oriclaw-agent 2>/dev/null || true

# ── VPS Agent systemd service ─────────────────────────────────────────────────
cat > /etc/systemd/system/oriclaw-agent.service << 'AGENTEOF'
[Unit]
Description=OriClaw VPS Agent
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

# ── Enable and start services ─────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable openclaw oriclaw-agent
systemctl start oriclaw-agent
# openclaw starts AFTER user configures API key via dashboard

# Signal completion
echo "ORICLAW_READY" > /var/lib/cloud/instance/oriclaw-status
`;
