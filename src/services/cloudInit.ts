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
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" curl wget git

# ── Node.js 20 ───────────────────────────────────────────────────────────────
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nodejs

# ── OpenClaw (método oficial) ─────────────────────────────────────────────────
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" build-essential python3 python3-pip

# Cria usuário dedicado para openclaw
useradd -m -s /bin/bash openclaw || true
mkdir -p /home/openclaw/.openclaw

# Instala openclaw como o usuário openclaw via script oficial
sudo -u openclaw bash -c '
  export HOME=/home/openclaw
  export OPENCLAW_HOME=/home/openclaw/.openclaw
  curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard
'

# Symlink seguro — só cria se o binário existir
OPENCLAW_BIN=$(sudo -u openclaw bash -c 'which openclaw 2>/dev/null || echo ""')
if [ -z "$OPENCLAW_BIN" ]; then
  OPENCLAW_BIN="/home/openclaw/.local/bin/openclaw"
fi

if [ -f "$OPENCLAW_BIN" ]; then
  ln -sf "$OPENCLAW_BIN" /usr/local/bin/openclaw
  echo "[oriclaw] openclaw symlink created: $OPENCLAW_BIN"
else
  echo "[oriclaw] ERROR: openclaw binary not found after install" >&2
  exit 1
fi

cat > /home/openclaw/.openclaw/config.json << 'CONFIGEOF'
{
  "model": "claude-sonnet-4-5",
  "channel": "whatsapp"
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
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;
const AGENT_SECRET = process.env.AGENT_SECRET || '';
const OPENCLAW_CONFIG_DIR = '/home/openclaw/.openclaw';
const OPENCLAW_ENV_FILE = path.join(OPENCLAW_CONFIG_DIR, '.env');
const OPENCLAW_CONFIG_FILE = path.join(OPENCLAW_CONFIG_DIR, 'config.json');

// ── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const secret = req.headers['x-agent-secret'];
  if (!AGENT_SECRET || secret !== AGENT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

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
 * Write a plain object back to the .env file, merging with existing values.
 */
function writeEnvFile(updates) {
  const existing = readEnvFile();
  const merged = { ...existing, ...updates };
  const content = Object.entries(merged).map(([k, v]) => \`\${k}=\${v}\`).join('\\n') + '\\n';
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
  const logs = getJournalLogs(200);
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
    res.json({ connected: false, qr: pngBase64 });
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
    // Update config.json
    const configUpdates = {};
    if (model) configUpdates.model = model;
    if (channel) configUpdates.channel = channel;
    if (assistant_name) configUpdates.assistant_name = assistant_name;
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

    exec('systemctl restart openclaw', (restartErr) => {
      if (restartErr) {
        return res.status(500).json({ success: false, error: 'Falha ao reiniciar o assistente: ' + restartErr.message });
      }
      // Poll até openclaw estar running ou timeout de 10s
      let attempts = 0;
      const poll = setInterval(() => {
        attempts++;
        const status = getOpenclawStatus();
        if (status === 'running') {
          clearInterval(poll);
          return res.json({ success: true, openclaw: 'running' });
        }
        if (attempts >= 10) {
          clearInterval(poll);
          return res.json({ success: true, openclaw: status, warning: 'Assistente ainda iniciando, aguarde alguns segundos.' });
        }
      }, 1000);
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /restart — with status detection and wait-for-up
app.post('/restart', auth, (req, res) => {
  const previous_status = getOpenclawStatus();

  exec('systemctl restart openclaw', (err) => {
    if (err) return res.status(500).json({ error: err.message, previous_status, restarted: false });

    // Poll for service to come up (up to 10s)
    let attempts = 0;
    const maxAttempts = 10;
    const poll = setInterval(() => {
      attempts++;
      const new_status = getOpenclawStatus();
      if (new_status === 'running' || attempts >= maxAttempts) {
        clearInterval(poll);
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
    const logs = getJournalLogs(100);
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
app.post('/channels/telegram', auth, (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token is required' });

  try {
    writeEnvFile({ TELEGRAM_BOT_TOKEN: token });

    exec('systemctl restart openclaw', (err) => {
      if (err) console.error('[telegram] restart error:', err.message);
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /channels/discord → body: { token, guild_id }
app.post('/channels/discord', auth, (req, res) => {
  const { token, guild_id } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token is required' });

  try {
    writeEnvFile({ DISCORD_BOT_TOKEN: token });
    if (guild_id) writeConfig({ discord_guild_id: guild_id });

    exec('systemctl restart openclaw', (err) => {
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
      exec(
        'rm -rf /home/openclaw/.openclaw/session /home/openclaw/.openclaw/.wwebjs_auth /home/openclaw/.openclaw/.baileys && systemctl restart openclaw',
        (err) => {
          if (err) console.error('[channels] WhatsApp disconnect error:', err.message);
          setTimeout(() => res.json({ success: true }), 3000);
        }
      );
      return;
    } else {
      const env = readEnvFile();
      delete env[envKeyMap[channel]];
      const content = Object.entries(env).map(([k, v]) => \`\${k}=\${v}\`).join('\\n') + '\\n';
      fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
      try { runCmd(\`chown -R openclaw:openclaw \${OPENCLAW_CONFIG_DIR}\`); } catch { /* ignore */ }

      exec('systemctl restart openclaw', (err) => {
        if (err) console.error('[disconnect] restart error:', err.message);
      });
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(\`🌀 OriClaw VPS Agent running on port \${PORT}\`);
});

SERVEREOF

cd /opt/oriclaw-agent && npm install --omit=dev

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
EnvironmentFile=-/home/openclaw/.openclaw/.env
ExecStart=/home/openclaw/.local/bin/openclaw gateway start --headless
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

# ── VPS Agent systemd service ─────────────────────────────────────────────────
cat > /etc/systemd/system/oriclaw-agent.service << 'AGENTEOF'
[Unit]
Description=OriClaw VPS Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/oriclaw-agent
Environment=PORT=8080
Environment=AGENT_SECRET=__AGENT_SECRET__
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
