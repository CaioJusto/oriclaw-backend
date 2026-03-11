/**
 * Cloud-init script for OriClaw droplets.
 * Installs OpenClaw + the OriClaw VPS agent side-by-side.
 *
 * __AGENT_SECRET__ is replaced at provision time with a random secret.
 */
export const CLOUD_INIT_SCRIPT = `#!/bin/bash
# OriClaw auto-provisioning script
set -e

# ── System ───────────────────────────────────────────────────────────────────
apt-get update -y
apt-get upgrade -y
apt-get install -y curl wget git

# ── Node.js 20 ───────────────────────────────────────────────────────────────
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# ── OpenClaw ─────────────────────────────────────────────────────────────────
npm install -g openclaw

# ── openclaw user ────────────────────────────────────────────────────────────
useradd -m -s /bin/bash openclaw || true
mkdir -p /home/openclaw/.openclaw

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

function auth(req, res, next) {
  const secret = req.headers['x-agent-secret'];
  if (!AGENT_SECRET || secret !== AGENT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function runCmd(cmd) {
  return execSync(cmd, { encoding: 'utf8', timeout: 30000 });
}

function getOpenclawStatus() {
  try { return runCmd('systemctl is-active openclaw').trim() === 'active' ? 'running' : 'stopped'; }
  catch { return 'stopped'; }
}

function getUptimeSeconds() {
  try {
    const ts = runCmd('systemctl show openclaw --property=ActiveEnterTimestamp --value').trim();
    if (!ts || ts === 'n/a') return 0;
    return Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  } catch { return 0; }
}

function extractQRData(logs) {
  const lines = logs.split('\\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    const lower = line.toLowerCase();
    if (lower.includes('qr') || lower.includes('scan')) {
      const waQR = line.match(/\\d+@[A-Za-z0-9+\\/=,_-]{20,}/);
      if (waQR) return waQR[0];
      const b64 = line.match(/[A-Za-z0-9+\\/]{40,}={0,2}/);
      if (b64) return b64[0];
    }
  }
  const allWA = [...logs.matchAll(/\\d+@[A-Za-z0-9+\\/=,_-]{20,}/g)];
  if (allWA.length) return allWA[allWA.length - 1][0];
  return null;
}

app.get('/health', auth, (req, res) => {
  res.json({ status: 'ok', openclaw: getOpenclawStatus(), uptime: getUptimeSeconds() });
});

app.get('/qr', auth, async (req, res) => {
  try {
    const logs = runCmd('journalctl -u openclaw -n 200 --no-pager --output=short-iso');
    if (getOpenclawStatus() === 'running' && logs.toLowerCase().includes('connected')) {
      return res.json({ connected: true, qr: null });
    }
    const qrData = extractQRData(logs);
    if (!qrData) return res.status(404).json({ error: 'QR not available yet', connected: false });
    const pngBase64 = await QRCode.toDataURL(qrData, { errorCorrectionLevel: 'M', type: 'image/png', width: 300, margin: 2 });
    res.json({ connected: false, qr: pngBase64 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/configure', auth, (req, res) => {
  const { anthropic_key, openai_key, model, assistant_name, channel } = req.body || {};
  try {
    fs.mkdirSync(OPENCLAW_CONFIG_DIR, { recursive: true });
    let config = {};
    try { config = JSON.parse(fs.readFileSync(OPENCLAW_CONFIG_FILE, 'utf8')); } catch {}
    if (model) config.model = model;
    if (channel) config.channel = channel;
    if (assistant_name) config.assistant_name = assistant_name;
    fs.writeFileSync(OPENCLAW_CONFIG_FILE, JSON.stringify(config, null, 2));

    const envLines = [];
    if (anthropic_key) envLines.push(\`ANTHROPIC_API_KEY=\${anthropic_key}\`);
    if (openai_key) envLines.push(\`OPENAI_API_KEY=\${openai_key}\`);
    if (envLines.length > 0) {
      let existing = '';
      try { existing = fs.readFileSync(OPENCLAW_ENV_FILE, 'utf8'); } catch {}
      const envMap = {};
      existing.split('\\n').filter(Boolean).forEach((l) => {
        const [k, ...v] = l.split('=');
        if (k) envMap[k.trim()] = v.join('=').trim();
      });
      envLines.forEach((l) => {
        const [k, ...v] = l.split('=');
        envMap[k.trim()] = v.join('=');
      });
      fs.writeFileSync(OPENCLAW_ENV_FILE, Object.entries(envMap).map(([k, v]) => \`\${k}=\${v}\`).join('\\n') + '\\n');
      try { runCmd(\`chown -R openclaw:openclaw \${OPENCLAW_CONFIG_DIR}\`); } catch {}
    }
    exec('systemctl restart openclaw', (err) => { if (err) console.error('[configure] restart:', err.message); });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/restart', auth, (req, res) => {
  exec('systemctl restart openclaw', (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/logs', auth, (req, res) => {
  try {
    const lines = runCmd('journalctl -u openclaw -n 50 --no-pager --output=short-iso');
    res.json({ logs: lines });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => console.log(\`🌀 OriClaw VPS Agent running on port \${PORT}\`));
SERVEREOF

cd /opt/oriclaw-agent && npm install --omit=dev

# ── OpenClaw systemd service ──────────────────────────────────────────────────
cat > /etc/systemd/system/openclaw.service << 'SVCEOF'
[Unit]
Description=OpenClaw AI Assistant
After=network.target

[Service]
Type=simple
User=openclaw
WorkingDirectory=/home/openclaw
EnvironmentFile=/home/openclaw/.openclaw/.env
ExecStart=/usr/local/bin/openclaw gateway start
Restart=always
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
