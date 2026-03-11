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
    return runCmd(`journalctl -u openclaw -n ${lines} --no-pager --output=short-iso`);
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
    content.split('\n').filter(Boolean).forEach((line) => {
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
  const content = Object.entries(merged).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  fs.mkdirSync(OPENCLAW_CONFIG_DIR, { recursive: true });
  fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
  try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }
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
  try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }
}

/**
 * Extract QR data from OpenClaw logs.
 */
function extractQRData(logs) {
  const lines = logs.split('\n');

  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    const lower = line.toLowerCase();

    if (lower.includes('qr') || lower.includes('scan')) {
      const waQR = line.match(/\d+@[A-Za-z0-9+/=,_-]{20,}/);
      if (waQR) return waQR[0];
      const b64 = line.match(/[A-Za-z0-9+/]{40,}={0,2}/);
      if (b64) return b64[0];
    }
  }

  const allWA = [...logs.matchAll(/\d+@[A-Za-z0-9+/=,_-]{20,}/g)];
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

// GET /qr  → base64 PNG of the current QR code (or { connected: true })
app.get('/qr', auth, async (req, res) => {
  const logs = getJournalLogs(200);

  if (getOpenclawStatus() === 'running' && logs.toLowerCase().includes('connected')) {
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
// body: { anthropic_key?, openai_key?, openrouter_key?, openai_token?,
//         model?, assistant_name?, channel?,
//         credits_mode?, chatgpt_mode? }
app.post('/configure', auth, (req, res) => {
  const {
    anthropic_key,
    openai_key,
    openrouter_key,
    openai_token,
    model,
    assistant_name,
    channel,
    credits_mode,
    chatgpt_mode,
  } = req.body || {};

  try {
    // Update config.json
    const configUpdates = {};
    if (model) configUpdates.model = model;
    if (channel) configUpdates.channel = channel;
    if (assistant_name) configUpdates.assistant_name = assistant_name;
    if (credits_mode) configUpdates.ai_mode = 'credits';
    else if (chatgpt_mode) configUpdates.ai_mode = 'chatgpt';
    else if (anthropic_key || openai_key || openrouter_key) configUpdates.ai_mode = 'byok';
    writeConfig(configUpdates);

    // Update .env
    const envUpdates = {};
    if (anthropic_key) envUpdates.ANTHROPIC_API_KEY = anthropic_key;
    if (openai_key) envUpdates.OPENAI_API_KEY = openai_key;
    if (openrouter_key) envUpdates.OPENROUTER_API_KEY = openrouter_key;
    if (openai_token) envUpdates.OPENAI_ACCESS_TOKEN = openai_token;
    if (Object.keys(envUpdates).length > 0) writeEnvFile(envUpdates);

    // Restart openclaw service
    exec('systemctl restart openclaw', (err) => {
      if (err) console.error('[configure] restart error:', err.message);
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /restart
app.post('/restart', auth, (req, res) => {
  exec('systemctl restart openclaw', (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
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
    const waConnected = isRunning && logs.toLowerCase().includes('connected');

    res.json({
      whatsapp: {
        status: waConnected ? 'connected' : (isRunning ? 'disconnected' : 'disconnected'),
        phone: config.whatsapp_phone || null,
      },
      telegram: {
        status: env.TELEGRAM_BOT_TOKEN ? 'connected' : 'not_configured',
        username: config.telegram_username || null,
      },
      discord: {
        status: (env.DISCORD_BOT_TOKEN && config.discord_guild_id) ? 'connected' : 'not_configured',
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
    return res.status(400).json({ error: `Unknown channel: ${channel}` });
  }

  try {
    if (channel === 'whatsapp') {
      // For WhatsApp, just restart which clears the session
      exec('systemctl restart openclaw', (err) => {
        if (err) console.error('[wa-disconnect] restart error:', err.message);
      });
    } else {
      const env = readEnvFile();
      delete env[envKeyMap[channel]];
      const content = Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
      fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
      try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }

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
  console.log(`🌀 OriClaw VPS Agent running on port ${PORT}`);
});
