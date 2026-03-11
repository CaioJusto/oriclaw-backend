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
 * Extract QR data from OpenClaw logs.
 * OpenClaw prints the WhatsApp QR as a text string (the raw QR data URL / pairing code).
 * We look for lines containing "qr" (case-insensitive) and extract the data portion.
 * If the data looks like a WA QR payload we return it; otherwise null.
 */
function extractQRData(logs) {
  const lines = logs.split('\n');

  // Strategy 1: look for a line with "qr" keyword followed by a long base64/url-like token
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    const lower = line.toLowerCase();

    // WhatsApp QR data typically looks like: "1@xxxx,yyyy,zzzz,wwww"
    // or just a long base64 string
    if (lower.includes('qr') || lower.includes('scan')) {
      // Extract the last whitespace-separated token that looks like QR data
      // WA QR format: digits@base64,base64,base64,base64
      const waQR = line.match(/\d+@[A-Za-z0-9+/=,_-]{20,}/);
      if (waQR) return waQR[0];

      // Fallback: a long base64 token
      const b64 = line.match(/[A-Za-z0-9+/]{40,}={0,2}/);
      if (b64) return b64[0];
    }
  }

  // Strategy 2: scan for WA QR pattern anywhere in logs (last occurrence)
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

  // Check if already connected (QR no longer present + service running)
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

// POST /configure  → body: { anthropic_key?, openai_key?, model?, assistant_name?, channel? }
app.post('/configure', auth, (req, res) => {
  const { anthropic_key, openai_key, model, assistant_name, channel } = req.body || {};

  try {
    // Ensure config dir exists
    fs.mkdirSync(OPENCLAW_CONFIG_DIR, { recursive: true });

    // Read existing config
    let config = {};
    try { config = JSON.parse(fs.readFileSync(OPENCLAW_CONFIG_FILE, 'utf8')); } catch {}

    // Update config
    if (model) config.model = model;
    if (channel) config.channel = channel;
    if (assistant_name) config.assistant_name = assistant_name;
    fs.writeFileSync(OPENCLAW_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');

    // Write .env file
    const envLines = [];
    if (anthropic_key) envLines.push(`ANTHROPIC_API_KEY=${anthropic_key}`);
    if (openai_key) envLines.push(`OPENAI_API_KEY=${openai_key}`);

    if (envLines.length > 0) {
      // Merge with existing .env
      let existing = '';
      try { existing = fs.readFileSync(OPENCLAW_ENV_FILE, 'utf8'); } catch {}
      const envMap = {};
      existing.split('\n').filter(Boolean).forEach((l) => {
        const [k, ...v] = l.split('=');
        if (k) envMap[k.trim()] = v.join('=').trim();
      });
      envLines.forEach((l) => {
        const [k, ...v] = l.split('=');
        envMap[k.trim()] = v.join('=');
      });
      const merged = Object.entries(envMap).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
      fs.writeFileSync(OPENCLAW_ENV_FILE, merged, 'utf8');

      // Fix ownership
      try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch {}
    }

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
    if (err) {
      return res.status(500).json({ error: err.message });
    }
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

// ── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🌀 OriClaw VPS Agent running on port ${PORT}`);
});
