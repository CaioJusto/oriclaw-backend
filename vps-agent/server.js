'use strict';

const express = require('express');
const https = require('https');
const crypto = require('crypto');
const { execSync, exec, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
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
const OPENCLAW_CONFIG_PATHS = [
  path.join(OPENCLAW_CONFIG_DIR, '.openclaw', 'openclaw.json'),
  path.join(OPENCLAW_CONFIG_DIR, 'openclaw.json'),
  OPENCLAW_CONFIG_FILE,
];

// ── Concurrency locks ─────────────────────────────────────────────────────────
let isConfiguring = false;
let isRestarting = false;

// Safety valve: release locks after 60s to avoid permanent lockout
// (covers edge cases where exec callback is never fired)
const LOCK_TIMEOUT_MS = 60_000;
let configuringTimer = null;
let restartingTimer = null;

// ── Usage tracking ─────────────────────────────────────────────────────────
const usageBuffer = [];
const USAGE_BUFFER_LIMIT = 5000;
let creditBlocked = false;

function appendUsageEvent(event) {
  usageBuffer.push({
    id: crypto.randomUUID(),
    ...event,
  });

  if (usageBuffer.length > USAGE_BUFFER_LIMIT) {
    const dropped = usageBuffer.length - USAGE_BUFFER_LIMIT;
    usageBuffer.splice(0, dropped);
    console.warn(`[usage-watcher] dropped ${dropped} old usage event(s) after buffer limit`);
  }
}

// ── Journald usage watcher ─────────────────────────────────────────────────
function startUsageWatcher() {
  const journal = spawn('journalctl', ['-u', 'openclaw', '-f', '-o', 'cat', '--no-pager'], {
    stdio: ['ignore', 'pipe', 'ignore'],
  });

  let partial = '';

  journal.stdout.on('data', (chunk) => {
    partial += chunk.toString();
    const lines = partial.split('\n');
    partial = lines.pop(); // keep incomplete line for next chunk

    for (const line of lines) {
      // Look for JSON containing usage data from OpenRouter
      const usageMatch = line.match(/\{[^{}]*"usage"\s*:\s*\{[^}]*"prompt_tokens"\s*:\s*\d+[^}]*\}[^}]*\}/);
      if (usageMatch) {
        try {
          const parsed = JSON.parse(usageMatch[0]);
          if (parsed.usage && typeof parsed.usage.prompt_tokens === 'number') {
            appendUsageEvent({
              prompt_tokens: parsed.usage.prompt_tokens,
              completion_tokens: parsed.usage.completion_tokens || 0,
              model: parsed.model || null,
              timestamp: new Date().toISOString(),
            });
          }
        } catch { /* malformed JSON, skip */ }
      }
    }
  });

  journal.on('close', (code) => {
    console.log('[usage-watcher] journalctl exited with code', code, '— restarting in 5s');
    setTimeout(startUsageWatcher, 5000);
  });

  console.log('[usage-watcher] started');
}

// Delay watcher start to ensure openclaw service exists
setTimeout(startUsageWatcher, 10_000);

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
      current.count = 1; // reset window
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
    return runCmd(`journalctl -u openclaw -n ${lines} --no-pager --output=short-iso`);
  } catch {
    return '';
  }
}

function getJournalLogsSinceLastStart(lines = 200) {
  try {
    const startTs = runCmd('systemctl show openclaw --property=ActiveEnterTimestamp --value').trim();
    if (startTs && startTs !== 'n/a' && startTs !== '') {
      return runCmd(`journalctl -u openclaw -n ${lines} --no-pager --output=short-iso --since "${startTs}"`);
    }
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
 * Sanitize env values — strip newlines and null bytes to prevent injection.
 */
function sanitizeEnvValue(v) {
  return String(v).replace(/[\r\n\0]/g, '');
}

/**
 * Write a plain object back to the .env file, merging with existing values.
 */
function writeEnvFile(updates) {
  const existing = readEnvFile();
  const merged = { ...existing, ...updates };
  const content = Object.entries(merged).map(([k, v]) => `${k}=${sanitizeEnvValue(v)}`).join('\n') + '\n';
  fs.mkdirSync(OPENCLAW_CONFIG_DIR, { recursive: true });
  fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
  try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }
}

/**
 * Resolve the active OpenClaw config file.
 */
function getOpenClawConfigPath() {
  return OPENCLAW_CONFIG_PATHS.find((cfgPath) => fs.existsSync(cfgPath)) || OPENCLAW_CONFIG_PATHS[0];
}

/**
 * Read the active OpenClaw config.
 */
function readConfig() {
  try { return JSON.parse(fs.readFileSync(getOpenClawConfigPath(), 'utf8')); } catch { return {}; }
}

/**
 * Write the active OpenClaw config, merging with existing values.
 */
function writeConfig(updates) {
  const configPath = getOpenClawConfigPath();
  const config = { ...readConfig(), ...updates };
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
  try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }
}

function safeJsonParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function getWhatsAppAuthDirs() {
  return [
    path.join(OPENCLAW_CONFIG_DIR, 'credentials', 'whatsapp', 'default'),
    path.join(OPENCLAW_CONFIG_DIR, '.openclaw', 'channels', 'whatsapp', 'default', 'auth'),
    path.join(OPENCLAW_CONFIG_DIR, 'channels', 'whatsapp', 'default', 'auth'),
  ];
}

function hasFiles(dir) {
  try {
    return fs.existsSync(dir) && fs.readdirSync(dir).length > 0;
  } catch {
    return false;
  }
}

function hasWhatsAppAuthState() {
  return getWhatsAppAuthDirs().some(hasFiles);
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

function readGatewayHealth() {
  try {
    const out = runCmd(`${openclawGatewayCall('health', '--json')} 2>/dev/null`);
    return safeJsonParse(out);
  } catch {
    return null;
  }
}

function getWhatsAppLinkedFromGatewayHealth(gatewayHealth) {
  const wa = gatewayHealth?.channels?.whatsapp;
  return !!wa && (wa.connected === true || wa.linked === true || wa.ready === true);
}

function buildChannelSnapshot(config = readConfig(), env = readEnvFile(), logs = getJournalLogsSinceLastStart(100), gatewayHealth = null) {
  const isRunning = getOpenclawStatus() === 'running';
  const whatsappAuthPresent = hasWhatsAppAuthState();
  const whatsappDesired = Boolean(
    config?.channel === 'whatsapp' ||
    config?.channels?.whatsapp?.enabled ||
    whatsappAuthPresent
  );
  const whatsappConnected =
    getWhatsAppLinkedFromGatewayHealth(gatewayHealth) ||
    isWhatsAppConnected(isRunning, logs);

  const telegramDesired = Boolean(env.TELEGRAM_BOT_TOKEN || config?.channels?.telegram?.enabled);
  const telegramGateway = gatewayHealth?.channels?.telegram;
  const telegramConnected = !!telegramGateway && (
    telegramGateway.connected === true ||
    telegramGateway.ready === true
  );

  const discordDesired = Boolean(env.DISCORD_BOT_TOKEN || config?.channels?.discord?.enabled);
  const discordGateway = gatewayHealth?.channels?.discord;
  const discordConnected = !!discordGateway && (
    discordGateway.connected === true ||
    discordGateway.ready === true
  );

  return {
    whatsapp: {
      desired: whatsappDesired,
      connected: whatsappConnected,
      auth_present: whatsappAuthPresent,
      login_in_progress: !!whatsappLoginProcess || !!whatsappSocket,
      needs_relink: whatsappDesired && !whatsappConnected && !whatsappAuthPresent,
    },
    telegram: {
      desired: telegramDesired,
      token_present: !!env.TELEGRAM_BOT_TOKEN,
      connected: telegramConnected,
    },
    discord: {
      desired: discordDesired,
      token_present: !!env.DISCORD_BOT_TOKEN,
      guild_id_present: !!config?.discord_guild_id,
      connected: discordConnected,
    },
  };
}

function getDegradedChannels(channels) {
  const degraded = [];

  if (channels.whatsapp.desired && channels.whatsapp.auth_present && !channels.whatsapp.connected) {
    degraded.push('whatsapp');
  }
  if (channels.telegram.desired && !channels.telegram.connected) {
    degraded.push('telegram');
  }
  if (channels.discord.desired && !channels.discord.connected) {
    degraded.push('discord');
  }

  return degraded;
}

const WATCHDOG_INTERVAL_MS = 60_000;
const WATCHDOG_RESTART_COOLDOWN_MS = 120_000;
const WATCHDOG_QR_COOLDOWN_MS = 5 * 60_000;

let isWatchdogRunning = false;
const watchdogState = {
  enabled: true,
  last_run_at: null,
  last_result: 'idle',
  last_reason: null,
  last_error: null,
  last_restart_at: null,
  last_qr_bootstrap_at: null,
  consecutive_service_failures: 0,
  consecutive_channel_failures: 0,
  total_self_heals: 0,
  degraded_channels: [],
  channels: null,
};

function canRunAfter(lastIso, cooldownMs) {
  if (!lastIso) return true;
  return (Date.now() - new Date(lastIso).getTime()) >= cooldownMs;
}

function restartOpenclawForWatchdog(reason) {
  runCmd('sudo systemctl reset-failed openclaw 2>/dev/null || true');
  runCmd('sudo systemctl restart openclaw');
  watchdogState.last_restart_at = new Date().toISOString();
  watchdogState.last_reason = reason;
  watchdogState.total_self_heals += 1;
}

function reconcileChannelConfig(config, env) {
  const repaired = [];

  if (env.TELEGRAM_BOT_TOKEN) {
    const telegramEnabled = config?.channels?.telegram?.enabled === true;
    const telegramToken = config?.channels?.telegram?.botToken;
    if (!telegramEnabled || telegramToken !== env.TELEGRAM_BOT_TOKEN) {
      const safeToken = sanitizeEnvValue(env.TELEGRAM_BOT_TOKEN);
      runCmd(`${openclawExec(`config set channels.telegram.botToken '"${safeToken}"' --strict-json`)} 2>/dev/null || true`);
      runCmd(`${openclawExec('config set channels.telegram.enabled true --strict-json')} 2>/dev/null || true`);
      repaired.push('telegram');
    }
  }

  if (env.DISCORD_BOT_TOKEN) {
    const discordEnabled = config?.channels?.discord?.enabled === true;
    const discordToken = config?.channels?.discord?.token;
    if (!discordEnabled || discordToken !== env.DISCORD_BOT_TOKEN) {
      const safeToken = sanitizeEnvValue(env.DISCORD_BOT_TOKEN);
      runCmd(`${openclawExec(`config set channels.discord.token '"${safeToken}"' --strict-json`)} 2>/dev/null || true`);
      runCmd(`${openclawExec('config set channels.discord.enabled true --strict-json')} 2>/dev/null || true`);
      repaired.push('discord');
    }
  }

  if ((config?.channel === 'whatsapp' || hasWhatsAppAuthState()) && config?.channels?.whatsapp?.enabled !== true) {
    runCmd(`${openclawExec('config set channels.whatsapp.enabled true --strict-json')} 2>/dev/null || true`);
    repaired.push('whatsapp');
  }

  return repaired;
}

async function runWatchdogCycle(trigger = 'interval') {
  if (isWatchdogRunning) {
    return watchdogState;
  }

  isWatchdogRunning = true;
  watchdogState.last_run_at = new Date().toISOString();
  watchdogState.last_error = null;

  try {
    if (creditBlocked) {
      watchdogState.last_result = 'skipped_credit_blocked';
      return watchdogState;
    }
    if (isConfiguring || isRestarting) {
      watchdogState.last_result = 'skipped_busy';
      return watchdogState;
    }

    const config = readConfig();
    const env = readEnvFile();
    const logs = getJournalLogsSinceLastStart(120);
    const openclawStatus = getOpenclawStatus();
    const gatewayHealth = openclawStatus === 'running' ? readGatewayHealth() : null;
    const channels = buildChannelSnapshot(config, env, logs, gatewayHealth);
    const degradedChannels = getDegradedChannels(channels);
    watchdogState.channels = channels;
    watchdogState.degraded_channels = degradedChannels;

    let restartReason = null;
    let restarted = false;
    let repaired = [];

    if (openclawStatus !== 'running' || !gatewayHealth) {
      watchdogState.consecutive_service_failures += 1;
    } else {
      watchdogState.consecutive_service_failures = 0;
    }

    if (degradedChannels.length > 0) {
      watchdogState.consecutive_channel_failures += 1;
    } else {
      watchdogState.consecutive_channel_failures = 0;
    }

    repaired = reconcileChannelConfig(config, env);
    if (repaired.length > 0) {
      restartReason = `channel_config_reconciled:${repaired.join(',')}`;
    }

    if (!restartReason && watchdogState.consecutive_service_failures >= 2) {
      restartReason = gatewayHealth ? 'openclaw_not_running' : 'gateway_unhealthy';
    }

    if (!restartReason && watchdogState.consecutive_channel_failures >= 2 && degradedChannels.length > 0) {
      restartReason = `channels_degraded:${degradedChannels.join(',')}`;
    }

    if (restartReason && canRunAfter(watchdogState.last_restart_at, WATCHDOG_RESTART_COOLDOWN_MS)) {
      restartOpenclawForWatchdog(restartReason);
      restarted = true;
    }

    if (
      !restarted &&
      channels.whatsapp.desired &&
      !channels.whatsapp.connected &&
      !channels.whatsapp.auth_present &&
      !channels.whatsapp.login_in_progress &&
      canRunAfter(watchdogState.last_qr_bootstrap_at, WATCHDOG_QR_COOLDOWN_MS)
    ) {
      await startWhatsAppLogin();
      watchdogState.last_qr_bootstrap_at = new Date().toISOString();
      watchdogState.last_reason = 'whatsapp_qr_bootstrap';
      watchdogState.total_self_heals += 1;
      watchdogState.last_result = 'started_qr_recovery';
      return watchdogState;
    }

    watchdogState.last_reason = restartReason;
    watchdogState.last_result = restarted
      ? 'restarted_openclaw'
      : (repaired.length > 0 ? 'reconciled_config' : 'ok');
    return watchdogState;
  } catch (err) {
    watchdogState.last_result = 'error';
    watchdogState.last_error = err.message;
    return watchdogState;
  } finally {
    isWatchdogRunning = false;
  }
}

setTimeout(() => {
  runWatchdogCycle('startup').catch((err) => {
    console.error('[watchdog] startup cycle failed:', err.message);
  });
  setInterval(() => {
    runWatchdogCycle('interval').catch((err) => {
      console.error('[watchdog] periodic cycle failed:', err.message);
    });
  }, WATCHDOG_INTERVAL_MS);
}, 20_000);

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
      const memTotal = parseInt((meminfo.match(/MemTotal:\s+(\d+)/) || [])[1] || '0', 10);
      const memAvail = parseInt((meminfo.match(/MemAvailable:\s+(\d+)/) || [])[1] || '0', 10);
      ram_total_mb = Math.round(memTotal / 1024);
      ram_used_mb = Math.round((memTotal - memAvail) / 1024);
    } catch { /* ignore */ }

    // Disk from df (use df -k for compatibility, convert to GB)
    let disk_used_gb = 0, disk_total_gb = 0;
    try {
      const dfOut = runCmd('df -k /').trim();
      // Format: Filesystem 1K-blocks Used Available Use% Mounted
      const lines = dfOut.split('\n');
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].trim().split(/\s+/);
        if (parts.length >= 4) {
          const totalKb = parseInt(parts[1], 10) || 0;
          const usedKb = parseInt(parts[2], 10) || 0;
          disk_total_gb = Math.round((totalKb / 1048576) * 10) / 10;
          disk_used_gb = Math.round((usedKb / 1048576) * 10) / 10;
          break;
        }
      }
    } catch { /* ignore */ }

    // CPU from top
    let cpu_percent = 0;
    try {
      const topOut = runCmd("top -bn1 | grep 'Cpu(s)'");
      const match = topOut.match(/(\d+[\.,]\d+)\s*[%]?\s*id/);
      if (match) {
        const idle = parseFloat(match[1].replace(',', '.'));
        cpu_percent = Math.round(100 - idle);
      } else {
        const usMatch = topOut.match(/(\d+[\.,]\d+)\s*[%]?\s*us/);
        if (usMatch) cpu_percent = Math.round(parseFloat(usMatch[1].replace(',', '.')));
      }
    } catch { /* ignore */ }

    // Last message time from logs
    let last_message_at = null;
    try {
      const logs = getJournalLogs(100);
      const lines = logs.split('\n').reverse();
      for (const line of lines) {
        if (line.toLowerCase().includes('message') || line.toLowerCase().includes('msg')) {
          const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)/);
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
      watchdog: watchdogState,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── OpenClaw command helpers ─────────────────────────────────────────────────
const OPENCLAW_CMD = '/home/openclaw/.npm-global/bin/openclaw';

function openclawExec(args) {
  return `sudo -u openclaw OPENCLAW_HOME=/home/openclaw/.openclaw HOME=/home/openclaw ${OPENCLAW_CMD} ${args}`;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function isPrivateIpv4(host) {
  return /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host);
}

function getGatewayHost() {
  const interfaces = os.networkInterfaces();
  const candidates = [];

  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      if (!entry || entry.family !== 'IPv4' || entry.internal || !entry.address) continue;
      candidates.push(entry.address);
    }
  }

  const uniqueCandidates = [...new Set(candidates)];
  return uniqueCandidates.find(isPrivateIpv4) || uniqueCandidates[0] || '127.0.0.1';
}

function getGatewayCliFlags() {
  const config = readConfig();
  const gateway = config?.gateway || {};
  const auth = gateway.auth || {};
  const port = Number(gateway.port || 18789);
  const flags = [`--url ${shellQuote(`ws://${getGatewayHost()}:${port}`)}`];
  if (auth.mode === 'token' && auth.token) {
    flags.push(`--token ${shellQuote(auth.token)}`);
  }
  return flags.join(' ');
}

function openclawGatewayCall(method, extraArgs = '') {
  const parts = ['gateway call', getGatewayCliFlags(), extraArgs, method].filter(Boolean);
  return openclawExec(parts.join(' '));
}

function openclawDevicesExec(args) {
  const parts = ['devices', args, getGatewayCliFlags()].filter(Boolean);
  return openclawExec(parts.join(' '));
}

// ── WhatsApp connection check helper ─────────────────────────────────────────
function isWhatsAppConnected(isRunning, logs) {
  if (!isRunning) return false;
  const lower = logs.toLowerCase();
  return (
    lower.includes('whatsapp connected') ||
    lower.includes('wa connected') ||
    lower.includes('[whatsapp] connected') ||
    lower.includes('client is ready') ||    // whatsapp-web.js
    lower.includes('connection opened')     // Baileys
  );
}

/**
 * Check WhatsApp connection status via OpenClaw gateway RPC.
 * Uses 'health' endpoint which is more reliable than 'status'.
 */
function isWhatsAppLinkedViaRPC() {
  return getWhatsAppLinkedFromGatewayHealth(readGatewayHealth());
}

// ── WhatsApp login process management ────────────────────────────────────────
let whatsappLoginProcess = null;
let whatsappLoginStartedAt = 0;
let whatsappRawQR = null;       // raw QR string from Baileys
let whatsappQRTimestamp = 0;
let whatsappLinkedAt = 0;

let whatsappSetupDone = false;

function ensureWhatsAppSetup() {
  if (whatsappSetupDone) return;
  try {
    exec(`${openclawExec('config set channels.whatsapp.enabled true --strict-json')} 2>/dev/null || true`, { timeout: 30_000 });
    whatsappSetupDone = true;
    console.log('[whatsapp] ensureWhatsAppSetup fired (async)');
  } catch (err) {
    console.error('[whatsapp] ensureWhatsAppSetup error:', err.message);
  }
}

/**
 * Load Baileys from OpenClaw's node_modules (lazy, cached).
 */
let _baileys = null;
function loadBaileys() {
  if (_baileys) return _baileys;
  const paths = [
    '/home/openclaw/.npm-global/lib/node_modules/openclaw/node_modules/@whiskeysockets/baileys',
    '/home/openclaw/.npm-global/lib/node_modules/@whiskeysockets/baileys',
  ];
  for (const p of paths) {
    try {
      _baileys = require(p);
      console.log('[whatsapp] Baileys loaded from:', p);
      return _baileys;
    } catch { /* try next */ }
  }
  return null;
}

let whatsappSocket = null;

/**
 * Start WhatsApp login using Baileys directly in-process.
 * Captures raw QR data string for PNG generation.
 */
async function startWhatsAppLogin() {
  if (whatsappSocket) return; // already running
  if (Date.now() - whatsappLoginStartedAt < 10_000) return;

  ensureWhatsAppSetup();
  whatsappRawQR = null;
  whatsappLoginStartedAt = Date.now();
  // Mark as "in progress" to prevent re-entry
  whatsappLoginProcess = { killed: false };

  const baileys = loadBaileys();
  if (!baileys) {
    console.error('[whatsapp] Baileys not found in OpenClaw node_modules');
    whatsappLoginProcess = null;
    return;
  }

  const makeWASocket = baileys.default || baileys.makeWASocket;
  const useMultiFileAuthState = baileys.useMultiFileAuthState;
  const fetchLatestBaileysVersion = baileys.fetchLatestBaileysVersion;
  const makeCacheableSignalKeyStore = baileys.makeCacheableSignalKeyStore;

  // Use a temp auth dir writable by the agent, then sync to OpenClaw's dir
  const authDir = '/tmp/oriclaw-wa-auth';
  try {
    fs.mkdirSync(authDir, { recursive: true });
    // Copy existing OpenClaw auth if available (so we don't re-link)
    for (const openclawAuth of getWhatsAppAuthDirs()) {
      execSync(`cp -rn '${openclawAuth}'/* '${authDir}/' 2>/dev/null || true`, { timeout: 5000 });
    }
  } catch { /* ignore */ }

  try {
    console.log('[whatsapp] creating Baileys socket...');
    const { state, saveCreds } = await useMultiFileAuthState(authDir);

    // Fetch latest WhatsApp protocol version (required, otherwise 405)
    let version;
    try {
      const vInfo = await fetchLatestBaileysVersion();
      version = vInfo.version;
      console.log('[whatsapp] protocol version:', version);
    } catch (err) {
      console.warn('[whatsapp] fetchLatestBaileysVersion failed, using default:', err.message);
    }

    const baileysLogger = {
      level: 'warn',
      info: () => {},
      debug: () => {},
      warn: (...args) => console.log('[baileys-warn]', ...args),
      error: (...args) => console.error('[baileys-error]', ...args),
      trace: () => {},
      fatal: (...args) => console.error('[baileys-fatal]', ...args),
      child: () => baileysLogger,
    };

    const sock = makeWASocket({
      auth: {
        creds: state.creds,
        keys: makeCacheableSignalKeyStore ? makeCacheableSignalKeyStore(state.keys, baileysLogger) : state.keys,
      },
      version,
      printQRInTerminal: false,
      browser: ['OpenClaw', 'Chrome', '20.0.04'],
      logger: baileysLogger,
      syncFullHistory: false,
      markOnlineOnConnect: false,
    });
    whatsappSocket = sock;

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect, qr } = update;
      if (qr) {
        whatsappRawQR = qr;
        whatsappQRTimestamp = Date.now();
        console.log('[whatsapp-login] QR data captured, length:', qr.length);
      }
      if (connection === 'open') {
        console.log('[whatsapp-login] connected!');
        whatsappRawQR = null;
        whatsappLinkedAt = Date.now();
        for (const ocAuth of getWhatsAppAuthDirs()) {
          try {
            execSync(`mkdir -p '${ocAuth}' && cp -r /tmp/oriclaw-wa-auth/* '${ocAuth}/' 2>/dev/null || true && chown -R openclaw:openclaw '${ocAuth}'`, { timeout: 10000 });
          } catch (err) {
            console.error('[whatsapp-login] auth sync error:', err.message);
          }
        }
        exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (restartErr) => {
          if (restartErr) console.error('[whatsapp-login] restart after auth sync failed:', restartErr.message);
        });
        cleanupWhatsAppSocket();
      }
      if (connection === 'close') {
        const err = lastDisconnect?.error;
        const code = err?.output?.statusCode;
        console.log('[whatsapp-login] connection closed, code:', code, 'error:', err?.message || err);
        cleanupWhatsAppSocket();
      }
    });

    // Auto-cleanup after 90s
    setTimeout(() => {
      if (whatsappSocket === sock) {
        console.log('[whatsapp-login] timeout, cleaning up');
        cleanupWhatsAppSocket();
      }
    }, 90_000);

  } catch (err) {
    console.error('[whatsapp-login] error creating socket:', err.message);
    cleanupWhatsAppSocket();
  }
}

function cleanupWhatsAppSocket() {
  if (whatsappSocket) {
    try { whatsappSocket.ws?.close(); } catch {}
    whatsappSocket = null;
  }
  whatsappLoginProcess = null;
}

function readOpenClawLogQR() {
  try {
    const today = new Date().toISOString().split('T')[0];
    const logFile = `/tmp/openclaw/openclaw-${today}.log`;
    if (!fs.existsSync(logFile)) return null;
    const content = fs.readFileSync(logFile, 'utf8');
    // Search last 8000 chars for recent QR data
    const recent = content.slice(-8000);
    return extractQRData(recent);
  } catch {
    return null;
  }
}

// GET /qr  → base64 PNG of the current QR code (or { connected: true })
app.get('/qr', auth, async (req, res) => {
  const isRunning = getOpenclawStatus() === 'running';

  // ── Fast path: check log heuristics first (instant) ─────────────────────────
  const logs = getJournalLogsSinceLastStart(200);
  const linkedViaRPC = isWhatsAppLinkedViaRPC();
  const linkedRecently = whatsappLinkedAt && (Date.now() - whatsappLinkedAt < 30_000);
  if (linkedViaRPC || linkedRecently || isWhatsAppConnected(isRunning, logs)) {
    if (whatsappLoginProcess && !whatsappLoginProcess.killed) {
      cleanupWhatsAppSocket();
    }
    return res.json({ connected: true, qr: null });
  }

  // ── Check if we have raw QR data from the Baileys helper ──────────────────
  if (whatsappRawQR && (Date.now() - whatsappQRTimestamp < 120_000)) {
    try {
      const pngBase64 = await QRCode.toDataURL(whatsappRawQR, {
        errorCorrectionLevel: 'L',
        type: 'image/png',
        width: 300,
        margin: 2,
      });
      return res.json({ connected: false, qr: pngBase64, generated_at: whatsappQRTimestamp });
    } catch (err) {
      console.error('[qr] QRCode.toDataURL error:', err.message);
    }
  }

  // ── Fallback: try to extract QR data from logs ──────────────────────────────
  let qrData = extractQRData(logs);
  if (!qrData) qrData = readOpenClawLogQR();

  if (qrData) {
    try {
      const pngBase64 = await QRCode.toDataURL(qrData, {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        width: 300,
        margin: 2,
      });
      return res.json({ connected: false, qr: pngBase64, generated_at: Date.now() });
    } catch (err) { /* fall through */ }
  }

  // No QR data found — trigger login process (fire and forget)
  startWhatsAppLogin().catch(err => console.error('[qr] startWhatsAppLogin error:', err.message));
  return res.status(404).json({ error: 'QR not available yet', connected: false, login_started: true });
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
  // Safety valve: force-release lock after 60s
  configuringTimer = setTimeout(() => {
    console.error('[vps-agent] configure lock timed out — force-releasing');
    isConfiguring = false;
    configuringTimer = null;
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
    // Update config.json — validate model, channel, assistant_name inputs
    const VALID_MODELS = [
      // Anthropic
      'claude-opus-4.6', 'claude-opus-4.5', 'claude-opus-4.1', 'claude-opus-4',
      'claude-sonnet-4.6', 'claude-sonnet-4.5', 'claude-sonnet-4', 'claude-3.7-sonnet',
      'claude-haiku-4.5', 'claude-3.5-haiku',
      // OpenAI GPT-5
      'gpt-5.4-pro', 'gpt-5.4', 'gpt-5.3-codex', 'gpt-5.3-chat',
      'gpt-5.2-pro', 'gpt-5.2', 'gpt-5.2-codex', 'gpt-5.2-chat',
      'gpt-5.1', 'gpt-5.1-codex-max', 'gpt-5', 'gpt-5-mini',
      // OpenAI GPT-4
      'gpt-4.1', 'gpt-4.1-mini', 'gpt-4.1-nano', 'gpt-4o', 'gpt-4o-mini',
      // OpenAI o-series
      'o4-mini', 'o3', 'o3-pro', 'o3-mini',
    ];
    const VALID_CHANNELS = ['whatsapp', 'telegram', 'discord'];
    // Accept OpenRouter models (format: provider/model-name) in credits mode,
    // plus the hardcoded BYOK models
    const MODEL_REGEX = /^[a-zA-Z0-9_-]+\/[a-zA-Z0-9._-]+$/;
    const safeModel = model
      ? (VALID_MODELS.includes(model) ? model : (MODEL_REGEX.test(model) ? model : null))
      : null;
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
    if (openrouter_key) {
      // Configure OpenRouter API key in openclaw.json env section (native OpenClaw config)
      try {
        const sanitizedKey = sanitizeEnvValue(openrouter_key);
        runCmd(openclawExec(`config set env.OPENROUTER_API_KEY ${sanitizedKey}`));
        console.log('[configure] set OPENROUTER_API_KEY in openclaw.json env');
      } catch (err) {
        console.error('[configure] openclaw config set env failed:', err.message);
      }
      // Also write to .env as fallback
      envUpdates.OPENROUTER_API_KEY = openrouter_key;
    }

    // Set model in OpenClaw via CLI — format: openrouter/<provider>/<model> for OpenRouter models
    if (safeModel) {
      try {
        // OpenRouter models (format: provider/model-name) need "openrouter/" prefix for OpenClaw
        const openclawModel = MODEL_REGEX.test(safeModel) ? `openrouter/${safeModel}` : safeModel;
        runCmd(openclawExec(`models set ${openclawModel}`));
        console.log(`[configure] set OpenClaw model to ${openclawModel}`);
      } catch (err) {
        console.error('[configure] openclaw models set failed:', err.message);
      }
    }
    if (openai_token) envUpdates.OPENAI_ACCESS_TOKEN = openai_token;
    if (timezone) envUpdates.TZ = timezone;
    if (Object.keys(envUpdates).length > 0) writeEnvFile(envUpdates);

    exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (restartErr) => {
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
    isRestarting = false;
    restartingTimer = null;
  }, LOCK_TIMEOUT_MS);

  const previous_status = getOpenclawStatus();

  exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (err) => {
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

// GET /chat-url → returns the OpenClaw Control UI URL and availability
app.get('/chat-url', auth, (req, res) => {
  try {
    // Get the public IP of this machine
    let publicIp = '';
    try {
      publicIp = runCmd("curl -s --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}'").trim();
    } catch {
      try { publicIp = runCmd("hostname -I | awk '{print $1}'").trim(); } catch { publicIp = 'localhost'; }
    }

    // Read gateway token from OpenClaw config (files owned by openclaw user, read via sudo)
    let gatewayToken = '';
    for (const cfgPath of OPENCLAW_CONFIG_PATHS) {
      try {
        const raw = runCmd(`sudo -u openclaw /usr/bin/cat '${cfgPath}' 2>/dev/null`);
        const config = JSON.parse(raw);
        if (config?.gateway?.auth?.token) {
          gatewayToken = config.gateway.auth.token;
          break;
        }
      } catch { /* try next */ }
    }

    // OpenClaw gateway listens on port 18789 by default
    const gatewayPort = 18789;

    // Check if gateway port is responding (--bind lan may not listen on localhost)
    let available = false;
    const gatewayHost = getGatewayHost();
    try {
      runCmd(`nc -z -w2 ${shellQuote(gatewayHost)} ${gatewayPort} 2>/dev/null`);
      available = true;
    } catch {
      try {
        // Fallback: check on public IP (openclaw --bind lan listens there)
        if (publicIp && publicIp !== 'localhost') {
          runCmd(`nc -z -w2 ${publicIp} ${gatewayPort} 2>/dev/null`);
          available = true;
        }
      } catch {
        // Last resort: check if systemd says openclaw is active
        try {
          const status = runCmd('systemctl is-active openclaw').trim();
          available = status === 'active';
        } catch { available = false; }
      }
    }

    // OpenClaw Control UI now expects to be opened top-level from the gateway
    // origin. When proxied through nginx on 443, the gateway URL is same-origin.
    const sslipDomain = publicIp.replace(/\./g, '-') + '.sslip.io';
    const baseUrl = `https://${sslipDomain}/`;
    const url = gatewayToken
      ? `${baseUrl}#token=${encodeURIComponent(gatewayToken)}`
      : baseUrl;
    res.json({ url, available });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /chat-approve → auto-approve pending device pairing requests
app.post('/chat-approve', auth, (req, res) => {
  try {
    // List pending devices and approve all
    let listOut = '';
    try {
      listOut = runCmd(`${openclawDevicesExec('list --json')} 2>/dev/null`);
    } catch { /* ignore */ }

    let approved = 0;
    if (listOut) {
      try {
        const data = JSON.parse(listOut);
        const pending = data?.pending || [];
        for (const p of pending) {
          const reqId = p.requestId || p.id;
          if (reqId) {
            try {
              runCmd(`${openclawDevicesExec(`approve ${shellQuote(reqId)}`)} 2>/dev/null`);
              approved++;
            } catch { /* ignore */ }
          }
        }
      } catch {
        // Fallback: parse text output for request IDs
        const lines = listOut.split('\n');
        for (const line of lines) {
          const match = line.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/);
          if (match) {
            try {
              runCmd(`${openclawDevicesExec(`approve ${shellQuote(match[1])}`)} 2>/dev/null`);
              approved++;
            } catch { /* ignore */ }
          }
        }
      }
    }

    res.json({ approved });
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
    const gatewayHealth = readGatewayHealth();
    const snapshot = buildChannelSnapshot(config, env, logs, gatewayHealth);

    res.json({
      whatsapp: {
        status: snapshot.whatsapp.connected
          ? 'connected'
          : (snapshot.whatsapp.desired
            ? (snapshot.whatsapp.needs_relink ? 'needs_relink' : 'disconnected')
            : 'not_configured'),
        phone: config.whatsapp_phone || null,
        auth_present: snapshot.whatsapp.auth_present,
        login_in_progress: snapshot.whatsapp.login_in_progress,
      },
      telegram: {
        status: !snapshot.telegram.desired
          ? 'not_configured'
          : (snapshot.telegram.connected ? 'connected' : 'configured'),
        username: config.telegram_username || null,
      },
      discord: {
        status: !snapshot.discord.desired
          ? 'not_configured'
          : (snapshot.discord.connected ? 'connected' : 'configured'),
        guild: config.discord_guild_name || config.discord_guild_id || null,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/watchdog', auth, (req, res) => {
  res.json(watchdogState);
});

app.post('/self-heal', auth, async (req, res) => {
  try {
    const result = await runWatchdogCycle('manual');
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /channels/telegram → body: { token }
app.post('/channels/telegram', auth, async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token é obrigatório.' });

  // Validar token com a API do Telegram
  let botUsername = null;
  try {
    const tgRes = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const tgData = await tgRes.json();
    if (!tgData.ok) {
      return res.status(400).json({ error: 'Token do Telegram inválido. Verifique e tente novamente.' });
    }
    botUsername = tgData.result.username;
    console.log(`[channels] Telegram bot verified: @${botUsername}`);
  } catch (err) {
    return res.status(500).json({ error: 'Não foi possível verificar o token. Tente novamente.' });
  }

  try {
    // Configure Telegram channel via OpenClaw config set
    try {
      const safeToken = sanitizeEnvValue(token);
      runCmd(`${openclawExec(`config set channels.telegram.botToken '"${safeToken}"' --strict-json`)} 2>/dev/null || true`);
      runCmd(`${openclawExec('config set channels.telegram.enabled true --strict-json')} 2>/dev/null || true`);
    } catch (err) {
      console.warn('[telegram] OpenClaw CLI config warning:', err.message);
    }

    // Also write to .env as fallback
    writeEnvFile({ TELEGRAM_BOT_TOKEN: token });

    exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (err) => {
      if (err) console.error('[telegram] restart error:', err.message);
    });

    res.json({ success: true, username: botUsername });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /channels/discord → body: { token, guild_id }
// Validate Discord bot token and guild_id before saving
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
      headers: { Authorization: `Bot ${token}` }
    });
    if (!discordRes.ok) {
      return res.status(400).json({ error: 'Token Discord inválido. Verifique o bot token.' });
    }
    const botInfo = await discordRes.json();
    console.log(`[channels] Discord bot verified: ${botInfo.username}`);
  } catch (err) {
    return res.status(500).json({ error: 'Não foi possível verificar o token Discord. Tente novamente.' });
  }

  try {
    // Configure Discord channel via OpenClaw config set
    try {
      const safeToken = sanitizeEnvValue(token);
      runCmd(`${openclawExec(`config set channels.discord.token '"${safeToken}"' --strict-json`)} 2>/dev/null || true`);
      runCmd(`${openclawExec('config set channels.discord.enabled true --strict-json')} 2>/dev/null || true`);
    } catch (err) {
      console.warn('[discord] OpenClaw CLI config warning:', err.message);
    }

    // Also write to .env and config as fallback
    writeEnvFile({ DISCORD_BOT_TOKEN: token });
    if (guild_id) writeConfig({ discord_guild_id: guild_id });

    exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (err) => {
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
      // Delete WhatsApp session files so the bot doesn't auto-reconnect
      // Respond immediately, then fire-and-forget the restart
      res.json({ success: true });
      exec(
        'rm -rf /home/openclaw/.openclaw/session /home/openclaw/.openclaw/.wwebjs_auth /home/openclaw/.openclaw/.baileys /home/openclaw/.openclaw/credentials/whatsapp /home/openclaw/.openclaw/.openclaw/channels/whatsapp/default/auth /home/openclaw/.openclaw/channels/whatsapp/default/auth && sudo systemctl restart openclaw',
        { timeout: 30_000 },
        (err) => {
          if (err) console.error('[vps-agent] restart after whatsapp disconnect failed:', err.message);
        }
      );
      return;
    } else {
      // Disable channel via OpenClaw config
      try {
        runCmd(`${openclawExec(`config set channels.${channel}.enabled false --strict-json`)} 2>/dev/null || true`);
      } catch { /* ignore */ }

      const env = readEnvFile();
      delete env[envKeyMap[channel]];
      const content = Object.entries(env).map(([k, v]) => `${k}=${sanitizeEnvValue(v)}`).join('\n') + '\n';
      fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
      try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }

      exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (err) => {
        if (err) console.error('[disconnect] restart error:', err.message);
      });
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /usage/pending → return buffered usage events and clear
app.get('/usage/pending', auth, (req, res) => {
  res.json({ events: usageBuffer.slice(), credit_blocked: creditBlocked });
});

// POST /usage/ack → remove usage events that were successfully processed
app.post('/usage/ack', auth, (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter((id) => typeof id === 'string') : [];
  if (ids.length === 0) {
    return res.json({ removed: 0, pending: usageBuffer.length });
  }

  const ackedIds = new Set(ids);
  let removed = 0;
  for (let i = usageBuffer.length - 1; i >= 0; i -= 1) {
    if (ackedIds.has(usageBuffer[i].id)) {
      usageBuffer.splice(i, 1);
      removed += 1;
    }
  }

  res.json({ removed, pending: usageBuffer.length });
});

// POST /credit-status → receive credit status from backend, start/stop openclaw
app.post('/credit-status', auth, (req, res) => {
  const { blocked, balance_brl } = req.body || {};

  if (blocked === true && !creditBlocked) {
    creditBlocked = true;
    exec('sudo systemctl stop openclaw', { timeout: 30_000 }, (err) => {
      if (err) console.error('[credit-guard] failed to stop openclaw:', err.message);
      else console.log('[credit-guard] openclaw stopped — credits exhausted');
    });
  } else if (blocked === false && creditBlocked) {
    creditBlocked = false;
    exec('sudo systemctl start openclaw', { timeout: 30_000 }, (err) => {
      if (err) console.error('[credit-guard] failed to start openclaw:', err.message);
      else console.log('[credit-guard] openclaw started — credits restored');
    });
  }

  res.json({ credit_blocked: creditBlocked, balance_brl: balance_brl || 0 });
});

// POST /configure-codex-oauth → receive OAuth token, configure OpenClaw for Codex
app.post('/configure-codex-oauth', auth, (req, res) => {
  const { oauth_data } = req.body || {};
  if (!oauth_data) {
    return res.status(400).json({ error: 'oauth_data is required' });
  }

  try {
    // Write OAuth credentials to OpenClaw credentials directory
    const credDir = path.join(OPENCLAW_CONFIG_DIR, 'credentials');
    runCmd(`sudo -u openclaw mkdir -p '${credDir}'`);

    const oauthPath = path.join(credDir, 'oauth.json');
    const safeContent = JSON.stringify(oauth_data).replace(/'/g, "'\\''");
    runCmd(`echo '${safeContent}' | sudo -u openclaw tee '${oauthPath}' > /dev/null`);
    runCmd(`sudo -u openclaw chmod 600 '${oauthPath}'`);

    // Update config to use openai-codex model
    writeConfig({ model: 'openai-codex/gpt-5.4', ai_mode: 'chatgpt' });

    // Restart OpenClaw to pick up new auth
    exec('sudo systemctl restart openclaw', { timeout: 30_000 }, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to restart openclaw: ' + err.message });
      }
      res.json({ success: true, model: 'openai-codex/gpt-5.4' });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start (HTTPS with self-signed TLS, fallback to HTTP) ─────────────────────
try {
  const tls = {
    key: require('fs').readFileSync(TLS_KEY),
    cert: require('fs').readFileSync(TLS_CERT),
  };
  https.createServer(tls, app).listen(PORT, () => {
    console.log(`🔒 OriClaw VPS Agent running on HTTPS port ${PORT}`);
  });
} catch (err) {
  console.warn('⚠️  TLS certs not found, falling back to HTTP:', err.message);
  app.listen(PORT, () => {
    console.log(`🌀 OriClaw VPS Agent running on HTTP port ${PORT} (no TLS)`);
  });
}
