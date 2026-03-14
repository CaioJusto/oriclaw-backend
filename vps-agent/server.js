'use strict';

const express = require('express');
const https = require('https');
const crypto = require('crypto');
const { execFile, execSync, spawn, spawnSync } = require('child_process');
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
const OPENCLAW_PAIRING_ROOT_DIRS = [
  path.join(OPENCLAW_CONFIG_DIR, '.openclaw'),
  OPENCLAW_CONFIG_DIR,
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

function extractErrorMessage(err) {
  if (!err) return '';
  if (typeof err === 'string') return err;
  if (typeof err.message === 'string') return err.message;
  return String(err);
}

function isTransientWhatsAppSocketError(err) {
  const message = extractErrorMessage(err);
  const statusCode = Number(err?.output?.statusCode || err?.data?.statusCode || err?.statusCode || 0);
  return (
    statusCode === 428 ||
    statusCode === 515 ||
    message.includes('Connection Closed') ||
    message.includes('Connection Terminated')
  );
}

function handleProcessLevelError(kind, err) {
  if (isTransientWhatsAppSocketError(err)) {
    console.warn(`[whatsapp] suppressed ${kind}:`, extractErrorMessage(err));
    cleanupWhatsAppSocket();
    return;
  }

  console.error(`[fatal] ${kind}:`, err);
  process.exit(1);
}

process.on('unhandledRejection', (reason) => {
  handleProcessLevelError('unhandledRejection', reason);
});

process.on('uncaughtException', (err) => {
  handleProcessLevelError('uncaughtException', err);
});

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

function runProcess(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: options.timeout ?? 30_000,
    input: options.input,
    env: options.env ?? process.env,
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0 && !options.allowFailure) {
    const stderr = typeof result.stderr === 'string' ? result.stderr.trim() : '';
    const stdout = typeof result.stdout === 'string' ? result.stdout.trim() : '';
    throw new Error(stderr || stdout || `${command} exited with status ${result.status}`);
  }

  return typeof result.stdout === 'string' ? result.stdout : '';
}

function runProcessCombined(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: options.timeout ?? 30_000,
    input: options.input,
    env: options.env ?? process.env,
  });

  if (result.error) {
    throw result.error;
  }

  const stdout = typeof result.stdout === 'string' ? result.stdout : '';
  const stderr = typeof result.stderr === 'string' ? result.stderr : '';
  const combined = [stdout.trim(), stderr.trim()].filter(Boolean).join('\n');

  if (result.status !== 0 && !options.allowFailure) {
    throw new Error(combined || `${command} exited with status ${result.status}`);
  }

  return combined;
}

function runProcessAsync(command, args, callback, options = {}) {
  return execFile(command, args, {
    timeout: options.timeout ?? 30_000,
    encoding: 'utf8',
    env: options.env ?? process.env,
  }, callback);
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

function readConfigPath(configPath) {
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch {
    try {
      const raw = runProcess('sudo', ['-u', 'openclaw', '/usr/bin/cat', configPath], { allowFailure: true }).trim();
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }
}

/**
 * Read the active OpenClaw config.
 */
function readConfig() {
  for (const configPath of OPENCLAW_CONFIG_PATHS) {
    const config = readConfigPath(configPath);
    if (config) return config;
  }
  return {};
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

function getDevicePairingFiles(rootDir) {
  const dir = path.join(rootDir, 'devices');
  return {
    pendingPath: path.join(dir, 'pending.json'),
    pairedPath: path.join(dir, 'paired.json'),
  };
}

function safeReadJsonFile(filePath, fallback) {
  try {
    const raw = runProcess('sudo', ['-u', 'openclaw', '/usr/bin/cat', filePath], { allowFailure: true }).trim();
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function writeOwnedJsonFile(filePath, value) {
  const dir = path.dirname(filePath);
  const tempPath = path.join(dir, `${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`);
  const content = `${JSON.stringify(value, null, 2)}\n`;

  runProcess('sudo', ['-u', 'openclaw', 'mkdir', '-p', dir]);
  runProcess('sudo', ['-u', 'openclaw', 'tee', tempPath], { input: content, allowFailure: true });
  runProcess('sudo', ['-u', 'openclaw', 'chmod', '600', tempPath], { allowFailure: true });
  runProcess('sudo', ['-u', 'openclaw', 'mv', tempPath, filePath]);
}

function normalizeStringList(...values) {
  const out = [];
  const seen = new Set();

  const addValue = (value) => {
    if (typeof value !== 'string') return;
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) return;
    seen.add(trimmed);
    out.push(trimmed);
  };

  for (const value of values) {
    if (Array.isArray(value)) {
      value.forEach(addValue);
    } else {
      addValue(value);
    }
  }

  return out;
}

function approvePendingDevicePairings(options = {}) {
  let approved = 0;
  const seenRoots = new Set();
  const allowedClientModes = normalizeStringList(options.clientModes);
  const allowedClientIds = normalizeStringList(options.clientIds);

  for (const rootDir of OPENCLAW_PAIRING_ROOT_DIRS) {
    if (!rootDir || seenRoots.has(rootDir)) continue;
    seenRoots.add(rootDir);

    const { pendingPath, pairedPath } = getDevicePairingFiles(rootDir);
    const pending = safeReadJsonFile(pendingPath, {});
    const paired = safeReadJsonFile(pairedPath, {});
    const pendingIds = Object.keys(pending).sort((left, right) => {
      const leftTs = Number(pending[left]?.ts || 0);
      const rightTs = Number(pending[right]?.ts || 0);
      return leftTs - rightTs;
    });

    let changed = false;

    for (const requestId of pendingIds) {
      const req = pending[requestId];
      const deviceId = typeof req?.deviceId === 'string' ? req.deviceId.trim() : '';
      const publicKey = typeof req?.publicKey === 'string' ? req.publicKey.trim() : '';
      const clientMode = typeof req?.clientMode === 'string' ? req.clientMode.trim() : '';
      const clientId = typeof req?.clientId === 'string' ? req.clientId.trim() : '';

      if (!deviceId || !publicKey) {
        delete pending[requestId];
        changed = true;
        continue;
      }

      const modeAllowed = allowedClientModes.length === 0 || allowedClientModes.includes(clientMode);
      const clientAllowed = allowedClientIds.length === 0 || allowedClientIds.includes(clientId);
      if (!modeAllowed || !clientAllowed) {
        continue;
      }

      const existing = paired[deviceId] && typeof paired[deviceId] === 'object'
        ? paired[deviceId]
        : {};
      const now = Date.now();
      const role = typeof req?.role === 'string' && req.role.trim()
        ? req.role.trim()
        : (typeof existing?.role === 'string' ? existing.role.trim() : '');
      const roles = normalizeStringList(existing?.roles, existing?.role, req?.roles, req?.role);
      const approvedScopes = normalizeStringList(existing?.approvedScopes, existing?.scopes, req?.scopes);
      const tokens = existing?.tokens && typeof existing.tokens === 'object'
        ? { ...existing.tokens }
        : {};

      if (role) {
        const existingToken = tokens[role] && typeof tokens[role] === 'object' ? tokens[role] : null;
        const tokenScopes = approvedScopes.length > 0
          ? approvedScopes
          : normalizeStringList(existingToken?.scopes, existing?.approvedScopes, existing?.scopes);

        tokens[role] = {
          token: crypto.randomBytes(32).toString('base64url'),
          role,
          scopes: tokenScopes,
          createdAtMs: typeof existingToken?.createdAtMs === 'number' ? existingToken.createdAtMs : now,
          rotatedAtMs: existingToken ? now : undefined,
          revokedAtMs: undefined,
          lastUsedAtMs: existingToken?.lastUsedAtMs,
        };
      }

      paired[deviceId] = {
        ...existing,
        deviceId,
        publicKey,
        displayName: req?.displayName ?? existing?.displayName,
        platform: req?.platform ?? existing?.platform,
        deviceFamily: req?.deviceFamily ?? existing?.deviceFamily,
        clientId: req?.clientId ?? existing?.clientId,
        clientMode: req?.clientMode ?? existing?.clientMode,
        role: role || existing?.role,
        roles,
        scopes: approvedScopes,
        approvedScopes,
        remoteIp: req?.remoteIp ?? existing?.remoteIp,
        tokens,
        createdAtMs: typeof existing?.createdAtMs === 'number' ? existing.createdAtMs : now,
        approvedAtMs: now,
      };

      delete pending[requestId];
      approved += 1;
      changed = true;
    }

    if (changed) {
      writeOwnedJsonFile(pendingPath, pending);
      writeOwnedJsonFile(pairedPath, paired);
    }
  }

  return approved;
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
  const linkedRecently = whatsappLinkedAt && (Date.now() - whatsappLinkedAt < 30_000);
  const whatsappConnected =
    linkedRecently ||
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

  const channels = {
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
      connection_known: !!gatewayHealth,
      connected: telegramConnected,
    },
    discord: {
      desired: discordDesired,
      token_present: !!env.DISCORD_BOT_TOKEN,
      guild_id_present: !!config?.discord_guild_id,
      connection_known: !!gatewayHealth,
      connected: discordConnected,
    },
  };

  channels.whatsapp.stabilizing = isWhatsAppConnectionStabilizing(channels);
  return channels;
}

function getDegradedChannels(channels) {
  const degraded = [];

  if (
    channels.whatsapp.desired &&
    channels.whatsapp.auth_present &&
    !channels.whatsapp.connected &&
    !channels.whatsapp.stabilizing
  ) {
    degraded.push('whatsapp');
  }
  if (channels.telegram.desired && channels.telegram.connection_known && !channels.telegram.connected) {
    degraded.push('telegram');
  }
  if (channels.discord.desired && channels.discord.connection_known && !channels.discord.connected) {
    degraded.push('discord');
  }

  return degraded;
}

const WATCHDOG_INTERVAL_MS = 60_000;
const WATCHDOG_RESTART_COOLDOWN_MS = 120_000;
const WATCHDOG_QR_COOLDOWN_MS = 5 * 60_000;
const WATCHDOG_WHATSAPP_CONNECT_GRACE_MS = 4 * 60_000;

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

function isRecentTimestamp(lastMs, windowMs) {
  return Boolean(lastMs) && (Date.now() - lastMs) < windowMs;
}

function isRecentIsoTimestamp(lastIso, windowMs) {
  return Boolean(lastIso) && !canRunAfter(lastIso, windowMs);
}

function isWhatsAppConnectionStabilizing(channels) {
  const whatsapp = channels?.whatsapp;
  if (!whatsapp || !whatsapp.desired || whatsapp.connected) {
    return false;
  }

  return (
    whatsapp.login_in_progress ||
    isRecentTimestamp(whatsappLoginStartedAt, WATCHDOG_WHATSAPP_CONNECT_GRACE_MS) ||
    isRecentTimestamp(whatsappAuthSyncedAt, WATCHDOG_WHATSAPP_CONNECT_GRACE_MS) ||
    isRecentTimestamp(whatsappLinkedAt, WATCHDOG_WHATSAPP_CONNECT_GRACE_MS) ||
    isRecentTimestamp(whatsappPairingRestartAt, WATCHDOG_WHATSAPP_CONNECT_GRACE_MS) ||
    isRecentIsoTimestamp(watchdogState.last_qr_bootstrap_at, WATCHDOG_WHATSAPP_CONNECT_GRACE_MS)
  );
}

function restartOpenclawForWatchdog(reason) {
  invalidateGatewayHealthCache();
  runSystemctl(['reset-failed', 'openclaw'], { allowFailure: true });
  runSystemctl(['restart', 'openclaw']);
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
      setOpenclawJsonString('channels.telegram.botToken', sanitizeEnvValue(env.TELEGRAM_BOT_TOKEN));
      setOpenclawJsonValue('channels.telegram.enabled', true);
      repaired.push('telegram');
    }
  }

  if (env.DISCORD_BOT_TOKEN) {
    const discordEnabled = config?.channels?.discord?.enabled === true;
    const discordToken = config?.channels?.discord?.token;
    if (!discordEnabled || discordToken !== env.DISCORD_BOT_TOKEN) {
      setOpenclawJsonString('channels.discord.token', sanitizeEnvValue(env.DISCORD_BOT_TOKEN));
      setOpenclawJsonValue('channels.discord.enabled', true);
      repaired.push('discord');
    }
  }

  if ((config?.channel === 'whatsapp' || hasWhatsAppAuthState()) && config?.channels?.whatsapp?.enabled !== true) {
    setOpenclawJsonValue('channels.whatsapp.enabled', true);
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
    if (openclawStatus === 'running') {
      refreshGatewayHealthCache({ force: true });
    }
    const gatewayHealth = openclawStatus === 'running'
      ? readGatewayHealth({ refresh: false })
      : null;
    const channels = buildChannelSnapshot(config, env, logs, gatewayHealth);
    const degradedChannels = getDegradedChannels(channels);
    watchdogState.channels = channels;
    watchdogState.degraded_channels = degradedChannels;

    let restartReason = null;
    let restarted = false;
    let repaired = [];

    if (openclawStatus !== 'running') {
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
      restartReason = 'openclaw_not_running';
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

    let liveChannels = watchdogState.channels;
    let liveDegradedChannels = watchdogState.degraded_channels;
    try {
      const config = readConfig();
      const env = readEnvFile();
      const logs = getJournalLogsSinceLastStart(120);
      if (openclaw === 'running') {
        refreshGatewayHealthCache({ force: true });
      }
      const gatewayHealth = openclaw === 'running'
        ? readGatewayHealth({ refresh: false })
        : null;
      liveChannels = buildChannelSnapshot(config, env, logs, gatewayHealth);
      liveDegradedChannels = getDegradedChannels(liveChannels);
    } catch (snapshotErr) {
      console.warn('[health/detailed] live channel snapshot failed:', snapshotErr.message);
    }

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
      watchdog: {
        ...watchdogState,
        channels: liveChannels,
        degraded_channels: liveDegradedChannels,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── OpenClaw command helpers ─────────────────────────────────────────────────
const OPENCLAW_CMD = '/home/openclaw/.npm-global/bin/openclaw';
const OPENCLAW_SUDO_ARGS = [
  '-u', 'openclaw',
  'OPENCLAW_HOME=/home/openclaw/.openclaw',
  'HOME=/home/openclaw',
  OPENCLAW_CMD,
];

function runOpenclaw(args, options = {}) {
  return runProcess('sudo', [...OPENCLAW_SUDO_ARGS, ...args], options);
}

function runOpenclawAsync(args, callback, options = {}) {
  return runProcessAsync('sudo', [...OPENCLAW_SUDO_ARGS, ...args], callback, options);
}

function runOpenclawCombined(args, options = {}) {
  return runProcessCombined('sudo', [...OPENCLAW_SUDO_ARGS, ...args], options);
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

function getPublicIpv4() {
  try {
    return runCmd("curl -s --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}'").trim();
  } catch {
    try {
      return runCmd("hostname -I | awk '{print $1}'").trim();
    } catch {
      return 'localhost';
    }
  }
}

function toWebSocketOrigin(origin) {
  const trimmed = typeof origin === 'string' ? origin.trim().replace(/\/+$/, '') : '';
  if (!trimmed) return '';
  if (trimmed.startsWith('https://')) return `wss://${trimmed.slice('https://'.length)}`;
  if (trimmed.startsWith('http://')) return `ws://${trimmed.slice('http://'.length)}`;
  return '';
}

function readGatewayConnectionConfig() {
  const activeConfig = readConfig();
  let port = Number(activeConfig?.gateway?.port || 18789);
  let token = typeof activeConfig?.gateway?.auth?.token === 'string' ? activeConfig.gateway.auth.token : '';
  let allowedOrigins = Array.isArray(activeConfig?.gateway?.controlUi?.allowedOrigins)
    ? activeConfig.gateway.controlUi.allowedOrigins
    : [];

  for (const cfgPath of OPENCLAW_CONFIG_PATHS) {
    try {
      const raw = runCmd(`sudo -u openclaw /usr/bin/cat '${cfgPath}' 2>/dev/null`);
      const config = JSON.parse(raw);
      const candidatePort = Number(config?.gateway?.port || port);
      if (Number.isFinite(candidatePort) && candidatePort > 0) {
        port = candidatePort;
      }
      if (!token && typeof config?.gateway?.auth?.token === 'string' && config.gateway.auth.token) {
        token = config.gateway.auth.token;
      }
      if (allowedOrigins.length === 0 && Array.isArray(config?.gateway?.controlUi?.allowedOrigins)) {
        allowedOrigins = config.gateway.controlUi.allowedOrigins;
      }
      if (token && allowedOrigins.length > 0) break;
    } catch { /* ignore invalid config variants */ }
  }

  return { port, token, allowedOrigins };
}

let lastSuccessfulGatewayUrl = '';
let lastSuccessfulGatewayUrlAt = 0;
const GATEWAY_URL_CACHE_TTL_MS = 10 * 60_000;
const GATEWAY_DEVICES_TIMEOUT_MS = 4_000;
const GATEWAY_HEALTH_CACHE_TTL_MS = 60_000;
const GATEWAY_HEALTH_REFRESH_TIMEOUT_MS = 5_000;
const gatewayHealthCache = {
  data: null,
  fetchedAt: 0,
  refreshing: false,
};

function invalidateGatewayHealthCache() {
  gatewayHealthCache.data = null;
  gatewayHealthCache.fetchedAt = 0;
}

function getGatewayUrlCandidates() {
  const { port, token, allowedOrigins } = readGatewayConnectionConfig();
  const urls = [];
  const loopbackUrl = `ws://127.0.0.1:${port}`;
  const addUrl = (value) => {
    if (typeof value !== 'string' || !value || urls.includes(value)) return;
    urls.push(value);
  };

  // Internal agent calls must prefer the local gateway socket instead of the
  // public sslip/nginx path. Using the public URL here can hang on hairpin or
  // firewall paths and makes local health checks depend on external routing.
  addUrl(loopbackUrl);
  addUrl(`ws://${getGatewayHost()}:${port}`);

  if (lastSuccessfulGatewayUrl && (Date.now() - lastSuccessfulGatewayUrlAt) < GATEWAY_URL_CACHE_TTL_MS) {
    addUrl(lastSuccessfulGatewayUrl);
  } else {
    lastSuccessfulGatewayUrl = '';
    lastSuccessfulGatewayUrlAt = 0;
  }

  for (const origin of allowedOrigins) {
    addUrl(toWebSocketOrigin(origin));
  }

  const interfaces = os.networkInterfaces();
  const privateIps = [];
  const publicIps = [];
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      if (!entry || entry.family !== 'IPv4' || entry.internal || !entry.address) continue;
      if (isPrivateIpv4(entry.address)) privateIps.push(entry.address);
      else publicIps.push(entry.address);
    }
  }

  for (const ip of [...new Set(privateIps)]) addUrl(`ws://${ip}:${port}`);

  const publicIp = getPublicIpv4();
  if (publicIp && publicIp !== 'localhost') {
    addUrl(`ws://${publicIp}:${port}`);
    addUrl(`wss://${publicIp.replace(/\./g, '-')}.sslip.io`);
  }

  for (const ip of [...new Set(publicIps)]) addUrl(`ws://${ip}:${port}`);

  const args = ['--url', loopbackUrl];
  if (token) {
    args.push('--token', token);
  }

  return {
    token,
    urls,
    fallbackArgs: args,
  };
}

function getGatewayCliArgs(url) {
  const { token } = getGatewayUrlCandidates();
  const args = ['--url', url];
  if (token) {
    args.push('--token', token);
  }
  return args;
}

function runOpenclawGatewayCall(method, extraArgs = [], options = {}) {
  return runOpenclaw(['gateway', 'call', ...getGatewayUrlCandidates().fallbackArgs, ...extraArgs, method], options);
}

function runOpenclawGatewayCallAsync(method, extraArgs = [], callback, options = {}) {
  return runOpenclawAsync(
    ['gateway', 'call', ...getGatewayUrlCandidates().fallbackArgs, ...extraArgs, method],
    callback,
    options,
  );
}

function runOpenclawDevices(args, options = {}) {
  const { urls, fallbackArgs } = getGatewayUrlCandidates();
  let lastError = null;

  for (const url of urls) {
    try {
      const out = runOpenclaw(['devices', ...args, ...getGatewayCliArgs(url)], {
        ...options,
        timeout: options.timeout ?? GATEWAY_DEVICES_TIMEOUT_MS,
      });
      lastSuccessfulGatewayUrl = url;
      lastSuccessfulGatewayUrlAt = Date.now();
      return out;
    } catch (err) {
      lastError = err;
    }
  }

  if (options.allowFailure) {
    try {
      return runOpenclaw(['devices', ...args, ...fallbackArgs], {
        ...options,
        timeout: options.timeout ?? GATEWAY_DEVICES_TIMEOUT_MS,
      });
    } catch (err) {
      lastError = err;
      return '';
    }
  }

  throw lastError || new Error('Unable to reach OpenClaw gateway for devices command');
}

function refreshGatewayHealthCache(options = {}) {
  const force = options.force === true;
  const now = Date.now();
  const cacheAge = now - gatewayHealthCache.fetchedAt;
  if (!force && gatewayHealthCache.refreshing) return false;
  if (!force && gatewayHealthCache.data && cacheAge < GATEWAY_HEALTH_CACHE_TTL_MS) return false;

  gatewayHealthCache.refreshing = true;
  runOpenclawGatewayCallAsync('health', ['--json'], (err, stdout) => {
    gatewayHealthCache.refreshing = false;
    if (err) {
      return;
    }

    const parsed = safeJsonParse(typeof stdout === 'string' ? stdout : '');
    if (!parsed) {
      return;
    }

    gatewayHealthCache.data = parsed;
    gatewayHealthCache.fetchedAt = Date.now();
  }, {
    timeout: GATEWAY_HEALTH_REFRESH_TIMEOUT_MS,
  });

  return true;
}

function readGatewayHealth(options = {}) {
  const allowStale = options.allowStale !== false;
  const refresh = options.refresh !== false;

  if (refresh) {
    refreshGatewayHealthCache();
  }

  const hasFreshData = Boolean(
    gatewayHealthCache.data &&
    (Date.now() - gatewayHealthCache.fetchedAt) < GATEWAY_HEALTH_CACHE_TTL_MS,
  );

  if (hasFreshData) {
    return gatewayHealthCache.data;
  }

  return allowStale ? gatewayHealthCache.data : null;
}

function runSystemctl(args, options = {}) {
  return runProcess('sudo', ['systemctl', ...args], options);
}

function runSystemctlAsync(args, callback, options = {}) {
  return runProcessAsync('sudo', ['systemctl', ...args], callback, options);
}

function truncateOutput(output, maxLength = 12_000) {
  const normalized = typeof output === 'string' ? output.trim() : '';
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength)}\n...[truncated]`;
}

function buildDiagnosticsPayload() {
  const config = readConfig();
  const env = readEnvFile();
  const openclaw = getOpenclawStatus();
  const logsSinceLastStart = getJournalLogsSinceLastStart(120);

  if (openclaw === 'running') {
    refreshGatewayHealthCache({ force: true });
  }

  const gatewayHealth = openclaw === 'running'
    ? readGatewayHealth({ refresh: false })
    : null;
  const channels = buildChannelSnapshot(config, env, logsSinceLastStart, gatewayHealth);
  const degradedChannels = getDegradedChannels(channels);
  const freeMemMb = Math.round(os.freemem() / 1024 / 1024);
  const totalMemMb = Math.round(os.totalmem() / 1024 / 1024);

  return {
    generated_at: new Date().toISOString(),
    summary: {
      openclaw,
      ram_used_mb: Math.max(totalMemMb - freeMemMb, 0),
      ram_total_mb: totalMemMb,
      watchdog: {
        last_run_at: watchdogState.last_run_at || null,
        last_result: watchdogState.last_result || null,
        last_reason: watchdogState.last_reason || null,
        last_error: watchdogState.last_error || null,
        degraded_channels: degradedChannels,
      },
      whatsapp: {
        status: channels.whatsapp.connected
          ? 'connected'
          : (channels.whatsapp.needs_relink ? 'needs_relink' : 'disconnected'),
        desired: channels.whatsapp.desired,
        auth_present: channels.whatsapp.auth_present,
        login_in_progress: channels.whatsapp.login_in_progress,
        stabilizing: channels.whatsapp.stabilizing,
      },
    },
    agent: {
      channels,
      watchdog: {
        ...watchdogState,
        degraded_channels: degradedChannels,
        channels,
      },
    },
    sections: {
      openclaw_health: truncateOutput(runOpenclawCombined(['health'], { allowFailure: true, timeout: 20_000 })),
      openclaw_doctor: truncateOutput(runOpenclawCombined(['doctor'], { allowFailure: true, timeout: 20_000 })),
      channels_list: truncateOutput(runOpenclawCombined(['channels', 'list'], { allowFailure: true, timeout: 15_000 })),
      channels_status: truncateOutput(
        runOpenclawCombined(['channels', 'status', '--probe'], { allowFailure: true, timeout: 15_000 }) ||
        runOpenclawCombined(['channels', 'status'], { allowFailure: true, timeout: 15_000 })
      ),
      channels_capabilities: truncateOutput(runOpenclawCombined(['channels', 'capabilities'], { allowFailure: true, timeout: 15_000 })),
      memory: truncateOutput(runProcessCombined('free', ['-h'], { allowFailure: true, timeout: 10_000 })),
      swap: truncateOutput(runProcessCombined('swapon', ['--show'], { allowFailure: true, timeout: 10_000 })),
      service_status: truncateOutput(runProcessCombined('systemctl', ['status', 'openclaw', '--no-pager', '--lines=20'], { allowFailure: true, timeout: 15_000 })),
      recent_logs: truncateOutput(runCmd('journalctl -u openclaw -n 80 --no-pager --output=short-iso 2>/dev/null || true')),
    },
  };
}

function setOpenclawJsonString(path, value) {
  return runOpenclaw(['config', 'set', path, JSON.stringify(value), '--strict-json'], { allowFailure: true });
}

function setOpenclawJsonValue(path, value) {
  return runOpenclaw(['config', 'set', path, String(value), '--strict-json'], { allowFailure: true });
}

function removeWhatsAppAuthState() {
  for (const authDir of getWhatsAppAuthDirs()) {
    try {
      fs.rmSync(authDir, { recursive: true, force: true });
    } catch (err) {
      console.warn('[whatsapp] failed to remove auth dir:', authDir, err.message);
    }
  }

  for (const dir of [
    path.join(OPENCLAW_CONFIG_DIR, 'session'),
    path.join(OPENCLAW_CONFIG_DIR, '.wwebjs_auth'),
    path.join(OPENCLAW_CONFIG_DIR, '.baileys'),
  ]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (err) {
      console.warn('[whatsapp] failed to remove session dir:', dir, err.message);
    }
  }
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
  return getWhatsAppLinkedFromGatewayHealth(readGatewayHealth({ allowStale: false }));
}

// ── WhatsApp login process management ────────────────────────────────────────
let whatsappLoginProcess = null;
let whatsappLoginStartedAt = 0;
let whatsappRawQR = null;       // raw QR string from Baileys
let whatsappQRTimestamp = 0;
let whatsappLinkedAt = 0;
let whatsappForceFreshLogin = false;
let whatsappAuthSyncTimer = null;
let whatsappAuthSyncInFlight = false;
let whatsappAuthSyncedAt = 0;
let whatsappPairingRestartAt = 0;
const WHATSAPP_TEMP_AUTH_DIR = '/tmp/oriclaw-wa-auth';
const WHATSAPP_QR_MAX_AGE_MS = 30_000;

let whatsappSetupDone = false;
let whatsappSetupInFlight = false;

function ensureWhatsAppSetup() {
  if (whatsappSetupDone || whatsappSetupInFlight) return;
  whatsappSetupInFlight = true;

  runOpenclawAsync(['config', 'set', 'channels.whatsapp.enabled', 'true', '--strict-json'], (err) => {
    whatsappSetupInFlight = false;
    if (err) {
      console.error('[whatsapp] ensureWhatsAppSetup error:', err.message);
      return;
    }

    whatsappSetupDone = true;
    console.log('[whatsapp] ensureWhatsAppSetup applied');
  }, {
    allowFailure: true,
    timeout: 20_000,
  });
}

function syncWhatsAppAuthToOpenclaw(authDir = WHATSAPP_TEMP_AUTH_DIR, options = {}) {
  if ((!options.force && whatsappAuthSyncInFlight) || !fs.existsSync(authDir)) return false;
  whatsappAuthSyncInFlight = true;

  try {
    for (const ocAuth of getWhatsAppAuthDirs()) {
      runProcess('sudo', ['-u', 'openclaw', 'mkdir', '-p', ocAuth], { allowFailure: true });
      runProcess('sudo', ['-u', 'openclaw', 'cp', '-r', `${authDir}/.`, ocAuth], { allowFailure: true });
      runProcess('chown', ['-R', 'openclaw:openclaw', ocAuth], { allowFailure: true });
    }
    whatsappAuthSyncedAt = Date.now();
    return true;
  } catch (err) {
    console.error('[whatsapp-login] auth sync error:', err.message);
    return false;
  } finally {
    whatsappAuthSyncInFlight = false;
  }
}

function restartOpenclawAfterPairing(authDir = WHATSAPP_TEMP_AUTH_DIR, reason = 'pairing_restart_required') {
  setTimeout(() => {
    const synced = syncWhatsAppAuthToOpenclaw(authDir, { force: true });
    if (!synced) {
      console.warn('[whatsapp-login] skipped restart because auth sync did not complete:', reason);
      return;
    }

    console.log('[whatsapp-login] restarting openclaw after pairing:', reason);
    invalidateGatewayHealthCache();
    whatsappPairingRestartAt = Date.now();
    runSystemctlAsync(['restart', 'openclaw'], (restartErr) => {
      if (restartErr) console.error('[whatsapp-login] restart after pairing failed:', restartErr.message);
    });
  }, 300);
}

function scheduleWhatsAppAuthSync(authDir = WHATSAPP_TEMP_AUTH_DIR, delayMs = 400) {
  if (whatsappAuthSyncTimer) {
    clearTimeout(whatsappAuthSyncTimer);
  }
  whatsappAuthSyncTimer = setTimeout(() => {
    whatsappAuthSyncTimer = null;
    syncWhatsAppAuthToOpenclaw(authDir);
  }, delayMs);
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
  const authDir = WHATSAPP_TEMP_AUTH_DIR;
  try {
    fs.mkdirSync(authDir, { recursive: true });
    execSync(`find '${authDir}' -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true`, { timeout: 5000 });
    if (!whatsappForceFreshLogin) {
      // Copy existing OpenClaw auth if available (so we don't re-link)
      for (const openclawAuth of getWhatsAppAuthDirs()) {
        execSync(`cp -rn '${openclawAuth}'/* '${authDir}/' 2>/dev/null || true`, { timeout: 5000 });
      }
    } else {
      console.log('[whatsapp] skipping stale auth seed after previous 401');
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

    sock.ev.on('creds.update', () => {
      Promise.resolve(saveCreds()).catch((err) => {
        console.error('[whatsapp-login] saveCreds error:', err.message);
      });
      scheduleWhatsAppAuthSync(authDir);
    });

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
        whatsappForceFreshLogin = false;
        whatsappLinkedAt = Date.now();
        watchdogState.consecutive_channel_failures = 0;
        syncWhatsAppAuthToOpenclaw(authDir);
        whatsappPairingRestartAt = Date.now();
        runSystemctlAsync(['restart', 'openclaw'], (restartErr) => {
          if (restartErr) console.error('[whatsapp-login] restart after auth sync failed:', restartErr.message);
        });
        invalidateGatewayHealthCache();
        cleanupWhatsAppSocket();
      }
      if (connection === 'close') {
        const err = lastDisconnect?.error;
        const code = err?.output?.statusCode;
        console.log('[whatsapp-login] connection closed, code:', code, 'error:', err?.message || err);
        if (code === 401) {
          whatsappForceFreshLogin = true;
        }
        if (code === 515) {
          restartOpenclawAfterPairing(authDir, 'stream_error_515');
        } else if (code === 428 && whatsappAuthSyncedAt && (Date.now() - whatsappAuthSyncedAt) < 15_000) {
          restartOpenclawAfterPairing(authDir, 'connection_terminated_after_auth_sync');
        }
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

function resetWhatsAppRelinkState() {
  cleanupWhatsAppSocket();
  if (whatsappAuthSyncTimer) {
    clearTimeout(whatsappAuthSyncTimer);
    whatsappAuthSyncTimer = null;
  }

  whatsappRawQR = null;
  whatsappQRTimestamp = 0;
  whatsappLinkedAt = 0;
  whatsappForceFreshLogin = true;
  whatsappAuthSyncInFlight = false;
  whatsappAuthSyncedAt = 0;
  whatsappPairingRestartAt = 0;
  try {
    fs.rmSync(WHATSAPP_TEMP_AUTH_DIR, { recursive: true, force: true });
  } catch { /* ignore */ }
}

async function triggerWhatsAppRelink() {
  removeWhatsAppAuthState();
  resetWhatsAppRelinkState();
  ensureWhatsAppSetup();
  await startWhatsAppLogin();
  const nowIso = new Date().toISOString();
  watchdogState.last_run_at = nowIso;
  watchdogState.last_qr_bootstrap_at = nowIso;
  watchdogState.last_reason = 'whatsapp_manual_relink';
  watchdogState.last_result = 'started_qr_recovery';
  watchdogState.last_error = null;
  watchdogState.consecutive_channel_failures = 0;
  return watchdogState;
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
  const rawQRAge = whatsappQRTimestamp ? Date.now() - whatsappQRTimestamp : Infinity;
  const hasFreshRawQR = Boolean(whatsappRawQR && rawQRAge < WHATSAPP_QR_MAX_AGE_MS);
  const hadStaleRawQR = Boolean(whatsappRawQR && rawQRAge >= WHATSAPP_QR_MAX_AGE_MS);

  if (hasFreshRawQR) {
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

  if (hadStaleRawQR) {
    console.log('[qr] stale QR expired after', rawQRAge, 'ms; restarting login flow');
    whatsappRawQR = null;
    whatsappQRTimestamp = 0;
    cleanupWhatsAppSocket();
  }

  const logs = getJournalLogsSinceLastStart(200);
  const linkedRecently = whatsappLinkedAt && (Date.now() - whatsappLinkedAt < 30_000);
  if (linkedRecently || isWhatsAppConnected(isRunning, logs)) {
    if (whatsappLoginProcess && !whatsappLoginProcess.killed) {
      cleanupWhatsAppSocket();
    }
    return res.json({ connected: true, qr: null });
  }

  if (isRunning) {
    const linkedViaRPC = isWhatsAppLinkedViaRPC();
    if (linkedViaRPC) {
      if (whatsappLoginProcess && !whatsappLoginProcess.killed) {
        cleanupWhatsAppSocket();
      }
      return res.json({ connected: true, qr: null });
    }
  }

  // ── Fallback: try to extract QR data from logs ──────────────────────────────
  if (!hadStaleRawQR) {
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
        runOpenclaw(['config', 'set', 'env.OPENROUTER_API_KEY', sanitizeEnvValue(openrouter_key)]);
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
        runOpenclaw(['models', 'set', openclawModel]);
        console.log(`[configure] set OpenClaw model to ${openclawModel}`);
      } catch (err) {
        console.error('[configure] openclaw models set failed:', err.message);
      }
    }
    if (openai_token) envUpdates.OPENAI_ACCESS_TOKEN = openai_token;
    if (timezone) envUpdates.TZ = timezone;
    if (Object.keys(envUpdates).length > 0) writeEnvFile(envUpdates);

    runSystemctlAsync(['restart', 'openclaw'], (restartErr) => {
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
  invalidateGatewayHealthCache();
  restartingTimer = setTimeout(() => {
    console.error('[vps-agent] restart lock timed out — force-releasing');
    isRestarting = false;
    restartingTimer = null;
  }, LOCK_TIMEOUT_MS);

  const previous_status = getOpenclawStatus();

  runSystemctlAsync(['restart', 'openclaw'], (err) => {
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
    const publicIp = getPublicIpv4();

    // Read gateway token from OpenClaw config (files owned by openclaw user, read via sudo)
    let gatewayToken = '';
    let preferredOrigin = '';
    for (const cfgPath of OPENCLAW_CONFIG_PATHS) {
      try {
        const raw = runCmd(`sudo -u openclaw /usr/bin/cat '${cfgPath}' 2>/dev/null`);
        const config = JSON.parse(raw);
        if (config?.gateway?.auth?.token) {
          gatewayToken = config.gateway.auth.token;
        }
        const allowedOrigins = Array.isArray(config?.gateway?.controlUi?.allowedOrigins)
          ? config.gateway.controlUi.allowedOrigins
          : [];
        const httpsOrigin = allowedOrigins.find((origin) => typeof origin === 'string' && origin.startsWith('https://'));
        if (typeof httpsOrigin === 'string' && httpsOrigin.length > 0) {
          preferredOrigin = httpsOrigin;
        }
        if (gatewayToken && preferredOrigin) break;
      } catch { /* try next */ }
    }

    // OpenClaw gateway listens on port 18789 by default
    const gatewayPort = 18789;

    // Check if gateway port is responding (--bind lan may not listen on localhost)
    let available = false;
    const gatewayHost = getGatewayHost();
    try {
      runProcess('nc', ['-z', '-w2', gatewayHost, String(gatewayPort)]);
      available = true;
    } catch {
      try {
        // Fallback: check on public IP (openclaw --bind lan listens there)
        if (publicIp && publicIp !== 'localhost') {
          runProcess('nc', ['-z', '-w2', publicIp, String(gatewayPort)]);
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
    const baseOrigin = preferredOrigin || `https://${sslipDomain}`;
    const baseUrl = baseOrigin.endsWith('/') ? baseOrigin : `${baseOrigin}/`;
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
    const approved = approvePendingDevicePairings({
      clientModes: ['webchat'],
      clientIds: ['openclaw-control-ui'],
    });
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
    const gatewayHealth = getOpenclawStatus() === 'running'
      ? readGatewayHealth()
      : null;
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
        stabilizing: snapshot.whatsapp.stabilizing,
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

app.get('/diagnostics', auth, (req, res) => {
  try {
    res.json(buildDiagnosticsPayload());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/self-heal', auth, async (req, res) => {
  try {
    const result = await runWatchdogCycle('manual');
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/channels/whatsapp/relink', auth, async (req, res) => {
  try {
    const watchdog = await triggerWhatsAppRelink();
    res.json({
      success: true,
      watchdog,
      relink_started: true,
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
      setOpenclawJsonString('channels.telegram.botToken', sanitizeEnvValue(token));
      setOpenclawJsonValue('channels.telegram.enabled', true);
    } catch (err) {
      console.warn('[telegram] OpenClaw CLI config warning:', err.message);
    }

    // Also write to .env as fallback
    writeEnvFile({ TELEGRAM_BOT_TOKEN: token });

    runSystemctlAsync(['restart', 'openclaw'], (err) => {
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
      setOpenclawJsonString('channels.discord.token', sanitizeEnvValue(token));
      setOpenclawJsonValue('channels.discord.enabled', true);
    } catch (err) {
      console.warn('[discord] OpenClaw CLI config warning:', err.message);
    }

    // Also write to .env and config as fallback
    writeEnvFile({ DISCORD_BOT_TOKEN: token });
    if (guild_id) writeConfig({ discord_guild_id: guild_id });

    runSystemctlAsync(['restart', 'openclaw'], (err) => {
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
      removeWhatsAppAuthState();
      runSystemctlAsync(['restart', 'openclaw'], (err) => {
        if (err) console.error('[vps-agent] restart after whatsapp disconnect failed:', err.message);
      });
      return;
    } else {
      // Disable channel via OpenClaw config
      try {
        setOpenclawJsonValue(`channels.${channel}.enabled`, false);
      } catch { /* ignore */ }

      const env = readEnvFile();
      delete env[envKeyMap[channel]];
      const content = Object.entries(env).map(([k, v]) => `${k}=${sanitizeEnvValue(v)}`).join('\n') + '\n';
      fs.writeFileSync(OPENCLAW_ENV_FILE, content, 'utf8');
      try { runCmd(`chown -R openclaw:openclaw ${OPENCLAW_CONFIG_DIR}`); } catch { /* ignore */ }

      runSystemctlAsync(['restart', 'openclaw'], (err) => {
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
    runSystemctlAsync(['stop', 'openclaw'], (err) => {
      if (err) console.error('[credit-guard] failed to stop openclaw:', err.message);
      else console.log('[credit-guard] openclaw stopped — credits exhausted');
    });
  } else if (blocked === false && creditBlocked) {
    creditBlocked = false;
    runSystemctlAsync(['start', 'openclaw'], (err) => {
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
    runProcess('sudo', ['-u', 'openclaw', 'mkdir', '-p', credDir]);

    const oauthPath = path.join(credDir, 'oauth.json');
    runProcess('sudo', ['-u', 'openclaw', 'tee', oauthPath], { input: JSON.stringify(oauth_data) });
    runProcess('sudo', ['-u', 'openclaw', 'chmod', '600', oauthPath]);

    // Update config to use openai-codex model
    writeConfig({ model: 'openai-codex/gpt-5.4', ai_mode: 'chatgpt' });

    // Restart OpenClaw to pick up new auth
    runSystemctlAsync(['restart', 'openclaw'], (err) => {
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
