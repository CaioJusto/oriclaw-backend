#!/usr/bin/env node

import axios from 'axios';
import https from 'https';
import { spawn } from 'child_process';

const insecureHttps = new https.Agent({ rejectUnauthorized: false });

const command = process.argv[2] || 'help';
const flags = new Set(process.argv.slice(3));

const agentHost = process.env.ORICLAW_AGENT_HOST || process.env.AGENT_HOST || '';
const agentSecret = process.env.ORICLAW_AGENT_SECRET || process.env.AGENT_SECRET || '';
const sshHost = process.env.ORICLAW_SSH_HOST || process.env.AGENT_HOST || '';
const sshUser = process.env.ORICLAW_SSH_USER || 'root';
const sshPort = process.env.ORICLAW_SSH_PORT || '22';
const sshKeyPath = process.env.ORICLAW_SSH_KEY_PATH || '';

function usage() {
  console.log(`OpenClaw ops automation

Usage:
  npm run ops:openclaw -- <command> [--json] [--force]

Commands:
  status             Lê /health, /health/detailed, /channels e /watchdog do vps-agent
  self-heal          Dispara POST /self-heal no vps-agent
  doctor             Executa openclaw health/doctor/channels via SSH e resume memória/systemd
  channels           Executa openclaw channels list/status via SSH
  logs               Lê os últimos logs do openclaw via SSH
  whatsapp-relink    Limpa auth do WhatsApp, reinicia serviços e dispara self-heal

Environment:
  ORICLAW_AGENT_HOST or AGENT_HOST           Host/IP do vps-agent
  ORICLAW_AGENT_SECRET or AGENT_SECRET       Secret do vps-agent
  ORICLAW_SSH_HOST or AGENT_HOST             Host/IP SSH da VPS
  ORICLAW_SSH_USER                           Default: root
  ORICLAW_SSH_PORT                           Default: 22
  ORICLAW_SSH_KEY_PATH                       Caminho opcional da chave SSH

Examples:
  npm run ops:openclaw:status
  npm run ops:openclaw:doctor
  npm run ops:openclaw -- logs
  npm run ops:openclaw -- whatsapp-relink --force
`);
}

function requireAgentConfig() {
  if (!agentHost || !agentSecret) {
    throw new Error('Configure ORICLAW_AGENT_HOST/AGENT_HOST e ORICLAW_AGENT_SECRET/AGENT_SECRET.');
  }
}

function requireSshConfig() {
  if (!sshHost) {
    throw new Error('Configure ORICLAW_SSH_HOST ou AGENT_HOST para usar os comandos via SSH.');
  }
}

function normalizeBaseUrl(rawUrl) {
  return rawUrl.replace(/\/+$/, '');
}

function agentBaseUrl() {
  requireAgentConfig();
  return normalizeBaseUrl(`https://${agentHost}:8080`);
}

async function agentRequest(path, options = {}) {
  const response = await axios({
    url: `${agentBaseUrl()}${path}`,
    headers: {
      'x-agent-secret': agentSecret,
      ...(options.headers || {}),
    },
    httpsAgent: insecureHttps,
    validateStatus: () => true,
    timeout: 15_000,
    ...options,
  });

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`${path} returned HTTP ${response.status}: ${JSON.stringify(response.data)}`);
  }

  return response.data;
}

function sshArgs(remoteCommand) {
  const args = [
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=10',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-p', String(sshPort),
  ];

  if (sshKeyPath) {
    args.push('-i', sshKeyPath);
  }

  args.push(`${sshUser}@${sshHost}`, 'bash', '-lc', remoteCommand);
  return args;
}

async function sshRun(remoteCommand) {
  requireSshConfig();

  const args = sshArgs(remoteCommand);

  return await new Promise((resolve, reject) => {
    const child = spawn('ssh', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }

      reject(new Error(stderr.trim() || `SSH command failed with exit code ${code}`));
    });
  });
}

function printSection(title, body) {
  console.log(`\n### ${title}\n${body.trim() || '(empty)'}`);
}

async function runStatus() {
  const [health, detailed, channels, watchdog] = await Promise.all([
    agentRequest('/health'),
    agentRequest('/health/detailed'),
    agentRequest('/channels'),
    agentRequest('/watchdog'),
  ]);

  if (flags.has('--json')) {
    console.log(JSON.stringify({ health, detailed, channels, watchdog }, null, 2));
    return;
  }

  const summary = {
    agent_status: health.status,
    openclaw: detailed.openclaw,
    restart_count: detailed.restart_count,
    uptime: detailed.uptime,
    degraded_channels: detailed.degraded_channels || [],
    whatsapp: channels.whatsapp,
    telegram: channels.telegram,
    discord: channels.discord,
    watchdog: {
      last_reason: watchdog.last_reason || null,
      last_result: watchdog.last_result || null,
      last_check_at: watchdog.last_check_at || null,
      last_qr_bootstrap_at: watchdog.last_qr_bootstrap_at || null,
    },
  };

  console.log(JSON.stringify(summary, null, 2));
}

async function runSelfHeal() {
  const result = await agentRequest('/self-heal', { method: 'POST' });
  console.log(JSON.stringify(result, null, 2));
}

async function runDoctor() {
  const remoteCommand = [
    'set -e',
    'printf "timestamp=%s\\n" "$(date -Iseconds)"',
    'printf "host=%s\\n" "$(hostname)"',
    'printf "user=%s\\n" "$(whoami)"',
    'echo',
    'echo "== openclaw health =="',
    'openclaw health || true',
    'echo',
    'echo "== openclaw doctor =="',
    'openclaw doctor || true',
    'echo',
    'echo "== openclaw channels list =="',
    'openclaw channels list || true',
    'echo',
    'echo "== openclaw channels status =="',
    '(openclaw channels status --probe || openclaw channels status || true)',
    'echo',
    'echo "== systemctl is-active openclaw =="',
    'systemctl is-active openclaw || true',
    'echo',
    'echo "== memory =="',
    'free -h || true',
    'echo',
    'echo "== swap =="',
    'swapon --show || true',
  ].join('; ');

  const { stdout } = await sshRun(remoteCommand);
  console.log(stdout.trim());
}

async function runChannels() {
  const remoteCommand = [
    'set -e',
    'echo "== openclaw channels list =="',
    'openclaw channels list || true',
    'echo',
    'echo "== openclaw channels status =="',
    '(openclaw channels status --probe || openclaw channels status || true)',
    'echo',
    'echo "== openclaw channels capabilities =="',
    'openclaw channels capabilities || true',
  ].join('; ');

  const { stdout } = await sshRun(remoteCommand);
  console.log(stdout.trim());
}

async function runLogs() {
  const remoteCommand = 'journalctl -u openclaw -n 80 --no-pager --output=short-iso || true';
  const { stdout } = await sshRun(remoteCommand);
  console.log(stdout.trim());
}

async function runWhatsAppRelink() {
  if (!flags.has('--force')) {
    throw new Error('whatsapp-relink é destrutivo. Rode novamente com --force.');
  }

  const remoteCommand = [
    'set -e',
    "rm -rf /tmp/oriclaw-wa-auth",
    "rm -rf /home/openclaw/.openclaw/credentials/whatsapp/default",
    "rm -rf /home/openclaw/.openclaw/.openclaw/channels/whatsapp/default/auth",
    "rm -rf /home/openclaw/.openclaw/channels/whatsapp/default/auth",
    "mkdir -p /home/openclaw/.openclaw/credentials/whatsapp",
    "mkdir -p /home/openclaw/.openclaw/channels/whatsapp/default",
    "mkdir -p /home/openclaw/.openclaw/.openclaw/channels/whatsapp/default",
    "chown -R openclaw:openclaw /home/openclaw/.openclaw",
    'systemctl restart openclaw',
    'systemctl restart oriclaw-agent',
    'systemctl is-active openclaw',
    'systemctl is-active oriclaw-agent',
  ].join('; ');

  const { stdout } = await sshRun(remoteCommand);
  printSection('SSH reset', stdout);

  try {
    const heal = await agentRequest('/self-heal', { method: 'POST' });
    printSection('Agent self-heal', JSON.stringify(heal, null, 2));
  } catch (error) {
    printSection('Agent self-heal', error instanceof Error ? error.message : String(error));
  }

  try {
    const qr = await agentRequest('/qr');
    printSection('QR bootstrap', JSON.stringify({
      connected: qr.connected,
      generated_at: qr.generated_at || null,
      has_qr: Boolean(qr.qr),
    }, null, 2));
  } catch (error) {
    printSection('QR bootstrap', error instanceof Error ? error.message : String(error));
  }
}

async function main() {
  switch (command) {
    case 'status':
      await runStatus();
      return;
    case 'self-heal':
      await runSelfHeal();
      return;
    case 'doctor':
      await runDoctor();
      return;
    case 'channels':
      await runChannels();
      return;
    case 'logs':
      await runLogs();
      return;
    case 'whatsapp-relink':
      await runWhatsAppRelink();
      return;
    case 'help':
    case '--help':
    case '-h':
      usage();
      return;
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
