import https from 'https';
import { TLSSocket } from 'tls';
import { OriClawInstance } from '../types';
import { getDroplet, getDropletPrivateIP, getDropletPublicIP } from './digitalocean';
import { updateInstance } from './supabase';
import {
  buildPinnedAgentHttpsAgent,
  getTlsMaterialFromCertPem,
  normalizeFingerprint256,
} from './agentTls';

export const AGENT_PORT = 8080;
export const AGENT_PRIVATE_CIDR = process.env.ORICLAW_AGENT_PRIVATE_CIDR || '10.116.0.0/20';
const AGENT_PROBE_TIMEOUT_MS = 2_500;
const RECENT_SUCCESS_TTL_MS = 5 * 60 * 1000;

type AgentInstanceLike = Pick<OriClawInstance, 'id' | 'droplet_id' | 'droplet_ip' | 'metadata'>;

type AgentMetadata = {
  agent_private_ip?: unknown;
  agent_public_ip?: unknown;
  agent_tls_cert_pem?: unknown;
  agent_tls_fingerprint256?: unknown;
};

type AgentPinnedTls = {
  certPem: string;
  fingerprint256: string;
};

export type AgentTransport = {
  baseUrl: string;
  httpsAgent: https.Agent;
};

const lastSuccessfulHostByInstance = new Map<string, { host: string; verifiedAt: number }>();

function asIp(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function asPem(value: unknown): string | null {
  return typeof value === 'string' && value.includes('BEGIN CERTIFICATE') ? value : null;
}

function getMetadata(instance: Pick<OriClawInstance, 'metadata'>): AgentMetadata {
  return (instance.metadata ?? {}) as AgentMetadata;
}

function getCachedPrivateIp(instance: Pick<OriClawInstance, 'metadata'>): string | null {
  return asIp(getMetadata(instance).agent_private_ip);
}

function getCachedPublicIp(instance: Pick<OriClawInstance, 'droplet_ip' | 'metadata'>): string | null {
  return asIp(getMetadata(instance).agent_public_ip) ?? asIp(instance.droplet_ip);
}

function getPinnedTls(instance: Pick<OriClawInstance, 'metadata'>): AgentPinnedTls | null {
  const metadata = getMetadata(instance);
  const certPem = asPem(metadata.agent_tls_cert_pem);
  const fingerprint256 = normalizeFingerprint256(
    typeof metadata.agent_tls_fingerprint256 === 'string' ? metadata.agent_tls_fingerprint256 : null
  );

  if (!certPem || !fingerprint256) {
    return null;
  }

  return { certPem, fingerprint256 };
}

async function refreshAgentIps(instance: AgentInstanceLike): Promise<{ privateIp: string | null; publicIp: string | null }> {
  if (!instance.droplet_id) {
    return {
      privateIp: getCachedPrivateIp(instance),
      publicIp: getCachedPublicIp(instance),
    };
  }

  const droplet = await getDroplet(instance.droplet_id);
  const privateIp = getDropletPrivateIP(droplet);
  const publicIp = getDropletPublicIP(droplet);
  const metadata = (instance.metadata ?? {}) as Record<string, unknown>;

  const metadataNeedsUpdate =
    privateIp !== asIp(metadata.agent_private_ip) ||
    publicIp !== asIp(metadata.agent_public_ip) ||
    publicIp !== instance.droplet_ip;

  if (metadataNeedsUpdate) {
    await updateInstance(instance.id, {
      droplet_ip: publicIp ?? instance.droplet_ip,
      metadata: {
        ...metadata,
        agent_private_ip: privateIp,
        agent_public_ip: publicIp ?? instance.droplet_ip,
      },
    });
  }

  return { privateIp, publicIp };
}

export async function resolveAgentHost(instance: AgentInstanceLike): Promise<string | null> {
  const cachedPrivateIp = getCachedPrivateIp(instance);
  if (cachedPrivateIp) return cachedPrivateIp;

  const cachedPublicIp = getCachedPublicIp(instance);
  if (!instance.droplet_id) return cachedPublicIp;

  try {
    const { privateIp, publicIp } = await refreshAgentIps(instance);
    return privateIp ?? publicIp ?? cachedPublicIp;
  } catch {
    return cachedPublicIp;
  }
}

export async function resolveAgentBaseUrl(instance: AgentInstanceLike): Promise<string | null> {
  const host = (await resolveAgentHosts(instance))[0] ?? null;
  return host ? `https://${host}:${AGENT_PORT}` : null;
}

export async function resolveAgentHosts(instance: AgentInstanceLike): Promise<string[]> {
  const hosts = new Set<string>();
  const cachedPrivateIp = getCachedPrivateIp(instance);
  const cachedPublicIp = getCachedPublicIp(instance);

  if (cachedPrivateIp) hosts.add(cachedPrivateIp);
  if (cachedPublicIp) hosts.add(cachedPublicIp);

  if (instance.droplet_id) {
    try {
      const { privateIp, publicIp } = await refreshAgentIps(instance);
      if (privateIp) hosts.add(privateIp);
      if (publicIp) hosts.add(publicIp);
    } catch {
      /* ignore refresh failures and fall back to cached IPs */
    }
  }

  return Array.from(hosts);
}

function pemFromRawCert(raw: Buffer): string {
  const base64 = raw.toString('base64');
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

async function fetchPinnedTlsFromHost(host: string, agentSecret: string): Promise<AgentPinnedTls> {
  return await new Promise<AgentPinnedTls>((resolve, reject) => {
    const req = https.request(
      {
        host,
        port: AGENT_PORT,
        path: '/health',
        method: 'GET',
        headers: { 'x-agent-secret': agentSecret },
        rejectUnauthorized: false,
        timeout: 5_000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`Agent TLS bootstrap returned status ${res.statusCode}`));
          return;
        }

        const socket = res.socket as TLSSocket;
        const peer = socket.getPeerCertificate(true);
        if (!peer || !peer.raw) {
          res.resume();
          reject(new Error('Agent TLS certificate missing from peer response'));
          return;
        }

        const certPem = pemFromRawCert(peer.raw);
        const tls = getTlsMaterialFromCertPem(certPem);
        res.resume();
        res.on('end', () => resolve({ certPem: tls.certPem, fingerprint256: tls.fingerprint256 }));
      }
    );

    req.on('timeout', () => req.destroy(new Error('Agent TLS bootstrap timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function bootstrapPinnedTls(instance: AgentInstanceLike, agentSecret: string): Promise<AgentPinnedTls> {
  const hosts = await resolveAgentHosts(instance);
  let lastError: Error | null = null;

  for (const host of hosts) {
    try {
      const tls = await fetchPinnedTlsFromHost(host, agentSecret);
      await updateInstance(instance.id, {
        metadata: {
          agent_tls_cert_pem: tls.certPem,
          agent_tls_fingerprint256: tls.fingerprint256,
        },
      });
      return tls;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }

  throw lastError ?? new Error('Unable to bootstrap pinned TLS for agent');
}

function createAgentTransport(host: string, tls: AgentPinnedTls): AgentTransport {
  return {
    baseUrl: `https://${host}:${AGENT_PORT}`,
    httpsAgent: buildPinnedAgentHttpsAgent(tls.certPem, tls.fingerprint256),
  };
}

function orderHosts(instanceId: string, hosts: string[]): string[] {
  const cached = lastSuccessfulHostByInstance.get(instanceId);
  if (!cached) return hosts;

  if ((Date.now() - cached.verifiedAt) > RECENT_SUCCESS_TTL_MS) {
    lastSuccessfulHostByInstance.delete(instanceId);
    return hosts;
  }

  return hosts.slice().sort((a, b) => {
    if (a === cached.host) return -1;
    if (b === cached.host) return 1;
    return 0;
  });
}

async function verifyAgentTransport(transport: AgentTransport, agentSecret: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = https.request(
      {
        host: new URL(transport.baseUrl).hostname,
        port: AGENT_PORT,
        path: '/health',
        method: 'GET',
        headers: { 'x-agent-secret': agentSecret },
        agent: transport.httpsAgent,
        timeout: AGENT_PROBE_TIMEOUT_MS,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`Agent transport probe returned status ${res.statusCode}`));
          return;
        }

        res.resume();
        res.on('end', () => resolve());
      }
    );

    req.on('timeout', () => req.destroy(new Error('Agent transport probe timed out')));
    req.on('error', reject);
    req.end();
  });
}

export async function resolveAgentTransport(
  instance: AgentInstanceLike,
  agentSecret: string
): Promise<AgentTransport | null> {
  const hosts = orderHosts(instance.id, await resolveAgentHosts(instance));
  if (hosts.length === 0) return null;
  const tls = getPinnedTls(instance) ?? await bootstrapPinnedTls(instance, agentSecret);
  let lastError: Error | null = null;

  for (const host of hosts) {
    const transport = createAgentTransport(host, tls);
    try {
      await verifyAgentTransport(transport, agentSecret);
      lastSuccessfulHostByInstance.set(instance.id, { host, verifiedAt: Date.now() });
      return transport;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }

  throw lastError ?? new Error('Unable to reach agent on any known host');
}
