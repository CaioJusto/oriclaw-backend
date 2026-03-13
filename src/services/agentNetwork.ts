import https from 'https';
import { OriClawInstance } from '../types';
import { getDroplet, getDropletPrivateIP, getDropletPublicIP } from './digitalocean';
import { updateInstance } from './supabase';

export const agentHttpsAgent = new https.Agent({ rejectUnauthorized: false });
export const AGENT_PORT = 8080;
export const AGENT_PRIVATE_CIDR = process.env.ORICLAW_AGENT_PRIVATE_CIDR || '10.116.0.0/20';

type AgentInstanceLike = Pick<OriClawInstance, 'id' | 'droplet_id' | 'droplet_ip' | 'metadata'>;

type AgentIpMetadata = {
  agent_private_ip?: unknown;
  agent_public_ip?: unknown;
};

function asIp(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function getMetadata(instance: Pick<OriClawInstance, 'metadata'>): AgentIpMetadata {
  return ((instance.metadata ?? {}) as AgentIpMetadata);
}

function getCachedPrivateIp(instance: Pick<OriClawInstance, 'metadata'>): string | null {
  return asIp(getMetadata(instance).agent_private_ip);
}

function getCachedPublicIp(instance: Pick<OriClawInstance, 'droplet_ip' | 'metadata'>): string | null {
  return asIp(getMetadata(instance).agent_public_ip) ?? asIp(instance.droplet_ip);
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
  const host = await resolveAgentHost(instance);
  return host ? `https://${host}:${AGENT_PORT}` : null;
}

export async function resolveAgentHosts(instance: AgentInstanceLike): Promise<string[]> {
  const cachedPrivateIp = getCachedPrivateIp(instance);
  const cachedPublicIp = getCachedPublicIp(instance);
  const hosts = new Set<string>();

  if (cachedPrivateIp) hosts.add(cachedPrivateIp);
  if (cachedPublicIp) hosts.add(cachedPublicIp);

  if (hosts.size > 0) {
    return Array.from(hosts);
  }

  const baseUrl = await resolveAgentBaseUrl(instance);
  if (!baseUrl) return [];

  return [baseUrl.replace(/^https:\/\//, '').replace(/:\d+$/, '')];
}
