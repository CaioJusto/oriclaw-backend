import crypto from 'crypto';
import axios from 'axios';
import { createDroplet, deleteDroplet, getDroplet, getDropletPublicIP } from './digitalocean';
import {
  createInstance,
  getInstanceById,
  getInstanceBySubscriptionId,
  updateInstance,
} from './supabase';
import { CLOUD_INIT_SCRIPT } from './cloudInit';
import { ProvisionRequest, DODroplet, DODropletResponse } from '../types';
import { encrypt, decrypt } from './crypto';

export async function provisionInstance(
  req: ProvisionRequest
): Promise<{ instance_id: string; status: string }> {
  console.log(`[provision] Starting for customer: ${req.customer_id}`);

  // Generate random agent secret for this instance
  const agentSecret = crypto.randomBytes(32).toString('hex');

  // Create DB record first
  const instance = await createInstance({
    customer_id: req.customer_id,
    email: req.email,
    plan: req.plan,
    droplet_id: null,
    droplet_ip: null,
    status: 'provisioning',
    stripe_subscription_id: req.stripe_subscription_id ?? null,
    api_key_encrypted: req.api_key_anthropic ? encrypt(req.api_key_anthropic) : null,
    metadata: { agent_secret: agentSecret },
  });

  // Create DO Droplet (non-blocking — status will update async)
  createDropletAsync(instance.id, req.customer_id, agentSecret).catch((err) => {
    console.error(`[provision] Droplet creation failed for ${instance.id}:`, err.message);
    updateInstance(instance.id, { status: 'suspended', metadata: { error: err.message } }).catch(
      console.error
    );
  });

  return { instance_id: instance.id, status: 'provisioning' };
}

async function createDropletAsync(
  instanceId: string,
  customerId: string,
  agentSecret: string
): Promise<void> {
  // Inject agent secret into cloud-init
  const cloudInit = CLOUD_INIT_SCRIPT.replace(/__AGENT_SECRET__/g, agentSecret);

  const droplet = await createDropletWithInit(customerId, cloudInit);
  console.log(`[provision] Droplet created: ${droplet.id} for instance ${instanceId}`);

  await updateInstance(instanceId, {
    droplet_id: droplet.id,
    metadata: { droplet_name: droplet.name, agent_secret: agentSecret },
  });

  // Poll for droplet IP (up to 3 minutes)
  let ip: string | null = null;
  for (let i = 0; i < 18; i++) {
    await sleep(10_000);
    const updated = await getDroplet(droplet.id);
    ip = getDropletPublicIP(updated);
    if (ip) break;
  }

  if (!ip) {
    await updateInstance(instanceId, {
      status: 'suspended',
      metadata: {
        droplet_name: droplet.name,
        agent_secret: agentSecret,
        error: 'Droplet não obteve IP em tempo hábil',
      },
    });
    return;
  }

  // Wait until VPS agent is responding on /health before exposing needs_config.
  const agentReady = await waitForAgentReadiness(ip, agentSecret, 20 * 60 * 1000);
  if (!agentReady) {
    await updateInstance(instanceId, {
      droplet_ip: ip,
      status: 'suspended',
      metadata: {
        droplet_name: droplet.name,
        agent_secret: agentSecret,
        error: 'VPS agent não respondeu após 20 minutos',
      },
    });
    return;
  }

  await updateInstance(instanceId, {
    droplet_ip: ip,
    status: 'needs_config',
    metadata: { droplet_name: droplet.name, agent_secret: agentSecret },
  });

  console.log(`[provision] Instance ${instanceId} ready for config at ${ip}`);
}

export async function deprovisionInstance(subscriptionId: string): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) {
    console.warn(`[deprovision] No instance found for subscription: ${subscriptionId}`);
    return;
  }

  if (instance.droplet_id) {
    try {
      await deleteDroplet(instance.droplet_id);
      console.log(`[deprovision] Droplet ${instance.droplet_id} deleted`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[deprovision] Failed to delete droplet: ${msg}`);
      await updateInstance(instance.id, {
        status: 'deletion_failed',
        metadata: { ...(instance.metadata ?? {}), error: msg },
      });
      return;
    }
  }

  await updateInstance(instance.id, { status: 'deleted' });
}

export async function suspendInstance(subscriptionId: string): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) return;
  await updateInstance(instance.id, { status: 'suspended' });
}

export async function reactivateInstance(subscriptionId: string): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) {
    console.log(`[reactivate] No instance found for subscription: ${subscriptionId}`);
    return;
  }
  if (instance.status === 'suspended') {
    // Não reativar se a VPS nunca chegou a ter IP (falha de provisionamento)
    const meta = instance.metadata as Record<string, unknown> | null;
    const provisioningFailed = meta?.error && !instance.droplet_ip;
    if (provisioningFailed) {
      console.warn(`[reactivate] Instance ${instance.id} was suspended due to provisioning failure — not reactivating automatically`);
      // Manter suspended — o suporte precisará intervir ou re-provisionar
      return;
    }
    await updateInstance(instance.id, {
      status: 'running',
      metadata: { ...(meta ?? {}), reactivated_at: new Date().toISOString(), error: undefined },
    });
    console.log(`[reactivate] Instance ${instance.id} reactivated`);
  }
}

export async function updateApiKey(instanceId: string, apiKey: string): Promise<void> {
  await updateInstance(instanceId, { api_key_encrypted: encrypt(apiKey) });
  console.log(`[updateApiKey] Stored new encrypted API key for instance ${instanceId} (configure via /proxy)`);
}

export { decrypt };

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForAgentReadiness(
  ip: string,
  agentSecret: string,
  maxWaitMs: number
): Promise<boolean> {
  const deadline = Date.now() + maxWaitMs;

  while (Date.now() < deadline) {
    try {
      const response = await axios.get(`http://${ip}:8080/health`, {
        headers: { 'x-agent-secret': agentSecret },
        timeout: 2_000,
      });

      if (response.status === 200) {
        return true;
      }
    } catch {
      // keep retrying until timeout
    }

    await sleep(5_000);
  }

  return false;
}

// ── Internal: create droplet with custom cloud-init ──────────────────────────
const DO_API_BASE = 'https://api.digitalocean.com/v2';

function getHeaders() {
  return {
    Authorization: `Bearer ${process.env.DO_API_TOKEN}`,
    'Content-Type': 'application/json',
  };
}

async function createDropletWithInit(customerId: string, cloudInit: string): Promise<DODroplet> {
  const dropletConfig = {
    name: `oriclaw-${customerId}`,
    region: 'nyc3',
    size: 's-1vcpu-2gb',
    image: 'ubuntu-22-04-x64',
    user_data: cloudInit,
    tags: ['oriclaw', `customer:${customerId}`],
    monitoring: true,
    ipv6: false,
  };

  const response = await axios.post<DODropletResponse>(
    `${DO_API_BASE}/droplets`,
    dropletConfig,
    { headers: getHeaders() }
  );

  return response.data.droplet;
}
