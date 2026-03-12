import crypto from 'crypto';
import axios from 'axios';
import Stripe from 'stripe';
import { deleteDroplet, getDroplet, getDropletPublicIP } from './digitalocean';
import {
  createInstance,
  getInstanceById,
  getInstanceBySubscriptionId,
  updateInstance,
  supabase,
} from './supabase';
import { CLOUD_INIT_SCRIPT } from './cloudInit';
import { ProvisionRequest, DODroplet, DODropletResponse } from '../types';
import { encrypt, decrypt } from './crypto';

// ── DO API rate-limit guard ───────────────────────────────────────────────────
// Limits simultaneous droplet creations to avoid hitting DigitalOcean's rate
// limit (typically 10 droplets/minute). Counter tracks async createDropletAsync
// coroutines in flight; decremented in the finally block of each.
let activeProvisioningCount = 0;
const MAX_CONCURRENT_PROVISIONING = 2;

export async function provisionInstance(
  req: ProvisionRequest
): Promise<{ instance_id: string; status: string }> {
  console.log(`[provision] Starting for customer: ${req.customer_id}`);

  // Bug fix #5: Reject early if too many droplets are being provisioned simultaneously
  if (activeProvisioningCount >= MAX_CONCURRENT_PROVISIONING) {
    throw new Error(
      `Limite de provisionamentos simultâneos atingido (${MAX_CONCURRENT_PROVISIONING}). ` +
      'Tente novamente em alguns minutos.'
    );
  }

  // Bug fix: reserve the semaphore slot BEFORE any async operation so that two
  // concurrent calls can't both pass the >= check before either increments.
  activeProvisioningCount++;

  // Generate random agent secret for this instance
  const agentSecret = crypto.randomBytes(32).toString('hex');

  let instance: Awaited<ReturnType<typeof createInstance>>;
  try {
    // Create DB record first (status='provisioning' — dashboard sees this immediately)
    instance = await createInstance({
      customer_id: req.customer_id,
      email: req.email,
      plan: req.plan,
      droplet_id: null,
      droplet_ip: null,
      status: 'provisioning',
      stripe_subscription_id: req.stripe_subscription_id ?? null,
      api_key_encrypted: req.api_key_anthropic ? encrypt(req.api_key_anthropic) : null,
      metadata: { agent_secret: encrypt(agentSecret) },
    });
  } catch (dbErr) {
    // If the DB insert fails, release the reserved slot before re-throwing
    activeProvisioningCount--;
    throw dbErr;
  }

  // Create DO Droplet (non-blocking — status will update async)
  createDropletAsync(instance.id, req.customer_id, agentSecret, req.stripe_subscription_id ?? null)
    .catch(async (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[provision] Droplet creation failed for ${instance.id}:`, msg);
      // Attempt to cancel the Stripe subscription so the user isn't billed for a
      // failed provisioning. Re-fetch the instance to get the subscription ID in
      // case it was bound by customer.subscription.created after checkout.
      await cancelSubscriptionForInstance(instance.id, req.stripe_subscription_id ?? null);
      // Bug fix #2: preserve agent_secret and add suspended_reason
      updateInstance(instance.id, {
        status: 'suspended',
        metadata: { agent_secret: encrypt(agentSecret), error: msg, suspended_reason: 'provisioning_failed' },
      }).catch(console.error);
    })
    .finally(() => {
      activeProvisioningCount--;
    });

  return { instance_id: instance.id, status: 'provisioning' };
}

const PLAN_SIZES: Record<string, string> = {
  'starter': 's-1vcpu-2gb',
  'pro': 's-2vcpu-4gb',
  'business': 's-4vcpu-8gb',
};

/**
 * cancelSubscriptionForInstance — best-effort: cancel Stripe subscription for an
 * instance whose provisioning failed so the user isn't billed for a broken VPS.
 * Re-fetches the instance to get the latest stripe_subscription_id (it may have
 * been bound by customer.subscription.created after checkout.session.completed).
 */
async function cancelSubscriptionForInstance(
  instanceId: string,
  knownSubId: string | null
): Promise<void> {
  if (!process.env.STRIPE_SECRET_KEY) return;
  let subId = knownSubId;
  if (!subId) {
    try {
      const latest = await getInstanceById(instanceId);
      subId = latest?.stripe_subscription_id ?? null;
    } catch { /* ignore — best effort */ }
  }
  if (!subId) return;
  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2026-02-25.clover' });
  try {
    await stripe.subscriptions.cancel(subId);
    console.log(`[provision] Cancelled Stripe subscription ${subId} after provisioning failure for instance ${instanceId}`);
  } catch (cancelErr: unknown) {
    // 'already_cancelled' or similar errors are expected — just log and move on
    console.error(
      `[provision] Failed to cancel subscription ${subId}:`,
      cancelErr instanceof Error ? cancelErr.message : String(cancelErr)
    );
  }
}

async function createDropletAsync(
  instanceId: string,
  customerId: string,
  agentSecret: string,
  stripeSubId: string | null
): Promise<void> {
  // Generate gateway token for OpenClaw UI auth
  const gatewayToken = crypto.randomBytes(32).toString('hex');

  // Inject agent secret and gateway token into cloud-init
  const cloudInit = CLOUD_INIT_SCRIPT
    .replace(/__AGENT_SECRET__/g, agentSecret)
    .replace(/__GATEWAY_TOKEN__/g, gatewayToken);

  // Get instance to determine plan-based droplet size
  const instanceForPlan = await getInstanceById(instanceId);
  const planSize = PLAN_SIZES[instanceForPlan?.plan ?? 'starter'] ?? 's-1vcpu-2gb';

  const droplet = await createDropletWithInit(customerId, cloudInit, planSize);
  console.log(`[provision] Droplet created: ${droplet.id} for instance ${instanceId}`);

  const currentAfterCreate = await getInstanceById(instanceId);
  if (!currentAfterCreate || currentAfterCreate.status === 'deleted') return;
  await updateInstance(instanceId, {
    droplet_id: droplet.id,
    metadata: { droplet_name: droplet.name, agent_secret: encrypt(agentSecret) },
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
    // Cancel Stripe subscription — user shouldn't be billed for a VPS without IP
    await cancelSubscriptionForInstance(instanceId, stripeSubId);
    // Bug fix #2: add suspended_reason so dashboard can show meaningful message
    await updateInstance(instanceId, {
      status: 'suspended',
      metadata: {
        droplet_name: droplet.name,
        agent_secret: encrypt(agentSecret),
        error: 'Droplet não obteve IP em tempo hábil',
        suspended_reason: 'provisioning_failed_no_ip',
      },
    });
    return;
  }

  // Wait until VPS agent is responding on /health before exposing needs_config.
  const agentReady = await waitForAgentReadiness(ip, agentSecret, 20 * 60 * 1000);
  if (!agentReady) {
    // Cancel Stripe subscription — user shouldn't be billed for an unresponsive VPS
    await cancelSubscriptionForInstance(instanceId, stripeSubId);
    // Bug fix #2: add suspended_reason
    await updateInstance(instanceId, {
      droplet_ip: ip,
      status: 'suspended',
      metadata: {
        droplet_name: droplet.name,
        agent_secret: encrypt(agentSecret),
        error: 'VPS agent não respondeu após 20 minutos',
        suspended_reason: 'provisioning_failed_agent_timeout',
      },
    });
    return;
  }

  const current = await getInstanceById(instanceId);
  if (!current || current.status === 'suspended' || current.status === 'deleted') {
    console.warn(`[provision] Instance ${instanceId} is ${current?.status} — aborting needs_config transition`);
    return;
  }
  await updateInstance(instanceId, {
    droplet_ip: ip,
    status: 'needs_config',
    metadata: { droplet_name: droplet.name, agent_secret: encrypt(agentSecret) },
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

    // Verify droplet is actually gone (DO API returns 404 for deleted droplets)
    try {
      await getDroplet(instance.droplet_id);
      // If we get here, droplet still exists — mark as deletion_failed
      console.warn(`[deprovision] Droplet ${instance.droplet_id} still exists after DELETE`);
      await updateInstance(instance.id, {
        status: 'deletion_failed',
        metadata: { ...(instance.metadata ?? {}), error: 'Droplet still exists after deletion request' },
      });
      return;
    } catch {
      // 404 = droplet is gone, which is what we want
    }
  }

  await updateInstance(instance.id, { status: 'deleted' });
}

export async function suspendInstance(subscriptionId: string, reason = 'payment_failed'): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) return;
  // Bug fix #2: preserve existing metadata and add suspended_reason so the
  // dashboard can distinguish "payment suspended" from "provisioning failed"
  const existingMeta = (instance.metadata ?? {}) as Record<string, unknown>;
  await updateInstance(instance.id, {
    status: 'suspended',
    metadata: { ...existingMeta, suspended_reason: reason },
  });
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
    const wasConfigured = !!(meta?.ai_mode);
    const newStatus = wasConfigured ? 'running' : 'needs_config';
    await updateInstance(instance.id, {
      status: newStatus,
      metadata: { ...(meta ?? {}), reactivated_at: new Date().toISOString(), error: undefined },
    });
    console.log(`[reactivate] Instance ${instance.id} reactivated to ${newStatus}`);
  }
}

export async function updateApiKey(instanceId: string, apiKey: string): Promise<void> {
  await updateInstance(instanceId, { api_key_encrypted: encrypt(apiKey) });
  console.log(`[updateApiKey] Stored new encrypted API key for instance ${instanceId} (configure via /proxy)`);
}

/**
 * Bug fix #3: retryPendingDeletions — called at startup to resolve instances
 * stuck in 'deletion_failed' state. deleteDroplet treats 404 as success, so
 * retrying is safe and idempotent.
 */
export async function retryPendingDeletions(): Promise<void> {
  try {
    const { data: failing } = await supabase
      .from('oriclaw_instances')
      .select('id, droplet_id, metadata')
      .eq('status', 'deletion_failed');

    if (!failing || failing.length === 0) return;

    console.log(`[startup] Found ${failing.length} deletion_failed instance(s), retrying`);

    for (const inst of failing) {
      try {
        if (inst.droplet_id) {
          await deleteDroplet(inst.droplet_id as number);
        }
        await updateInstance(inst.id, { status: 'deleted' });
        console.log(`[startup] Retry deletion succeeded for instance ${inst.id}`);
      } catch (err) {
        console.warn(
          `[startup] Retry deletion failed for ${inst.id}:`,
          err instanceof Error ? err.message : err
        );
      }
    }
  } catch (err) {
    console.warn('[startup] Could not check for deletion_failed instances:', err);
  }
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
      const response = await axios.get(`https://${ip}:8080/health`, {
        headers: { 'x-agent-secret': agentSecret },
        timeout: 2_000,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
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

async function createDropletWithInit(customerId: string, cloudInit: string, size: string = 's-1vcpu-2gb'): Promise<DODroplet> {
  const dropletConfig = {
    name: `oriclaw-${customerId}`,
    region: 'nyc3',
    size,
    image: 'ubuntu-24-04-x64',
    user_data: cloudInit,
    tags: ['oriclaw', `customer:${customerId}`],
    monitoring: true,
    ipv6: false,
  };

  const response = await axios.post<DODropletResponse>(
    `${DO_API_BASE}/droplets`,
    dropletConfig,
    { headers: getHeaders(), timeout: 30_000 }
  );

  return response.data.droplet;
}
