import { NodeSSH } from 'node-ssh';
import { createDroplet, deleteDroplet, getDroplet, getDropletPublicIP } from './digitalocean';
import {
  createInstance,
  getInstanceById,
  getInstanceBySubscriptionId,
  updateInstance,
} from './supabase';
import { ProvisionRequest } from '../types';

export async function provisionInstance(
  req: ProvisionRequest
): Promise<{ instance_id: string; status: string }> {
  console.log(`[provision] Starting for customer: ${req.customer_id}`);

  // Create DB record first
  const instance = await createInstance({
    customer_id: req.customer_id,
    email: req.email,
    plan: req.plan,
    droplet_id: null,
    droplet_ip: null,
    status: 'provisioning',
    stripe_subscription_id: req.stripe_subscription_id ?? null,
    api_key_encrypted: req.api_key_anthropic ?? null,
    metadata: null,
  });

  // Create DO Droplet (non-blocking — status will update async)
  createDropletAsync(instance.id, req.customer_id).catch((err) => {
    console.error(`[provision] Droplet creation failed for ${instance.id}:`, err.message);
    updateInstance(instance.id, { status: 'suspended', metadata: { error: err.message } }).catch(
      console.error
    );
  });

  return { instance_id: instance.id, status: 'provisioning' };
}

async function createDropletAsync(instanceId: string, customerId: string): Promise<void> {
  const droplet = await createDroplet(customerId);
  console.log(`[provision] Droplet created: ${droplet.id} for instance ${instanceId}`);

  await updateInstance(instanceId, {
    droplet_id: droplet.id,
    metadata: { droplet_name: droplet.name },
  });

  // Poll for droplet IP (up to 3 minutes)
  let ip: string | null = null;
  for (let i = 0; i < 18; i++) {
    await sleep(10_000);
    const updated = await getDroplet(droplet.id);
    ip = getDropletPublicIP(updated);
    if (ip) break;
  }

  await updateInstance(instanceId, {
    droplet_ip: ip,
    status: ip ? 'running' : 'provisioning',
  });

  if (ip) {
    console.log(`[provision] Instance ${instanceId} is running at ${ip}`);
  }
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
    }
  }

  await updateInstance(instance.id, { status: 'deleted' });
}

export async function suspendInstance(subscriptionId: string): Promise<void> {
  const instance = await getInstanceBySubscriptionId(subscriptionId);
  if (!instance) return;
  await updateInstance(instance.id, { status: 'suspended' });
}

export async function updateApiKey(instanceId: string, apiKey: string): Promise<void> {
  // Update in Supabase
  await updateInstance(instanceId, { api_key_encrypted: apiKey });

  // Optionally SSH into droplet to update .env
  const instance = await getInstanceById(instanceId);
  if (!instance?.droplet_ip) {
    console.warn(`[updateApiKey] No IP for instance ${instanceId}, skipping SSH`);
    return;
  }

  try {
    const ssh = new NodeSSH();
    await ssh.connect({
      host: instance.droplet_ip,
      username: 'root',
      // In production, use a private key stored securely
      // privateKey: process.env.SSH_PRIVATE_KEY,
      readyTimeout: 10_000,
    });

    await ssh.execCommand(
      `echo "ANTHROPIC_API_KEY=${apiKey}" >> /home/openclaw/.env && ` +
        `systemctl restart openclaw`
    );

    ssh.dispose();
    console.log(`[updateApiKey] Updated API key on droplet for instance ${instanceId}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[updateApiKey] SSH failed (non-fatal): ${msg}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
