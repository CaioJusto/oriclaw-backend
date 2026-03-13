import axios from 'axios';
import https from 'https';
import { decrypt } from './crypto';
import { supabase } from './supabase';

const creditStatusHttpsAgent = new https.Agent({ rejectUnauthorized: false });

type CreditManagedInstance = {
  id: string;
  customer_id: string;
  droplet_ip: string | null;
  metadata: Record<string, unknown> | null;
};

function isCreditsMode(instance: CreditManagedInstance): boolean {
  const meta = (instance.metadata ?? {}) as Record<string, unknown>;
  return meta.ai_mode === 'credits';
}

async function getCustomerBalance(customerId: string): Promise<number> {
  const { data } = await supabase
    .from('oriclaw_credits')
    .select('balance_brl')
    .eq('customer_id', customerId)
    .maybeSingle();

  return (data as { balance_brl: number } | null)?.balance_brl ?? 0;
}

async function sendCreditStatus(instance: CreditManagedInstance, balance: number): Promise<void> {
  if (!instance.droplet_ip) return;

  const meta = (instance.metadata ?? {}) as Record<string, unknown>;
  const agentSecretEncrypted = meta.agent_secret as string | undefined;
  if (!agentSecretEncrypted) return;

  let agentSecret: string;
  try {
    agentSecret = decrypt(agentSecretEncrypted);
  } catch {
    return;
  }

  const blocked = balance <= 0;
  await axios.post(
    `https://${instance.droplet_ip}:8080/credit-status`,
    { blocked, balance_brl: balance },
    {
      headers: {
        'x-agent-secret': agentSecret,
        'Content-Type': 'application/json',
      },
      timeout: 5_000,
      httpsAgent: creditStatusHttpsAgent,
    }
  );
}

export async function notifyCreditStatusForCustomer(customerId: string): Promise<void> {
  const balance = await getCustomerBalance(customerId);
  const { data: instances } = await supabase
    .from('oriclaw_instances')
    .select('id, customer_id, droplet_ip, metadata')
    .eq('customer_id', customerId)
    .eq('status', 'running');

  for (const instance of (instances as CreditManagedInstance[] | null) ?? []) {
    if (!isCreditsMode(instance)) continue;
    try {
      await sendCreditStatus(instance, balance);
    } catch (err) {
      console.warn(
        `[credit-status] Failed to notify instance ${instance.id}:`,
        err instanceof Error ? err.message : String(err)
      );
    }
  }
}

export async function notifyCreditStatusForAllCreditsInstances(): Promise<void> {
  const { data: instances } = await supabase
    .from('oriclaw_instances')
    .select('id, customer_id, droplet_ip, metadata')
    .eq('status', 'running');

  const balanceCache = new Map<string, number>();

  for (const instance of (instances as CreditManagedInstance[] | null) ?? []) {
    if (!isCreditsMode(instance)) continue;

    let balance = balanceCache.get(instance.customer_id);
    if (balance === undefined) {
      balance = await getCustomerBalance(instance.customer_id);
      balanceCache.set(instance.customer_id, balance);
    }

    try {
      await sendCreditStatus(instance, balance);
    } catch (err) {
      console.warn(
        `[credit-status] Failed to notify instance ${instance.id}:`,
        err instanceof Error ? err.message : String(err)
      );
    }
  }
}
