import { createClient } from '@supabase/supabase-js';
import { OriClawInstance } from '../types';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

const TABLE = 'oriclaw_instances';
const pendingProvisionCustomers = new Set<string>();

function isUniqueViolation(error: { code?: string; message?: string } | null | undefined): boolean {
  if (!error) return false;
  return error.code === '23505' || /duplicate key|unique/i.test(error.message ?? '');
}

export async function createInstance(
  data: Omit<OriClawInstance, 'id' | 'created_at'>
): Promise<OriClawInstance> {
  if (pendingProvisionCustomers.has(data.customer_id)) {
    throw new Error(`Provisioning already in progress for customer ${data.customer_id}`);
  }

  pendingProvisionCustomers.add(data.customer_id);
  try {
    const { data: existing } = await supabase
      .from(TABLE)
      .select('id')
      .eq('customer_id', data.customer_id)
      .neq('status', 'deleted')
      .limit(1)
      .maybeSingle();

    if (existing) {
      throw new Error(`Instance already exists for customer ${data.customer_id}`);
    }

    const { data: row, error } = await supabase
      .from(TABLE)
      .insert(data)
      .select()
      .single();

    if (error) {
      if (isUniqueViolation(error)) {
        throw new Error(`Instance already exists for customer ${data.customer_id}`);
      }
      throw new Error(`Supabase insert error: ${error.message}`);
    }

    return row as OriClawInstance;
  } finally {
    pendingProvisionCustomers.delete(data.customer_id);
  }
}

export async function getInstanceByCustomerId(
  customerId: string
): Promise<OriClawInstance | null> {
  const { data, error } = await supabase
    .from(TABLE)
    .select('*')
    .eq('customer_id', customerId)
    .neq('status', 'deleted')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw new Error(`Supabase query error: ${error.message}`);
  return data as OriClawInstance | null;
}

export async function getInstanceById(
  instanceId: string
): Promise<OriClawInstance | null> {
  const { data, error } = await supabase
    .from(TABLE)
    .select('*')
    .eq('id', instanceId)
    .maybeSingle();

  if (error) throw new Error(`Supabase query error: ${error.message}`);
  return data as OriClawInstance | null;
}

export async function getInstanceBySubscriptionId(
  subscriptionId: string
): Promise<OriClawInstance | null> {
  const { data, error } = await supabase
    .from(TABLE)
    .select('*')
    .eq('stripe_subscription_id', subscriptionId)
    .neq('status', 'deleted')
    .maybeSingle();

  if (error) throw new Error(`Supabase query error: ${error.message}`);
  return data as OriClawInstance | null;
}

export async function updateInstance(
  instanceId: string,
  updates: Partial<OriClawInstance>
): Promise<OriClawInstance> {
  if (updates.metadata) {
    const { data: existing } = await supabase
      .from(TABLE)
      .select('metadata')
      .eq('id', instanceId)
      .single();

    const existingMeta = (existing?.metadata ?? {}) as Record<string, unknown>;
    updates.metadata = { ...existingMeta, ...(updates.metadata as Record<string, unknown>) };
  }

  const { data, error } = await supabase
    .from(TABLE)
    .update(updates)
    .eq('id', instanceId)
    .select()
    .single();

  if (error) throw new Error(`Supabase update error: ${error.message}`);
  return data as OriClawInstance;
}

export { supabase };
