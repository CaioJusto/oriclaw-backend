-- OriClaw RLS Policies
-- Run this migration in Supabase SQL editor or via supabase db push

-- Enable RLS on all OriClaw tables
ALTER TABLE oriclaw_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE oriclaw_credits ENABLE ROW LEVEL SECURITY;

-- Instances: users can only see/modify their own
CREATE POLICY "instances_owner_select" ON oriclaw_instances
  FOR SELECT USING (customer_id = auth.uid()::text);

CREATE POLICY "instances_owner_update" ON oriclaw_instances
  FOR UPDATE USING (customer_id = auth.uid()::text);

-- Credits: users can only see their own balance
CREATE POLICY "credits_owner_select" ON oriclaw_credits
  FOR SELECT USING (customer_id = auth.uid()::text);

-- Service role bypasses RLS (backend uses service role key)
-- These policies protect against direct anon/user key access

-- ── Audit log table ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS oriclaw_audit_log (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id text,
  instance_id uuid,
  action text NOT NULL,
  ip text,
  metadata jsonb,
  created_at timestamptz DEFAULT now()
);

-- Audit log: users can read their own
CREATE POLICY "audit_owner_select" ON oriclaw_audit_log
  FOR SELECT USING (user_id = auth.uid()::text);

ALTER TABLE oriclaw_audit_log ENABLE ROW LEVEL SECURITY;

-- ── Stripe processed events table ───────────────────────────────────────────
-- Ensure processed_at column exists (add if table was created without it)
ALTER TABLE stripe_processed_events
  ADD COLUMN IF NOT EXISTS processed_at timestamptz DEFAULT now();
