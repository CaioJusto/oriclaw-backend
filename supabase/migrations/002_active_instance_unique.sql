-- Prevent duplicate live instances per customer.
-- Historical deleted rows remain allowed for audit/history purposes.

CREATE UNIQUE INDEX IF NOT EXISTS oriclaw_instances_one_active_per_customer
  ON public.oriclaw_instances (customer_id)
  WHERE status <> 'deleted';
