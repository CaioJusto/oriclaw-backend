/**
 * Credits routes — manage OriClaw credit balances for pay-as-you-go customers.
 *
 * Credits are stored in `oriclaw_credits` (customer_id, balance_brl, updated_at).
 * Purchases are handled via Stripe Hosted Checkout; the webhook handler adds
 * credits to the balance when checkout.session.completed fires (mode: 'payment').
 */
import { Router, Request, Response } from 'express';
import Stripe from 'stripe';
import { supabase } from '../services/supabase';

const router = Router();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

const CREDITS_TABLE = 'oriclaw_credits';

// Valid top-up amounts (BRL) → message estimate
const VALID_AMOUNTS: Record<number, number> = {
  20: 1000,
  50: 3000,
  100: 7000,
};

// ── Auth helper ──────────────────────────────────────────────────────────────
async function getUserId(req: Request): Promise<string | null> {
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user.id;
}

// ── GET /api/credits ─────────────────────────────────────────────────────────
// Returns current credit balance for the authenticated user.
router.get('/', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const { data, error } = await supabase
    .from(CREDITS_TABLE)
    .select('balance_brl')
    .eq('customer_id', userId)
    .maybeSingle();

  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json({ balance_brl: (data as { balance_brl: number } | null)?.balance_brl ?? 0 });
});

// ── POST /api/credits/purchase ───────────────────────────────────────────────
// Creates a Stripe Hosted Checkout session for a credit top-up.
// Body: { amount_brl: 20 | 50 | 100, instance_id?: string }
// Returns: { payment_url }
router.post('/purchase', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const { amount_brl } = req.body as { amount_brl?: number; instance_id?: string };
  if (!amount_brl || !VALID_AMOUNTS[amount_brl]) {
    res.status(400).json({
      error: `Invalid amount. Must be one of: ${Object.keys(VALID_AMOUNTS).join(', ')}`,
    });
    return;
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'brl',
          product_data: {
            name: `OriClaw Créditos R$${amount_brl}`,
            description: `≈${VALID_AMOUNTS[amount_brl].toLocaleString()} mensagens`,
          },
          unit_amount: amount_brl * 100, // centavos
        },
        quantity: 1,
      }],
      success_url: `${process.env.APP_URL}/dashboard?credits=success`,
      cancel_url: `${process.env.APP_URL}/dashboard?credits=cancelled`,
      metadata: {
        customer_id: userId,
        amount_brl: String(amount_brl),
        messages_estimate: String(VALID_AMOUNTS[amount_brl]),
      },
    });

    res.json({ payment_url: session.url });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Stripe error';
    console.error('[credits/purchase]', msg);
    res.status(500).json({ error: msg });
  }
});

// ── GET /api/credits/:customer_id ────────────────────────────────────────────
// Internal / admin route to fetch balance by customer_id.
router.get('/:customer_id', async (req: Request, res: Response): Promise<void> => {
  const apiSecret = (req.headers['x-api-secret'] ?? '') as string;
  if (apiSecret !== process.env.API_SECRET) {
    res.status(403).json({ error: 'Forbidden' }); return;
  }

  const { data, error } = await supabase
    .from(CREDITS_TABLE)
    .select('balance_brl, updated_at')
    .eq('customer_id', req.params.customer_id)
    .maybeSingle();

  if (error) { res.status(500).json({ error: error.message }); return; }
  res.json({
    customer_id: req.params.customer_id,
    balance_brl: (data as { balance_brl: number; updated_at: string } | null)?.balance_brl ?? 0,
    updated_at: (data as { balance_brl: number; updated_at: string } | null)?.updated_at ?? null,
  });
});

/**
 * addCredits — called by the Stripe webhook when checkout.session.completed fires
 * (for mode: 'payment' credits purchases).
 * Upserts the oriclaw_credits row for customer_id.
 */
export async function addCredits(customerId: string, amountBrl: number): Promise<void> {
  const { data: existing } = await supabase
    .from(CREDITS_TABLE)
    .select('balance_brl')
    .eq('customer_id', customerId)
    .maybeSingle();

  const currentBalance = (existing as { balance_brl: number } | null)?.balance_brl ?? 0;
  const newBalance = currentBalance + amountBrl;

  await supabase
    .from(CREDITS_TABLE)
    .upsert(
      { customer_id: customerId, balance_brl: newBalance, updated_at: new Date().toISOString() },
      { onConflict: 'customer_id' }
    );
}

export default router;
