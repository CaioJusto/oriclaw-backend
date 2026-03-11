/**
 * Checkout routes — create Stripe Hosted Checkout sessions for plan subscriptions.
 */
import { Router, Request, Response } from 'express';
import Stripe from 'stripe';
import { supabase } from '../services/supabase';

const router = Router();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

// Plan prices in centavos (BRL)
const PLAN_PRICES: Record<string, number> = {
  starter: 9700,
  pro: 14700,
  business: 24700,
};

// ── POST /api/checkout/session ────────────────────────────────────────────────
// Creates a Stripe Hosted Checkout subscription session.
// Body: { plan: 'starter' | 'pro' | 'business', email?: string }
// Returns: { url }
router.post('/session', async (req: Request, res: Response): Promise<void> => {
  const { plan, email, supabase_user_id } = req.body as { plan?: string; email?: string; supabase_user_id?: string };

  if (!plan || !PLAN_PRICES[plan]) {
    res.status(400).json({ error: 'Invalid plan. Must be: starter | pro | business' });
    return;
  }

  if (!supabase_user_id) {
    res.status(400).json({ error: 'supabase_user_id required' });
    return;
  }

  // Validar que o user autenticado bate com o supabase_user_id enviado
  const authHeader = req.headers['authorization'] ?? '';
  const token = (authHeader as string).replace(/^Bearer\s+/i, '').trim();
  if (!token) {
    res.status(401).json({ error: 'Autenticação obrigatória.' });
    return;
  }
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user || user.id !== supabase_user_id) {
    res.status(403).json({ error: 'Acesso negado.' });
    return;
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: email,
      line_items: [{
        price_data: {
          currency: 'brl',
          product_data: { name: `OriClaw ${plan.charAt(0).toUpperCase() + plan.slice(1)}`, metadata: { plan } },
          unit_amount: PLAN_PRICES[plan],
          recurring: { interval: 'month' },
        },
        quantity: 1,
      }],
      success_url: `${process.env.APP_URL}/dashboard?checkout=success`,
      cancel_url: `${process.env.APP_URL}/checkout?plan=${plan}&cancelled=true`,
      metadata: { plan, supabase_user_id },
      subscription_data: {

        metadata: { supabase_user_id, plan },
      },
    });

    res.json({ url: session.url });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Stripe error';
    console.error('[checkout/session]', msg);
    res.status(500).json({ error: msg });
  }
});

export default router;
