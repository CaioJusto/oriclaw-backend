import { Router, Request, Response } from 'express';
import Stripe from 'stripe';
import { requireAuth } from '../middleware/requireAuth';
import { supabase } from '../services/supabase';

const router = Router();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

// POST /api/billing/portal
// Creates a Stripe Customer Portal session for the authenticated user
router.post('/portal', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Get instance to find stripe customer ID
    const { data: instance, error } = await supabase
      .from('oriclaw_instances')
      .select('stripe_subscription_id, metadata')
      .eq('customer_id', userId)
      .not('stripe_subscription_id', 'is', null)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !instance) {
      res.status(404).json({ error: 'No active subscription found' });
      return;
    }

    // Get customer ID from Stripe subscription
    const subscription = await stripe.subscriptions.retrieve(instance.stripe_subscription_id!);
    const customerId = subscription.customer as string;

    const returnUrl = `${process.env.APP_URL ?? 'https://oriclaw.com.br'}/dashboard`;

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl,
    });

    res.json({ url: session.url });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to create portal session';
    console.error('[billing/portal] Error:', msg);
    res.status(500).json({ error: msg });
  }
});

export default router;
