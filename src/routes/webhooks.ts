import { Router, Request, Response } from 'express';
import Stripe from 'stripe';
import { provisionInstance, deprovisionInstance, suspendInstance } from '../services/provisioning';
import { addCredits } from './credits';
import { supabase, getInstanceBySubscriptionId } from '../services/supabase';

const router = Router();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

const PROCESSED_EVENTS_TABLE = 'stripe_processed_events';

// ── Idempotency helpers ──────────────────────────────────────────────────────
async function isEventProcessed(eventId: string): Promise<boolean> {
  const { data } = await supabase
    .from(PROCESSED_EVENTS_TABLE)
    .select('id')
    .eq('id', eventId)
    .single();
  return !!data;
}

async function markEventProcessed(eventId: string): Promise<void> {
  await supabase
    .from(PROCESSED_EVENTS_TABLE)
    .insert({ id: eventId });
}

// Stripe sends raw body — must use express.raw() for this route
router.post(
  '/stripe',
  async (req: Request, res: Response): Promise<void> => {
    const sig = req.headers['stripe-signature'];

    if (!sig) {
      res.status(400).json({ error: 'Missing stripe-signature header' });
      return;
    }

    let event: Stripe.Event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body as Buffer,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET!
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Webhook verification failed';
      console.error('[webhook] Signature verification failed:', msg);
      res.status(400).json({ error: msg });
      return;
    }

    console.log(`[webhook] Received event: ${event.type}`);

    // ── Idempotency check ────────────────────────────────────────────────────
    try {
      const alreadyProcessed = await isEventProcessed(event.id);
      if (alreadyProcessed) {
        console.log(`[webhook] Skipping duplicate event: ${event.id}`);
        res.json({ received: true, skipped: true });
        return;
      }
      // Mark as processed immediately before handling
      await markEventProcessed(event.id);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Idempotency check failed';
      console.error('[webhook] Idempotency error:', msg);
      // Continue processing — idempotency table may not exist yet
    }

    try {
      switch (event.type) {
        case 'customer.subscription.created': {
          const subscription = event.data.object as Stripe.Subscription;
          const customerId = subscription.customer as string;
          const plan = resolvePlan(subscription);

          // Uniqueness check: skip if already provisioned for this subscription
          const existingInstance = await getInstanceBySubscriptionId(subscription.id);
          if (existingInstance) {
            console.log(`[webhook] Instance already exists for subscription ${subscription.id}, skipping`);
            break;
          }

          // Fetch customer email from Stripe
          const customer = await stripe.customers.retrieve(customerId);
          const email = 'email' in customer ? (customer.email ?? 'unknown@unknown.com') : 'unknown@unknown.com';

          await provisionInstance({
            customer_id: customerId,
            plan,
            email,
            stripe_subscription_id: subscription.id,
          });
          break;
        }

        case 'customer.subscription.deleted': {
          const subscription = event.data.object as Stripe.Subscription;
          await deprovisionInstance(subscription.id);
          break;
        }

        case 'invoice.payment_failed': {
          const invoice = event.data.object as Stripe.Invoice;
          const subId = typeof invoice.subscription === 'string'
            ? invoice.subscription
            : invoice.subscription?.id ?? null;
          if (subId) {
            await suspendInstance(subId);
          }
          break;
        }

        case 'checkout.session.completed': {
          const session = event.data.object as Stripe.Checkout.Session;
          // Handle credits top-up (one-time payment mode)
          if (session.mode === 'payment') {
            const customerId = session.metadata?.customer_id;
            const amountBrl = parseFloat(session.metadata?.amount_brl ?? '0');
            if (customerId && amountBrl > 0) {
              await addCredits(customerId, amountBrl);
              console.log(`[webhook] Added R$${amountBrl} credits to ${customerId}`);
            }
          }
          // For subscription mode, customer.subscription.created handles provisioning
          break;
        }

        // Legacy: keep payment_intent.succeeded handling for old PaymentIntent-based flows
        case 'payment_intent.succeeded': {
          const pi = event.data.object as Stripe.PaymentIntent;
          const customerId = pi.metadata?.customer_id;
          const creditsBrl = parseFloat(pi.metadata?.credits_brl ?? '0');
          if (customerId && creditsBrl > 0) {
            await addCredits(customerId, creditsBrl);
            console.log(`[webhook] Added R$${creditsBrl} credits to ${customerId} (legacy PaymentIntent)`);
          }
          break;
        }

        default:
          console.log(`[webhook] Unhandled event type: ${event.type}`);
      }

      res.json({ received: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Internal error';
      console.error(`[webhook] Handler error for ${event.type}:`, msg);
      res.status(500).json({ error: msg });
    }
  }
);

function resolvePlan(subscription: Stripe.Subscription): 'starter' | 'pro' | 'business' {
  const item = subscription.items.data[0];
  const metadata = item?.price?.metadata ?? {};
  const plan = metadata['plan'] as string;

  if (plan === 'pro') return 'pro';
  if (plan === 'business') return 'business';
  return 'starter';
}

export default router;
