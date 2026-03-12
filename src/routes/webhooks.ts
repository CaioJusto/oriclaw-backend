import { Router, Request, Response } from 'express';
import Stripe from 'stripe';
import { provisionInstance, deprovisionInstance, suspendInstance, reactivateInstance } from '../services/provisioning';
import { addCredits } from './credits';
import { supabase, getInstanceBySubscriptionId, getInstanceByCustomerId, updateInstance } from '../services/supabase';

const router = Router();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

const PROCESSED_EVENTS_TABLE = 'stripe_processed_events';

// ── Idempotency helpers ──────────────────────────────────────────────────────
async function reserveEventProcessing(eventId: string): Promise<boolean> {
  const { count, error } = await supabase
    .from(PROCESSED_EVENTS_TABLE)
    .upsert({ id: eventId }, { onConflict: 'id', ignoreDuplicates: true, count: 'exact' });

  if (error) {
    throw new Error(`Failed to reserve webhook event: ${error.message}`);
  }

  // count > 0 = row was inserted (new event, proceed)
  // count === 0 = row already existed (duplicate, skip)
  return (count ?? 0) > 0;
}

async function releaseEventReservation(eventId: string): Promise<void> {
  await supabase
    .from(PROCESSED_EVENTS_TABLE)
    .delete()
    .eq('id', eventId);
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

    // ── Atomic idempotency reservation (INSERT ... ON CONFLICT DO NOTHING) ─
    try {
      const reserved = await reserveEventProcessing(event.id);
      if (!reserved) {
        console.log(`[webhook] Skipping duplicate event: ${event.id}`);
        res.json({ received: true, skipped: true });
        return;
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Idempotency reservation failed';
      console.error('[webhook] Idempotency reservation error:', msg);
      res.status(500).json({ error: 'Idempotency reservation failed' });
      return;
    }

    try {
      switch (event.type) {
        case 'customer.subscription.created': {
          const subscription = event.data.object as Stripe.Subscription;
          // Get supabase_user_id from subscription metadata (set during checkout)
          const supabaseUserId = subscription.metadata?.supabase_user_id;
          const plan = resolvePlan(subscription);

          if (!supabaseUserId) {
            console.warn('[webhook] subscription.created missing supabase_user_id in metadata, skipping provisioning');
            break;
          }

          // Uniqueness check: skip if already provisioned for this user
          const existingInstance = await getInstanceByCustomerId(supabaseUserId);
          if (existingInstance && existingInstance.status !== 'deleted') {
            console.log(`[webhook] Instance already exists for user ${supabaseUserId}, skipping`);
            break;
          }

          // Fetch customer email from Stripe
          const customerId = subscription.customer as string;
          const customer = await stripe.customers.retrieve(customerId);
          const email = 'email' in customer ? (customer.email ?? '') : '';

          await provisionInstance({
            customer_id: supabaseUserId,  // Use Supabase UID, not Stripe cus_
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

        case 'invoice.payment_succeeded': {
          const invoice = event.data.object as Stripe.Invoice;
          const subId = typeof invoice.subscription === 'string'
            ? invoice.subscription
            : (invoice.subscription as Stripe.Subscription | null)?.id ?? null;
          if (subId) {
            try {
              await reactivateInstance(subId);
              console.log(`[webhook] Reactivated instance for subscription: ${subId}`);
            } catch (err: unknown) {
              const msg = err instanceof Error ? err.message : String(err);
              console.error(`[webhook] Failed to reactivate instance: ${msg}`);
            }
          }
          break;
        }

        case 'customer.subscription.updated': {
          const subscription = event.data.object as Stripe.Subscription;
          const subId = subscription.id;
          const instance = await getInstanceBySubscriptionId(subId);
          if (!instance) break;

          // Tentar extrair o plano do metadata do price, subscription metadata ou do nickname
          const planFromMeta = subscription.items.data[0]?.price?.metadata?.plan as string | undefined;
          const planFromSub = subscription.metadata?.plan as string | undefined;
          const planFromNickname = subscription.items.data[0]?.price?.nickname?.toLowerCase() as string | undefined;
          const newPlan = planFromMeta ?? planFromSub ?? planFromNickname ?? null;

          if (newPlan && ['starter', 'pro', 'business'].includes(newPlan)) {
            await updateInstance(instance.id, { plan: newPlan as 'starter' | 'pro' | 'business' });
            console.log(`[webhook] Updated plan to ${newPlan} for instance ${instance.id}`);
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
          console.log(`[webhook] checkout.session.completed: ${session.id}`);
          break;
        }

        // Bug fix #10: payment_intent.succeeded intentionally does NOT handle credits.
        // Stripe fires BOTH checkout.session.completed AND payment_intent.succeeded for
        // the same purchase. Credits are exclusively handled in checkout.session.completed
        // (mode: 'payment') to prevent double-crediting. Do NOT add credit logic here.
        case 'payment_intent.succeeded': {
          console.log(`[webhook] payment_intent.succeeded received — no action taken (credits handled in checkout.session.completed)`);
          break;
        }

        default:
          console.log(`[webhook] Unhandled event type: ${event.type}`);
      }

      res.json({ received: true });
    } catch (err: unknown) {
      // Release reservation so Stripe retries can process again.
      try {
        await releaseEventReservation(event.id);
      } catch (releaseErr: unknown) {
        const releaseMsg = releaseErr instanceof Error ? releaseErr.message : String(releaseErr);
        console.warn('[webhook] Failed to release idempotency reservation:', releaseMsg);
      }

      const msg = err instanceof Error ? err.message : 'Internal error';
      console.error(`[webhook] Handler failed for ${event.type}, will allow retry:`, msg);
      res.status(500).json({ error: 'Handler failed' });
    }
  }
);

function resolvePlan(subscription: Stripe.Subscription): 'starter' | 'pro' | 'business' {
  const item = subscription.items.data[0];
  // Tenta ler do price metadata (se disponível)
  const planFromPrice = item?.price?.metadata?.plan;
  // Fallback: subscription metadata (definido no checkout via subscription_data.metadata)
  const planFromSub = subscription.metadata?.plan;
  const plan = planFromPrice ?? planFromSub;

  if (plan === 'pro') return 'pro';
  if (plan === 'business') return 'business';
  return 'starter';
}

export default router;
