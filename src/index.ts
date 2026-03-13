import 'dotenv/config';
import express, { Request as ExpressRequest } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';
import webhookRoutes from './routes/webhooks';
import instanceRoutes from './routes/instances';
import proxyRoutes from './routes/proxy';
import creditsRoutes from './routes/credits';
import authRoutes from './routes/auth';
import checkoutRoutes from './routes/checkout';
import billingRoutes from './routes/billing';
import adminRoutes from './routes/admin';
import { supabase } from './services/supabase';
import { retryPendingDeletions } from './services/provisioning';
import { calculateOpenRouterCostUsd, getAdminSettings, normalizeOpenRouterModelId } from './services/openrouter';
import { decrypt } from './services/crypto';
import { notifyCreditStatusForAllCreditsInstances } from './services/creditStatus';
import { agentHttpsAgent, resolveAgentBaseUrl } from './services/agentNetwork';
import axios from 'axios';

// ── Required environment variable validation ──────────────────────────────────
const REQUIRED_ENV_VARS = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'DO_API_TOKEN',
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'ENCRYPTION_KEY',
  'ORICLAW_OPENROUTER_KEY',
  'API_SECRET', // required by requireApiSecret middleware on provisioning endpoints
  'APP_URL',    // required for Stripe redirect URLs in checkout.ts and credits.ts
];

const missingVars = REQUIRED_ENV_VARS.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error(`[startup] FATAL: Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

const encKey = process.env.ENCRYPTION_KEY ?? '';
if (!/^[0-9a-fA-F]{64}$/.test(encKey)) {
  console.error('[startup] FATAL: ENCRYPTION_KEY deve ser uma string hexadecimal de 64 caracteres (32 bytes para AES-256). Gere com: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

if (process.env.NODE_ENV === 'production' && !process.env.CORS_ORIGIN) {
  console.error('[startup] FATAL: CORS_ORIGIN is required in production');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT ?? 3001;

// ── Security headers ─────────────────────────────────────────────────────────
app.use(helmet());

// ── CORS — strict in production ──────────────────────────────────────────────
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',')
  : process.env.NODE_ENV === 'production'
    ? [] // block all in production if not configured
    : ['http://localhost:3000'];

app.use(cors({
  origin: allowedOrigins.length > 0 ? allowedOrigins : false,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-secret'],
}));

// ── Body parsing ─────────────────────────────────────────────────────────────
// Stripe webhooks need raw body for signature verification — registered BEFORE
// the global rate limiter so the raw Buffer is available for signature checks
// and webhook deliveries are never accidentally rate-limited by IP.
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));

// All other routes use JSON
app.use(express.json());

// ── Rate limiting ────────────────────────────────────────────────────────────
// Webhook routes are excluded: Stripe sends from known IPs, validates with
// HMAC signature, and must never be rate-limited by client IP.
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  skip: (req) => req.path.startsWith('/webhooks/'),
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'oriclaw-backend', ts: new Date().toISOString() });
});

// ── Auth resolver: runs before rate limiters to enable per-user keying ───────
// Without this, req.user?.id is always undefined in keyGenerator because auth
// middleware runs inside route handlers, not before the rate limiter.
async function resolveUser(req: express.Request, _res: express.Response, next: express.NextFunction): Promise<void> {
  const authHeader = req.headers['authorization'] ?? '';
  const token = (authHeader as string).replace(/^Bearer\s+/i, '').trim();
  if (token) {
    try {
      const { data } = await supabase.auth.getUser(token);
      if (data?.user) req.user = { id: data.user.id };
    } catch { /* ignore — rate limit will fall back to IP */ }
  }
  next();
}

// ── Per-user rate limits for proxy routes ────────────────────────────────────
const proxyRateLimit = rateLimit({
  windowMs: 60_000, // 1 minuto
  max: 30,
  keyGenerator: (req: ExpressRequest & { user?: { id: string } }) => req.user?.id ?? req.ip ?? 'unknown',
  message: { error: 'Muitas requisições. Aguarde um momento.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const restartRateLimit = rateLimit({
  windowMs: 60_000,
  max: 5,
  keyGenerator: (req: ExpressRequest & { user?: { id: string } }) => req.user?.id ?? req.ip ?? 'unknown',
  message: { error: 'Muitos restarts em pouco tempo. Aguarde.' },
});

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/webhooks', webhookRoutes);
app.use('/api/instances', instanceRoutes);
app.use('/api/proxy', resolveUser);
app.use('/api/proxy', proxyRateLimit);
app.use('/api/proxy/:id/restart', restartRateLimit);
app.use('/api/proxy', proxyRoutes);
app.use('/api/credits', creditsRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/checkout', checkoutRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/admin', adminRoutes);

// ── 404 fallback ─────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Global error handler ─────────────────────────────────────────────────────
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const isDev = process.env.NODE_ENV !== 'production';
  console.error('[unhandled]', err.message, err.stack);
  res.status(500).json({
    error: isDev ? err.message : 'Erro interno do servidor. Tente novamente.',
  });
});

// ── Startup recovery ─────────────────────────────────────────────────────────
async function recoverStuckProvisioningInstances() {
  try {
    const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString(); // 30 min atrás
    const { data: stuck } = await supabase
      .from('oriclaw_instances')
      .select('id')
      .eq('status', 'provisioning')
      .lt('created_at', cutoff);

    if (stuck && stuck.length > 0) {
      console.log(`[startup] Found ${stuck.length} stuck provisioning instance(s), marking as suspended`);

      // Lazy-init Stripe only when needed (key already validated at startup)
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, { apiVersion: '2026-02-25.clover' });

      for (const inst of stuck) {
        // Fetch existing metadata AND stripe_subscription_id to cancel the sub
        const { data: stuckInst } = await supabase
          .from('oriclaw_instances')
          .select('metadata, stripe_subscription_id')
          .eq('id', inst.id)
          .single();

        const existingMeta = ((stuckInst?.metadata ?? {}) as Record<string, unknown>);

        // Cancel the Stripe subscription so the user isn't billed for a VPS
        // that never finished provisioning due to a server restart.
        const subId = stuckInst?.stripe_subscription_id as string | null ?? null;
        if (subId) {
          try {
            await stripe.subscriptions.cancel(subId);
            console.log(`[startup] Cancelled Stripe subscription ${subId} for stuck instance ${inst.id}`);
          } catch (cancelErr: unknown) {
            // already_cancelled / resource_missing are expected — log and continue
            console.warn(
              `[startup] Could not cancel subscription ${subId} for stuck instance ${inst.id}:`,
              cancelErr instanceof Error ? cancelErr.message : String(cancelErr)
            );
          }
        }

        await supabase.from('oriclaw_instances').update({
          status: 'suspended',
          metadata: {
            ...existingMeta,
            error: 'Timeout de provisionamento — servidor não respondeu a tempo.',
            suspended_reason: 'provisioning_timeout',
          }
        }).eq('id', inst.id);
      }
    }
  } catch (err) {
    console.warn('[startup] Could not check for stuck instances:', err);
  }
}

recoverStuckProvisioningInstances();
// Bug fix #3: retry instances stuck in deletion_failed on startup
retryPendingDeletions();

// ── Usage polling — collect per-instance usage from VPS agents ───────────────
const USD_TO_BRL = 5.5;

type CreditUsageEvent = {
  id?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  model?: string | null;
  timestamp?: string;
};

type RunningInstance = {
  id: string;
  customer_id: string;
  droplet_id: number | null;
  droplet_ip: string | null;
  metadata: Record<string, unknown> | null;
};

async function getCustomerCreditBalance(customerId: string): Promise<number> {
  const { data } = await supabase
    .from('oriclaw_credits')
    .select('balance_brl')
    .eq('customer_id', customerId)
    .maybeSingle();

  return (data as { balance_brl: number } | null)?.balance_brl ?? 0;
}

async function acknowledgeUsageEvents(baseUrl: string, agentSecret: string, eventIds: string[]): Promise<void> {
  if (!baseUrl || eventIds.length === 0) return;

  await axios.post(
    `${baseUrl}/usage/ack`,
    { ids: eventIds },
    {
      headers: { 'x-agent-secret': agentSecret, 'Content-Type': 'application/json' },
      timeout: 10_000,
      httpsAgent: agentHttpsAgent,
    }
  );
}

async function collectUsageFromAgents(): Promise<void> {
  try {
    const adminSettings = await getAdminSettings();
    const multiplier = adminSettings?.cost_multiplier ?? 1;
    const defaultModelId = normalizeOpenRouterModelId(adminSettings?.default_model ?? null);

    const { data: instances, error: fetchErr } = await supabase
      .from('oriclaw_instances')
      .select('id, customer_id, droplet_id, droplet_ip, metadata')
      .eq('status', 'running');

    if (fetchErr || !instances) {
      console.warn('[usage-poll] Failed to fetch instances:', fetchErr?.message);
      return;
    }

    const creditsInstances = (instances as RunningInstance[]).filter((inst) => {
      const meta = (inst.metadata ?? {}) as Record<string, unknown>;
      return meta.ai_mode === 'credits';
    });

    if (creditsInstances.length === 0) {
      await notifyCreditStatusForAllCreditsInstances();
      return;
    }

    for (const inst of creditsInstances) {
      const meta = (inst.metadata ?? {}) as Record<string, unknown>;
      const configuredModel = normalizeOpenRouterModelId((meta.model as string | undefined) ?? null);
      const agentSecretEncrypted = meta.agent_secret as string | undefined;
      if (!agentSecretEncrypted) continue;

      let agentSecret: string;
      try {
        agentSecret = decrypt(agentSecretEncrypted);
      } catch {
        continue;
      }

      const baseUrl = await resolveAgentBaseUrl(inst);
      if (!baseUrl) continue;

      try {
        const { data: usageData } = await axios.get(`${baseUrl}/usage/pending`, {
          headers: { 'x-agent-secret': agentSecret },
          timeout: 10_000,
          httpsAgent: agentHttpsAgent,
        });

        const events = Array.isArray(usageData?.events) ? (usageData.events as CreditUsageEvent[]) : [];
        if (events.length === 0) continue;

        const usageByModel = new Map<string, {
          model: string;
          totalTokens: number;
          costUsdRaw: number;
          createdAt: string;
        }>();
        const processedEventIds: string[] = [];

        for (const event of events) {
          const promptTokens = Number(event.prompt_tokens ?? 0);
          const completionTokens = Number(event.completion_tokens ?? 0);
          const totalTokens = promptTokens + completionTokens;
          if (totalTokens <= 0) continue;

          const preferredModel =
            normalizeOpenRouterModelId(event.model ?? null) ??
            configuredModel ??
            defaultModelId;
          if (!preferredModel) continue;

          let costUsdRaw = await calculateOpenRouterCostUsd(preferredModel, promptTokens, completionTokens);
          if (costUsdRaw === null && defaultModelId && preferredModel !== defaultModelId) {
            costUsdRaw = await calculateOpenRouterCostUsd(defaultModelId, promptTokens, completionTokens);
          }
          if (costUsdRaw === null) {
            console.warn(`[usage-poll] Missing pricing for model ${preferredModel} on instance ${inst.id}`);
            continue;
          }

          if (typeof event.id === 'string' && event.id) {
            processedEventIds.push(event.id);
          }

          const bucketKey = preferredModel;
          const existing = usageByModel.get(bucketKey);
          if (existing) {
            existing.totalTokens += totalTokens;
            existing.costUsdRaw += costUsdRaw;
            if (event.timestamp && event.timestamp > existing.createdAt) {
              existing.createdAt = event.timestamp;
            }
          } else {
            usageByModel.set(bucketKey, {
              model: preferredModel,
              totalTokens,
              costUsdRaw,
              createdAt: event.timestamp ?? new Date().toISOString(),
            });
          }
        }

        if (usageByModel.size === 0) continue;

        const usageRows = Array.from(usageByModel.values()).map((entry) => {
          const costUsd = entry.costUsdRaw * multiplier;
          return {
            instance_id: inst.id,
            customer_id: inst.customer_id,
            model: entry.model,
            total_tokens: entry.totalTokens,
            cost_usd: costUsd,
            cost_brl: costUsd * USD_TO_BRL,
            created_at: entry.createdAt,
          };
        });

        const totalCostBrl = usageRows.reduce((sum, row) => sum + row.cost_brl, 0);
        if (totalCostBrl <= 0) {
          if (processedEventIds.length > 0) {
            await acknowledgeUsageEvents(baseUrl, agentSecret, processedEventIds);
          }
          continue;
        }

        let chargedAmountBrl = 0;
        let shouldAckProcessedEvents = false;

        const { data: deducted, error: deductErr } = await supabase.rpc('deduct_credits', {
          p_customer_id: inst.customer_id,
          p_amount: totalCostBrl,
        });

        if (deductErr) {
          console.warn(`[usage-poll] deduct_credits error for ${inst.customer_id}:`, deductErr.message);
          continue;
        }

        if (deducted) {
          chargedAmountBrl = totalCostBrl;
          shouldAckProcessedEvents = true;
        } else {
          const availableBalance = await getCustomerCreditBalance(inst.customer_id);
          const partialAmountBrl = Math.min(Math.max(availableBalance, 0), totalCostBrl);

          if (partialAmountBrl > 0) {
            const { data: partialDeducted, error: partialDeductErr } = await supabase.rpc('deduct_credits', {
              p_customer_id: inst.customer_id,
              p_amount: partialAmountBrl,
            });

            if (partialDeductErr) {
              console.warn(
                `[usage-poll] partial deduct_credits error for ${inst.customer_id}:`,
                partialDeductErr.message
              );
              continue;
            }

            if (!partialDeducted) {
              console.warn(`[usage-poll] Partial deduction race for ${inst.customer_id}; retrying next cycle`);
              continue;
            }

            chargedAmountBrl = partialAmountBrl;
            shouldAckProcessedEvents = true;
            console.warn(
              `[usage-poll] Charged partial balance R$${partialAmountBrl.toFixed(4)} ` +
              `for ${inst.customer_id} on instance ${inst.id}`
            );
          } else {
            shouldAckProcessedEvents = true;
            console.warn(
              `[usage-poll] Balance exhausted before charging ${inst.customer_id} for instance ${inst.id}`
            );
          }
        }

        if (chargedAmountBrl > 0) {
          const chargeRatio = Math.min(chargedAmountBrl / totalCostBrl, 1);
          const chargedUsageRows = usageRows.map((row) => ({
            ...row,
            cost_usd: row.cost_usd * chargeRatio,
            cost_brl: row.cost_brl * chargeRatio,
          }));

          const { error: insertErr } = await supabase.from('oriclaw_token_usage').insert(chargedUsageRows);
          if (insertErr) {
            console.warn(`[usage-poll] Failed to insert usage rows for ${inst.id}:`, insertErr.message);
          } else {
            console.log(
              `[usage-poll] Deducted R$${chargedAmountBrl.toFixed(4)} from ${inst.customer_id} (${inst.id})`
            );
          }
        }

        if (shouldAckProcessedEvents && processedEventIds.length > 0) {
          try {
            await acknowledgeUsageEvents(baseUrl, agentSecret, processedEventIds);
          } catch (ackErr) {
            console.warn(
              `[usage-poll] Failed to acknowledge usage events for ${inst.id}:`,
              ackErr instanceof Error ? ackErr.message : String(ackErr)
            );
          }
        }
      } catch (instErr) {
        console.warn(`[usage-poll] Error processing instance ${inst.id}:`,
          instErr instanceof Error ? instErr.message : String(instErr));
      }
    }

    await notifyCreditStatusForAllCreditsInstances();
  } catch (err) {
    console.error('[usage-poll] Unexpected error:', err instanceof Error ? err.message : String(err));
  }
}

// Run once after 30s delay, then every 60s
setTimeout(collectUsageFromAgents, 30_000);
setInterval(collectUsageFromAgents, 60_000);

app.listen(PORT, () => {
  console.log(`🌀 OriClaw backend running on port ${PORT}`);
});

export default app;
