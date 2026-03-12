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
import { supabase } from './services/supabase';
import { retryPendingDeletions } from './services/provisioning';

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
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
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
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, { apiVersion: '2023-10-16' });

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

app.listen(PORT, () => {
  console.log(`🌀 OriClaw backend running on port ${PORT}`);
});

export default app;
