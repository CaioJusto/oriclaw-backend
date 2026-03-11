import 'dotenv/config';
import express, { Request as ExpressRequest } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import webhookRoutes from './routes/webhooks';
import instanceRoutes from './routes/instances';
import proxyRoutes from './routes/proxy';
import creditsRoutes from './routes/credits';
import authRoutes from './routes/auth';
import checkoutRoutes from './routes/checkout';
import billingRoutes from './routes/billing';
import { supabase } from './services/supabase';

// ── Required environment variable validation ──────────────────────────────────
const REQUIRED_ENV_VARS = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'DO_API_TOKEN',
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'ENCRYPTION_KEY',
  'ORICLAW_OPENROUTER_KEY',
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

// ── Rate limiting ────────────────────────────────────────────────────────────
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
}));

// ── Body parsing ─────────────────────────────────────────────────────────────
// Stripe webhooks need raw body for signature verification
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));

// All other routes use JSON
app.use(express.json());

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'oriclaw-backend', ts: new Date().toISOString() });
});

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
  console.error('[unhandled]', err.message);
  res.status(500).json({ error: err.message });
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
      for (const inst of stuck) {
        await supabase.from('oriclaw_instances').update({
          status: 'suspended',
          metadata: { error: 'Timeout de provisionamento — servidor não respondeu a tempo.' }
        }).eq('id', inst.id);
      }
    }
  } catch (err) {
    console.warn('[startup] Could not check for stuck instances:', err);
  }
}

recoverStuckProvisioningInstances();

app.listen(PORT, () => {
  console.log(`🌀 OriClaw backend running on port ${PORT}`);
});

export default app;
