import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import webhookRoutes from './routes/webhooks';
import instanceRoutes from './routes/instances';
import proxyRoutes from './routes/proxy';
import creditsRoutes from './routes/credits';
import authRoutes from './routes/auth';

const app = express();
const PORT = process.env.PORT ?? 3001;

// CORS — allow dashboard origins
app.use(cors({
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : '*',
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-secret'],
}));

// Stripe webhooks need raw body for signature verification
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));

// All other routes use JSON
app.use(express.json());

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'oriclaw-backend', ts: new Date().toISOString() });
});

// Routes
app.use('/webhooks', webhookRoutes);
app.use('/api/instances', instanceRoutes);
app.use('/api/proxy', proxyRoutes);
app.use('/api/credits', creditsRoutes);
app.use('/api/auth', authRoutes);

// 404 fallback
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[unhandled]', err.message);
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log(`🌀 OriClaw backend running on port ${PORT}`);
});

export default app;
