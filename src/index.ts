import 'dotenv/config';
import express from 'express';
import webhookRoutes from './routes/webhooks';
import instanceRoutes from './routes/instances';

const app = express();
const PORT = process.env.PORT ?? 3001;

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
