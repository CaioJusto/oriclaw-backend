/**
 * Proxy routes — bridge between the OriClaw dashboard and VPS agents.
 *
 * Auth: expects `Authorization: Bearer <supabase_access_token>`.
 * We validate the token via Supabase admin client and verify that the
 * requested instance belongs to the authenticated user.
 */
import { Router, Request, Response } from 'express';
import axios from 'axios';
import { supabase } from '../services/supabase';
import { getInstanceById, updateInstance } from '../services/supabase';

const router = Router();

// ── Auth helper ──────────────────────────────────────────────────────────────
async function getUserFromRequest(req: Request): Promise<string | null> {
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user.id;
}

// ── Instance ownership check + VPS URL builder ──────────────────────────────
async function resolveInstance(instanceId: string, userId: string) {
  const instance = await getInstanceById(instanceId);
  if (!instance) throw Object.assign(new Error('Instance not found'), { status: 404 });
  if (instance.customer_id !== userId) {
    throw Object.assign(new Error('Forbidden'), { status: 403 });
  }
  if (!instance.droplet_ip) {
    throw Object.assign(new Error('Instance not ready — no IP yet'), { status: 503 });
  }
  const agentSecret = (instance.metadata as Record<string, unknown>)?.agent_secret as string | undefined;
  if (!agentSecret) {
    throw Object.assign(new Error('Agent secret missing for instance'), { status: 500 });
  }
  return { instance, baseUrl: `http://${instance.droplet_ip}:8080`, agentSecret };
}

function agentHeaders(secret: string) {
  return { 'x-agent-secret': secret, 'Content-Type': 'application/json' };
}

// ── Middleware: auth + resolve instance ─────────────────────────────────────
async function withInstance(
  req: Request,
  res: Response,
  handler: (ctx: { baseUrl: string; agentSecret: string; instance: Awaited<ReturnType<typeof getInstanceById>> }) => Promise<void>
): Promise<void> {
  try {
    const userId = await getUserFromRequest(req);
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const ctx = await resolveInstance(req.params.instance_id, userId);
    await handler(ctx);
  } catch (err: unknown) {
    const e = err as Error & { status?: number };
    const status = e.status ?? 500;
    console.error(`[proxy] ${status} ${e.message}`);
    res.status(status).json({ error: e.message });
  }
}

// ── GET /api/proxy/:instance_id/health ───────────────────────────────────────
router.get('/:instance_id/health', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    const { data } = await axios.get(`${baseUrl}/health`, {
      headers: agentHeaders(agentSecret),
      timeout: 10_000,
    });
    res.json(data);
  });
});

// ── GET /api/proxy/:instance_id/qr ──────────────────────────────────────────
router.get('/:instance_id/qr', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    try {
      const { data } = await axios.get(`${baseUrl}/qr`, {
        headers: agentHeaders(agentSecret),
        timeout: 15_000,
      });
      res.json(data);
    } catch (err: unknown) {
      const axErr = err as { response?: { status?: number; data?: unknown } };
      const status = axErr.response?.status ?? 502;
      res.status(status).json(axErr.response?.data ?? { error: 'QR fetch failed' });
    }
  });
});

// ── POST /api/proxy/:instance_id/configure ──────────────────────────────────
router.post('/:instance_id/configure', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret, instance }) => {
    const { data } = await axios.post(`${baseUrl}/configure`, req.body, {
      headers: agentHeaders(agentSecret),
      timeout: 30_000,
    });

    // Mark instance as running after successful configuration
    if (instance) {
      await updateInstance(instance.id, { status: 'running' });
    }

    res.json(data);
  });
});

// ── POST /api/proxy/:instance_id/restart ────────────────────────────────────
router.post('/:instance_id/restart', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    const { data } = await axios.post(`${baseUrl}/restart`, {}, {
      headers: agentHeaders(agentSecret),
      timeout: 30_000,
    });
    res.json(data);
  });
});

// ── GET /api/proxy/:instance_id/logs ─────────────────────────────────────────
router.get('/:instance_id/logs', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    const { data } = await axios.get(`${baseUrl}/logs`, {
      headers: agentHeaders(agentSecret),
      timeout: 15_000,
    });
    res.json(data);
  });
});

export default router;
