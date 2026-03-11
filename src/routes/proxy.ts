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

// ── GET /api/proxy/:instance_id/health/detailed ──────────────────────────────
router.get('/:instance_id/health/detailed', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    try {
      const { data } = await axios.get(`${baseUrl}/health/detailed`, {
        headers: agentHeaders(agentSecret),
        timeout: 15_000,
      });
      res.json(data);
    } catch (err: unknown) {
      const axErr = err as { response?: { status?: number; data?: unknown } };
      const status = axErr.response?.status ?? 502;
      res.status(status).json(axErr.response?.data ?? { error: 'Health detailed fetch failed' });
    }
  });
});

// ── GET /api/proxy/:instance_id/chat-url ─────────────────────────────────────
router.get('/:instance_id/chat-url', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    try {
      const { data } = await axios.get(`${baseUrl}/chat-url`, {
        headers: agentHeaders(agentSecret),
        timeout: 10_000,
      });
      res.json(data);
    } catch (err: unknown) {
      const axErr = err as { response?: { status?: number; data?: unknown } };
      const status = axErr.response?.status ?? 502;
      res.status(status).json(axErr.response?.data ?? { error: 'Chat URL fetch failed' });
    }
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
    const body = { ...req.body } as Record<string, unknown>;

    // Inject ORICLAW_OPENROUTER_KEY server-side when credits mode is requested
    if (body.credits_mode) {
      const orKey = process.env.ORICLAW_OPENROUTER_KEY;
      if (!orKey) {
        res.status(500).json({ error: 'OriClaw OpenRouter key not configured on server' });
        return;
      }
      body.openrouter_key = orKey;
    }

    // Inject stored OpenAI OAuth token when ChatGPT Plus mode is requested
    if (body.chatgpt_mode) {
      const meta = (instance?.metadata ?? {}) as Record<string, unknown>;
      if (!meta.openai_access_token) {
        res.status(400).json({ error: 'ChatGPT Plus not connected yet. Complete OAuth first.' });
        return;
      }
      body.openai_token = meta.openai_access_token as string;
    }

    const { data } = await axios.post(`${baseUrl}/configure`, body, {
      headers: agentHeaders(agentSecret),
      timeout: 30_000,
    });

    // Persist ai_mode and status in Supabase instance record
    if (instance) {
      const existingMeta = (instance.metadata ?? {}) as Record<string, unknown>;
      const metaUpdates: Record<string, unknown> = { ...existingMeta };
      if (body.credits_mode) {
        metaUpdates.ai_mode = 'credits';
      } else if (body.chatgpt_mode) {
        metaUpdates.ai_mode = 'chatgpt';
      } else {
        metaUpdates.ai_mode = 'byok';
        if (body.model) metaUpdates.model = body.model as string;
      }
      await updateInstance(instance.id, { status: 'running', metadata: metaUpdates });
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

// ── GET /api/proxy/:instance_id/channels ─────────────────────────────────────
router.get('/:instance_id/channels', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    try {
      const { data } = await axios.get(`${baseUrl}/channels`, {
        headers: agentHeaders(agentSecret),
        timeout: 10_000,
      });
      res.json(data);
    } catch (err: unknown) {
      const axErr = err as { response?: { status?: number; data?: unknown } };
      const status = axErr.response?.status ?? 502;
      res.status(status).json(axErr.response?.data ?? { error: 'Channels fetch failed' });
    }
  });
});

// ── POST /api/proxy/:instance_id/channels/telegram ───────────────────────────
router.post('/:instance_id/channels/telegram', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    const { data } = await axios.post(`${baseUrl}/channels/telegram`, req.body, {
      headers: agentHeaders(agentSecret),
      timeout: 30_000,
    });
    res.json(data);
  });
});

// ── POST /api/proxy/:instance_id/channels/discord ────────────────────────────
router.post('/:instance_id/channels/discord', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    const { data } = await axios.post(`${baseUrl}/channels/discord`, req.body, {
      headers: agentHeaders(agentSecret),
      timeout: 30_000,
    });
    res.json(data);
  });
});

// ── DELETE /api/proxy/:instance_id/channels/:channel ─────────────────────────
router.delete('/:instance_id/channels/:channel', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret }) => {
    const { data } = await axios.delete(`${baseUrl}/channels/${req.params.channel}`, {
      headers: agentHeaders(agentSecret),
      timeout: 15_000,
    });
    res.json(data);
  });
});

// ── GET /api/proxy/:instance_id/openai-status ────────────────────────────────
// Returns whether the instance has a ChatGPT Plus OAuth token stored.
router.get('/:instance_id/openai-status', async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = await getUserFromRequest(req);
    if (!userId) { res.status(401).json({ error: 'Unauthorized' }); return; }

    const instance = await getInstanceById(req.params.instance_id);
    if (!instance || instance.customer_id !== userId) {
      res.status(403).json({ error: 'Forbidden' }); return;
    }

    const meta = (instance.metadata ?? {}) as Record<string, unknown>;
    res.json({ connected: !!meta.chatgpt_connected });
  } catch (err: unknown) {
    const e = err as Error;
    res.status(500).json({ error: e.message });
  }
});

export default router;
