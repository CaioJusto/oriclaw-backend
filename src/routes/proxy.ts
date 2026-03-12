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
import { decrypt, encrypt } from '../services/crypto';

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
async function resolveInstance(instanceId: string, userId: string, checkCredits = false) {
  const instance = await getInstanceById(instanceId);
  if (!instance) throw Object.assign(new Error('Instância não encontrada.'), { status: 404 });
  if (instance.customer_id !== userId) {
    throw Object.assign(new Error('Acesso negado.'), { status: 403 });
  }
  if (['suspended', 'deleted', 'deletion_failed'].includes(instance.status)) {
    throw Object.assign(
      new Error('Instância suspensa ou cancelada. Acesse o dashboard para regularizar.'),
      { status: 403 }
    );
  }
  if (!instance.droplet_ip) {
    throw Object.assign(new Error('Servidor ainda inicializando. Tente novamente em alguns minutos.'), { status: 503 });
  }
  const agentSecret = (instance.metadata as Record<string, unknown>)?.agent_secret as string | undefined;
  if (!agentSecret) {
    throw Object.assign(new Error('Agent secret missing for instance'), { status: 500 });
  }

  // ── Bug fix #5: Block proxy requests when credits balance is depleted ──────
  if (checkCredits) {
    const meta = (instance.metadata ?? {}) as Record<string, unknown>;
    if (meta.ai_mode === 'credits') {
      const { data: creditsRow } = await supabase
        .from('oriclaw_credits')
        .select('balance_brl')
        .eq('customer_id', userId)
        .maybeSingle();
      const balance = (creditsRow as { balance_brl: number } | null)?.balance_brl ?? 0;
      if (balance <= 0) {
        throw Object.assign(
          new Error('Saldo insuficiente. Recarregue seus créditos.'),
          { status: 402 }
        );
      }
    }
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
  handler: (ctx: { baseUrl: string; agentSecret: string; instance: Awaited<ReturnType<typeof getInstanceById>>; userId: string }) => Promise<void>,
  { checkCredits = false } = {}
): Promise<void> {
  try {
    const userId = await getUserFromRequest(req);
    if (!userId) {
      res.status(401).json({ error: 'Não autorizado. Faça login novamente.' });
      return;
    }
    const ctx = await resolveInstance(req.params.instance_id, userId, checkCredits);
    await handler({ ...ctx, userId });
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
  const MAX_SYSTEM_PROMPT_BYTES = 8_000;
  if (typeof req.body.system_prompt === 'string' &&
      Buffer.byteLength(req.body.system_prompt, 'utf8') > MAX_SYSTEM_PROMPT_BYTES) {
    res.status(413).json({ error: `system_prompt excede o limite de ${MAX_SYSTEM_PROMPT_BYTES} bytes (8KB).` });
    return;
  }

  await withInstance(req, res, async ({ baseUrl, agentSecret, instance, userId }) => {
    const body = { ...req.body } as Record<string, unknown>;

    // ── Bug fix #5: Credits mode — enforce balance check before configuring ──
    if (body.credits_mode) {
      const { data: creditsRow } = await supabase
        .from('oriclaw_credits')
        .select('balance_brl')
        .eq('customer_id', userId)
        .maybeSingle();
      const balance = (creditsRow as { balance_brl: number } | null)?.balance_brl ?? 0;
      if (balance <= 0) {
        res.status(402).json({ error: 'Saldo insuficiente. Recarregue seus créditos.' });
        return;
      }

      // Inject ORICLAW_OPENROUTER_KEY server-side when credits mode is requested
      const orKey = process.env.ORICLAW_OPENROUTER_KEY;
      if (!orKey) {
        res.status(500).json({ error: 'OriClaw OpenRouter key not configured on server' });
        return;
      }
      body.openrouter_key = orKey;
    }

    // Inject stored Anthropic API key (decrypted) if not provided by client and instance has one
    if (
      !body.anthropic_key &&
      !body.openai_key &&
      !body.google_key &&
      !body.openrouter_key &&
      !body.credits_mode &&
      !body.chatgpt_mode
    ) {
      const storedKey = (instance as { api_key_encrypted?: string | null })?.api_key_encrypted;
      if (storedKey) {
        try {
          body.anthropic_key = decrypt(storedKey);
        } catch (decryptErr) {
          console.error('[proxy/configure] Failed to decrypt stored API key:', decryptErr);
          res.status(500).json({ error: 'Falha ao decriptar API key armazenada. Por favor, reconfigure sua chave de API.' });
          return;
        }
      }
    }

    // ── Bug fix #2: ChatGPT mode now uses stored API key (not OAuth token) ──
    if (body.chatgpt_mode) {
      const meta = (instance?.metadata ?? {}) as Record<string, unknown>;
      // Support new api_key_encrypted field (BYOK) and legacy OAuth token field
      const encryptedKey = (meta.openai_api_key_encrypted ?? meta.openai_access_token_encrypted) as string | undefined;
      if (!encryptedKey) {
        res.status(400).json({ error: 'Chave OpenAI não configurada. Adicione sua API key OpenAI primeiro.' });
        return;
      }
      try {
        body.openai_key = decrypt(encryptedKey);
      } catch (decryptErr) {
        console.error('[proxy/configure] Failed to decrypt OpenAI key:', decryptErr);
        res.status(500).json({ error: 'Falha ao decriptar chave OpenAI. Reconfigure sua API key.' });
        return;
      }
    }

    console.log(`[audit] configure: user=${userId} instance=${instance?.id} ai_mode=${body.credits_mode ? 'credits' : 'byok'} ip=${req.ip}`);

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

      // Persist API key (encrypted) if a user-supplied key was provided
      const keyToStore = (body.anthropic_key ?? body.openai_key ?? body.google_key ?? body.openrouter_key) as string | undefined;
      if (!body.credits_mode && !body.chatgpt_mode && keyToStore && typeof keyToStore === 'string') {
        try {
          const encrypted = encrypt(keyToStore);
          await updateInstance(instance.id, { api_key_encrypted: encrypted });
        } catch (cryptoErr) {
          console.warn('[proxy/configure] Failed to persist API key:', cryptoErr);
          // Non-fatal — continua
        }
      }

      // ── Bug fix #5: Deduct a small setup credit when configuring in credits mode ─
      // Ongoing per-message deduction is handled via the Supabase RPC deduct_credits.
      // SQL function: CREATE OR REPLACE FUNCTION deduct_credits(p_user_id uuid, p_amount numeric)
      //   RETURNS void LANGUAGE plpgsql AS $$ BEGIN
      //     UPDATE oriclaw_credits SET balance_brl = balance_brl - p_amount WHERE user_id = p_user_id;
      //   END; $$;
      if (body.credits_mode) {
        try {
          await supabase.rpc('deduct_credits', { p_user_id: userId, p_amount: 0.05 });
        } catch (deductErr) {
          console.warn('[proxy/configure] Failed to deduct credits (non-fatal):', deductErr);
        }
      }
    }

    res.json(data);
  });
});

// ── POST /api/proxy/:instance_id/restart ────────────────────────────────────
router.post('/:instance_id/restart', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret, instance, userId }) => {
    console.log(`[audit] restart: user=${userId} instance=${instance?.id} ip=${req.ip}`);
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
  await withInstance(req, res, async ({ baseUrl, agentSecret, instance, userId }) => {
    const channel = req.params.channel;
    console.log(`[audit] disconnect: user=${userId} instance=${instance?.id} channel=${channel} ip=${req.ip}`);
    const { data } = await axios.delete(`${baseUrl}/channels/${channel}`, {
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
    if (!userId) { res.status(401).json({ error: 'Não autorizado. Faça login novamente.' }); return; }

    const instance = await getInstanceById(req.params.instance_id);
    if (!instance || instance.customer_id !== userId) {
      res.status(403).json({ error: 'Acesso negado.' }); return;
    }

    const meta = (instance.metadata ?? {}) as Record<string, unknown>;
    res.json({ connected: !!meta.chatgpt_connected });
  } catch (err: unknown) {
    const e = err as Error;
    res.status(500).json({ error: e.message });
  }
});

export default router;
