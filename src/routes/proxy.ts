/**
 * Proxy routes — bridge between the OriClaw dashboard and VPS agents.
 *
 * Auth: expects `Authorization: Bearer <supabase_access_token>`.
 * We validate the token via Supabase admin client and verify that the
 * requested instance belongs to the authenticated user.
 */
import { Router, Request, Response } from 'express';
import axios from 'axios';
import https from 'https';
import path from 'path';
import { supabase } from '../services/supabase';
import { getInstanceById, updateInstance } from '../services/supabase';
import { decrypt, encrypt } from '../services/crypto';
import { getUserId } from '../middleware/requireAuth';
import { getAdminSettings } from '../services/openrouter';

// Accept self-signed TLS certs from VPS agents
const vpsHttpsAgent = new https.Agent({ rejectUnauthorized: false });

const router = Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  const agentSecretEncrypted = (instance.metadata as Record<string, unknown>)?.agent_secret as string | undefined;
  if (!agentSecretEncrypted) {
    throw Object.assign(new Error('Agent secret missing for instance'), { status: 500 });
  }
  let agentSecret: string;
  try {
    agentSecret = decrypt(agentSecretEncrypted);
  } catch {
    throw Object.assign(new Error('Failed to decrypt agent secret'), { status: 500 });
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

  return { instance, baseUrl: `https://${instance.droplet_ip}:8080`, agentSecret };
}

function agentHeaders(secret: string) {
  return { 'x-agent-secret': secret, 'Content-Type': 'application/json' };
}

/** Axios config for VPS agent calls (includes TLS agent for self-signed certs) */
function agentAxiosConfig(secret: string, timeout = 15_000) {
  return { headers: agentHeaders(secret), timeout, httpsAgent: vpsHttpsAgent };
}

// ── Middleware: auth + resolve instance ─────────────────────────────────────
async function withInstance(
  req: Request,
  res: Response,
  handler: (ctx: { baseUrl: string; agentSecret: string; instance: Awaited<ReturnType<typeof getInstanceById>>; userId: string }) => Promise<void>,
  { checkCredits = false } = {}
): Promise<void> {
  // Reject non-UUID instance_id early to avoid PostgreSQL parse errors
  if (!UUID_RE.test(req.params.instance_id)) {
    res.status(400).json({ error: 'ID de instância inválido.' });
    return;
  }
  try {
    const userId = await getUserId(req);
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
      httpsAgent: vpsHttpsAgent,
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
        httpsAgent: vpsHttpsAgent,
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
        httpsAgent: vpsHttpsAgent,
      });

      // Workaround: older VPS agents check `nc -z localhost 18789` which fails
      // when OpenClaw is started with `--bind lan` (listens on public IP, not localhost).
      // If the agent reports available=false but the URL looks valid, verify via health.
      if (data && data.available === false && data.url) {
        try {
          const { data: healthData } = await axios.get(`${baseUrl}/health`, {
            headers: agentHeaders(agentSecret),
            timeout: 5_000,
            httpsAgent: vpsHttpsAgent,
          });
          if (healthData && healthData.openclaw === 'running') {
            data.available = true;
          }
        } catch { /* ignore — keep original available=false */ }
      }

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
        httpsAgent: vpsHttpsAgent,
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

      // Ensure an OpenRouter-compatible model is set for credits mode.
      // Without this, OpenClaw may try to use a previous provider (e.g. "anthropic")
      // which fails because only OPENROUTER_API_KEY is configured.
      // The model format should be "provider/model" (e.g. "minimax/minimax-m2.5")
      // which is the native OpenRouter format — OpenClaw uses OPENROUTER_API_KEY env var
      // to route through OpenRouter automatically.
      if (!body.model) {
        const settings = await getAdminSettings();
        body.model = settings?.default_model ?? 'anthropic/claude-sonnet-4-5';
      }
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

    // Validate language and timezone before forwarding to VPS agent
    const VALID_LANGUAGES = ['pt-BR', 'en-US', 'es-ES', 'fr-FR', 'de-DE', 'it-IT', 'ja-JP', 'zh-CN', 'ar-SA'];
    const TIMEZONE_REGEX = /^[A-Za-z][A-Za-z0-9_\-+/]{1,50}$/;

    if (body.language && !VALID_LANGUAGES.includes(body.language as string)) {
      res.status(400).json({ error: 'Idioma inválido.' });
      return;
    }
    if (body.timezone && !TIMEZONE_REGEX.test(body.timezone as string)) {
      res.status(400).json({ error: 'Fuso horário inválido.' });
      return;
    }

    const auditAiMode = body.credits_mode ? 'credits' : body.chatgpt_mode ? 'chatgpt' : 'byok';
    console.log(`[audit] configure: user=${userId} instance=${instance?.id} ai_mode=${auditAiMode} ip=${req.ip}`);
    supabase.from('oriclaw_audit_log').insert({
      user_id: userId,
      instance_id: instance?.id,
      action: 'configure',
      ip: req.ip,
      metadata: { ai_mode: auditAiMode },
      created_at: new Date().toISOString(),
    }).then(({ error }) => {
      if (error) console.warn('[audit] failed to write to DB:', error.message);
    });

    // Whitelist allowed fields to prevent arbitrary config injection
    const ALLOWED_CONFIGURE_FIELDS = [
      'anthropic_key', 'openai_key', 'google_key', 'openrouter_key',
      'openai_token', 'model', 'assistant_name', 'channel',
      'credits_mode', 'chatgpt_mode', 'system_prompt', 'language', 'timezone',
    ];
    const sanitizedBody: Record<string, unknown> = {};
    for (const key of ALLOWED_CONFIGURE_FIELDS) {
      if (key in body) sanitizedBody[key] = body[key];
    }

    const { data } = await axios.post(`${baseUrl}/configure`, sanitizedBody, {
      headers: agentHeaders(agentSecret),
      timeout: 30_000,
      httpsAgent: vpsHttpsAgent,
    });

    // Persist ai_mode and status in Supabase instance record
    if (instance) {
      // Fetch current metadata to preserve ai_mode when only updating persona/language/timezone
      const { data: existingInstance } = await supabase
        .from('oriclaw_instances')
        .select('metadata')
        .eq('id', instance.id)
        .single();
      const existingMeta = ((existingInstance?.metadata ?? instance.metadata ?? {}) as Record<string, unknown>);
      const existingAiMode = existingMeta.ai_mode as string | undefined;

      const metaUpdates: Record<string, unknown> = { ...existingMeta };

      if (body.credits_mode) {
        metaUpdates.ai_mode = 'credits';
      } else if (body.chatgpt_mode) {
        metaUpdates.ai_mode = 'chatgpt';
      } else if (body.model || body.anthropic_key || body.openai_key || body.google_key || body.openrouter_key) {
        // Explicitly reconfiguring BYOK keys/model — update ai_mode
        metaUpdates.ai_mode = 'byok';
        if (body.model) metaUpdates.model = body.model as string;
      } else {
        // Only updating persona/language/timezone — preserve the existing ai_mode
        if (existingAiMode) metaUpdates.ai_mode = existingAiMode;
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

      // Deduct setup fee when first configuring in credits mode.
      // Per-message deduction is handled in the ai/* route handler.
      if (body.credits_mode) {
        const { data: deducted, error: deductErr } = await supabase.rpc('deduct_credits', {
          p_customer_id: userId,
          p_amount: 0.05,
        });
        if (deductErr || !deducted) {
          console.warn('[proxy/configure] deduct_credits (setup fee) insufficient or error:', deductErr?.message);
          // non-fatal — instance is configured; balance may have already been checked above
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
      httpsAgent: vpsHttpsAgent,
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
      httpsAgent: vpsHttpsAgent,
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
        httpsAgent: vpsHttpsAgent,
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
      httpsAgent: vpsHttpsAgent,
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
      httpsAgent: vpsHttpsAgent,
    });
    res.json(data);
  });
});

// ── DELETE /api/proxy/:instance_id/channels/:channel ─────────────────────────
router.delete('/:instance_id/channels/:channel', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret, instance, userId }) => {
    const channel = req.params.channel;
    const VALID_CHANNELS = ['whatsapp', 'telegram', 'discord'];
    if (!VALID_CHANNELS.includes(channel)) {
      res.status(400).json({ error: 'Canal inválido.' });
      return;
    }
    console.log(`[audit] disconnect: user=${userId} instance=${instance?.id} channel=${channel} ip=${req.ip}`);
    const { data } = await axios.delete(`${baseUrl}/channels/${channel}`, {
      headers: agentHeaders(agentSecret),
      timeout: 15_000,
      httpsAgent: vpsHttpsAgent,
    });
    res.json(data);
  });
});

// ── ALL /api/proxy/:instance_id/* catch-all — forwards AI messages to VPS ────
// Credit check enabled so depleted-balance users can't use credits mode.
// After a successful response, deduct R$0.02 per message for credits-mode users.
//
// SQL function required (with atomic balance guard to prevent going negative):
/*
  CREATE OR REPLACE FUNCTION deduct_credits(p_customer_id uuid, p_amount numeric)
    RETURNS boolean
    LANGUAGE plpgsql AS $$
    DECLARE
      rows_affected integer;
    BEGIN
      UPDATE oriclaw_credits
      SET balance_brl = balance_brl - p_amount, updated_at = now()
      WHERE customer_id = p_customer_id
        AND balance_brl >= p_amount;  -- atomic guard: prevents negative balance

      GET DIAGNOSTICS rows_affected = ROW_COUNT;
      RETURN rows_affected > 0;  -- false = insufficient balance
    END;
  $$;
*/
router.all('/:instance_id/ai/*', async (req: Request, res: Response): Promise<void> => {
  await withInstance(req, res, async ({ baseUrl, agentSecret, instance, userId }) => {
    const rawSubPath = (req.params as Record<string, string>)[0] ?? '';
    const subPath = path.posix.normalize(rawSubPath).replace(/^\/+/, '');
    if (subPath.includes('..')) {
      res.status(400).json({ error: 'Invalid path.' });
      return;
    }
    try {
      const { data } = await axios({
        method: req.method,
        url: `${baseUrl}/ai/${subPath}`,
        headers: { ...agentHeaders(agentSecret) },
        data: req.body,
        timeout: 60_000,
        httpsAgent: vpsHttpsAgent,
      });

      res.json(data);
    } catch (err: unknown) {
      const axErr = err as { response?: { status?: number; data?: unknown } };
      const status = axErr.response?.status ?? 502;
      res.status(status).json(axErr.response?.data ?? { error: 'AI proxy request failed' });
    }
  }, { checkCredits: true });
});

// ── GET /api/proxy/:instance_id/openai-status ────────────────────────────────
// Returns whether the instance has a ChatGPT Plus OAuth token stored.
router.get('/:instance_id/openai-status', async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = await getUserId(req);
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
