/**
 * Auth routes — OpenAI OAuth flow for ChatGPT Plus integration.
 *
 * Flow:
 *  1. Dashboard calls GET /api/auth/openai/url/:instance_id → gets OAuth URL
 *  2. User is redirected to OpenAI to approve access
 *  3. OpenAI redirects to APP_URL/auth/openai/callback?code=X&state=instance_id
 *  4. Callback page calls POST /api/auth/openai/exchange → token stored in Supabase
 *  5. Dashboard polls GET /api/proxy/:instance_id/openai-status until connected
 */
import { Router, Request, Response } from 'express';
import axios from 'axios';
import { getInstanceById, getInstanceByCustomerId, updateInstance, supabase } from '../services/supabase';
import { encrypt } from '../services/crypto';

const router = Router();

const OPENAI_CLIENT_ID = process.env.OPENAI_CLIENT_ID ?? '';
const OPENAI_CLIENT_SECRET = process.env.OPENAI_CLIENT_SECRET ?? '';
const APP_URL = process.env.APP_URL ?? 'https://oriclaw.com.br';

// ── Auth helper ──────────────────────────────────────────────────────────────
async function getUserId(req: Request): Promise<string | null> {
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user.id;
}

// ── GET /api/auth/openai/url/:instance_id ────────────────────────────────────
// Returns the OpenAI OAuth authorization URL.
router.get('/openai/url/:instance_id', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) { res.status(401).json({ error: 'Unauthorized' }); return; }

  const instance = await getInstanceById(req.params.instance_id);
  if (!instance || instance.customer_id !== userId) {
    res.status(403).json({ error: 'Forbidden' }); return;
  }

  if (!OPENAI_CLIENT_ID) {
    res.status(500).json({ error: 'OpenAI OAuth not configured on server' }); return;
  }

  const redirectUri = `${APP_URL}/auth/openai/callback`;
  const state = req.params.instance_id;

  const url = [
    'https://auth.openai.com/authorize',
    `?client_id=${encodeURIComponent(OPENAI_CLIENT_ID)}`,
    `&redirect_uri=${encodeURIComponent(redirectUri)}`,
    `&response_type=code`,
    `&scope=openid+email+profile`,
    `&state=${encodeURIComponent(state)}`,
  ].join('');

  res.json({ url });
});

// ── POST /api/auth/openai/exchange ───────────────────────────────────────────
// Exchanges an authorization code for an OpenAI access token and stores it
// in the instance metadata so the configure route can inject it into the VPS.
// Body: { code: string, instance_id: string, redirect_uri?: string }
router.post('/openai/exchange', async (req: Request, res: Response): Promise<void> => {
  const { code, instance_id, redirect_uri } = req.body as {
    code?: string;
    instance_id?: string;
    redirect_uri?: string;
  };

  if (!code || !instance_id) {
    res.status(400).json({ error: 'Missing code or instance_id' }); return;
  }

  // Ownership check — prevent IDOR write
  const userId = await getUserId(req);
  if (!userId) {
    res.status(401).json({ error: 'Autenticação obrigatória.' });
    return;
  }

  const ownedInstance = await getInstanceByCustomerId(userId);
  if (!ownedInstance || ownedInstance.id !== instance_id) {
    res.status(403).json({ error: 'Acesso negado.' });
    return;
  }

  if (!OPENAI_CLIENT_ID || !OPENAI_CLIENT_SECRET) {
    res.status(500).json({ error: 'OpenAI OAuth credentials not configured on server' }); return;
  }

  const callbackUri = redirect_uri ?? `${APP_URL}/auth/openai/callback`;

  try {
    // Exchange code for access token
    const tokenRes = await axios.post<{ access_token: string; token_type: string }>(
      'https://auth.openai.com/oauth/token',
      {
        client_id: OPENAI_CLIENT_ID,
        client_secret: OPENAI_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: callbackUri,
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 15_000 }
    );

    const { access_token } = tokenRes.data;

    // Store token in Supabase instance metadata (encrypted)
    const instance = await getInstanceById(instance_id);
    if (!instance) { res.status(404).json({ error: 'Instância não encontrada.' }); return; }

    const encryptedToken = encrypt(access_token);
    const existingMeta = (instance.metadata ?? {}) as Record<string, unknown>;
    // Remove plaintext token if present
    const { openai_access_token: _plaintext, ...cleanMeta } = existingMeta as Record<string, unknown> & { openai_access_token?: unknown };
    await updateInstance(instance_id, {
      metadata: {
        ...cleanMeta,
        chatgpt_connected: true,
        openai_access_token_encrypted: encryptedToken,
      },
    });

    res.json({ success: true });
  } catch (err: unknown) {
    console.error('[openai/exchange]', err);
    const axErr = err as { response?: { data?: unknown; status?: number } };
    const detail = axErr.response?.data ?? (err instanceof Error ? err.message : 'OAuth exchange failed');
    res.status(axErr.response?.status ?? 500).json({ error: detail });
  }
});

export default router;
