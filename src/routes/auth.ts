/**
 * Auth routes — OpenAI API Key storage for ChatGPT/GPT-4 integration.
 *
 * NOTE: The original OAuth flow using https://auth.openai.com/authorize and
 * https://auth.openai.com/oauth/token was removed because OpenAI does NOT
 * offer public OAuth for ChatGPT Plus subscribers. Those endpoints do not exist.
 *
 * Replacement flow (BYOK — Bring Your Own Key):
 *  1. User enters their OpenAI API key in the dashboard
 *  2. Dashboard calls POST /api/auth/openai/key → key encrypted and stored in Supabase
 *  3. Dashboard calls POST /api/proxy/:id/configure (chatgpt_mode: true) → VPS configured
 */
import { Router, Request, Response } from 'express';
import axios from 'axios';
import { getInstanceById, getInstanceByCustomerId, updateInstance, supabase } from '../services/supabase';
import { encrypt } from '../services/crypto';

const router = Router();

// ── Auth helper ──────────────────────────────────────────────────────────────
async function getUserId(req: Request): Promise<string | null> {
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user.id;
}

// ── POST /api/auth/openai/key ────────────────────────────────────────────────
// Receives an OpenAI API key, encrypts it, and stores it in the instance metadata.
// Body: { instance_id: string, api_key: string }
router.post('/openai/key', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) {
    res.status(401).json({ error: 'Autenticação obrigatória.' });
    return;
  }

  const { instance_id, api_key } = (req.body ?? {}) as { instance_id?: string; api_key?: string };

  if (!instance_id || !api_key) {
    res.status(400).json({ error: 'instance_id e api_key são obrigatórios.' });
    return;
  }

  // Basic API key format validation (sk-... or sk-proj-...)
  if (!api_key.startsWith('sk-') || api_key.length < 20) {
    res.status(400).json({ error: 'Chave de API OpenAI inválida. Deve começar com "sk-".' });
    return;
  }

  // Test the key against the OpenAI API to verify it actually works
  try {
    const testRes = await axios.get('https://api.openai.com/v1/models', {
      headers: { 'Authorization': `Bearer ${api_key}` },
      timeout: 5000,
    });
    if (testRes.status !== 200) {
      res.status(400).json({ error: 'API Key OpenAI inválida ou sem permissão.' });
      return;
    }
  } catch (err: unknown) {
    const axErr = err as { response?: { status?: number } };
    if (axErr.response?.status === 401) {
      res.status(400).json({ error: 'API Key OpenAI inválida. Verifique a chave e tente novamente.' });
      return;
    }
    // Other errors (network timeout, etc.) — allow the key to be saved.
    // Do NOT log the raw error object — axios error includes config.headers.Authorization
    // which would expose the API key in plaintext in server logs.
    const safeMsg = err instanceof Error ? err.message : String(err);
    console.warn('[auth/openai] key validation test failed (non-fatal):', safeMsg);
  }

  // Ownership check — prevent IDOR write
  const ownedInstance = await getInstanceByCustomerId(userId);
  if (!ownedInstance || ownedInstance.id !== instance_id) {
    res.status(403).json({ error: 'Acesso negado.' });
    return;
  }

  const instance = await getInstanceById(instance_id);
  if (!instance) {
    res.status(404).json({ error: 'Instância não encontrada.' });
    return;
  }

  try {
    const encryptedKey = encrypt(api_key);
    const existingMeta = (instance.metadata ?? {}) as Record<string, unknown>;
    await updateInstance(instance_id, {
      metadata: {
        ...existingMeta,
        chatgpt_connected: true,
        openai_api_key_encrypted: encryptedKey,
        // Remove any legacy OAuth fields if present
        openai_access_token_encrypted: undefined,
        openai_access_token: undefined,
      },
    });

    console.log(`[auth/openai/key] API key stored for instance=${instance_id} user=${userId}`);
    res.json({ success: true });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to store API key';
    console.error('[auth/openai/key]', msg);
    res.status(500).json({ error: msg });
  }
});

// ── GET /api/auth/openai/status/:instance_id ─────────────────────────────────
// Returns whether the instance has an OpenAI API key stored.
// (Kept for backwards compatibility with polling logic in the dashboard)
router.get('/openai/status/:instance_id', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) { res.status(401).json({ error: 'Não autorizado.' }); return; }

  const instance = await getInstanceById(req.params.instance_id);
  if (!instance || instance.customer_id !== userId) {
    res.status(403).json({ error: 'Acesso negado.' }); return;
  }

  const meta = (instance.metadata ?? {}) as Record<string, unknown>;
  res.json({ connected: !!meta.chatgpt_connected });
});

export default router;
