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
import crypto from 'crypto';
import axios from 'axios';
import { getInstanceById, getInstanceByCustomerId, updateInstance } from '../services/supabase';
import { encrypt, decrypt } from '../services/crypto';
import { getUserId } from '../middleware/requireAuth';
import { resolveAgentTransport } from '../services/agentNetwork';

const router = Router();
type OpenAIValidationStatus = 'verified' | 'saved_unverified';

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

  let validationStatus: OpenAIValidationStatus = 'verified';
  let validationWarning: string | null = null;

  // Test the key against the OpenAI API to verify it actually works
  try {
    const testRes = await axios.get('https://api.openai.com/v1/models', {
      headers: { 'Authorization': `Bearer ${api_key}` },
      timeout: 10_000,
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
    validationStatus = 'saved_unverified';
    validationWarning = safeMsg;
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
        chatgpt_connected: validationStatus === 'verified' || !!existingMeta.chatgpt_connected,
        openai_key_saved: true,
        openai_key_validation_status: validationStatus,
        openai_key_validation_error: validationStatus === 'saved_unverified' ? validationWarning : undefined,
        openai_key_validated_at: validationStatus === 'verified'
          ? new Date().toISOString()
          : (existingMeta.openai_key_validated_at ?? undefined),
        openai_api_key_encrypted: encryptedKey,
        // Remove any legacy OAuth fields if present
        openai_access_token_encrypted: undefined,
        openai_access_token: undefined,
      },
    });

    console.log(`[auth/openai/key] API key stored for instance=${instance_id} user=${userId}`);
    res.json({
      success: true,
      connected: validationStatus === 'verified',
      key_saved: true,
      validation_status: validationStatus,
      warning: validationWarning,
    });
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
  res.json({
    connected: !!meta.chatgpt_connected,
    key_saved: !!meta.openai_api_key_encrypted || !!meta.openai_key_saved,
    validation_status: (meta.openai_key_validation_status as string | undefined) ?? null,
  });
});

// ── POST /api/auth/openai-codex/init ──────────────────────────────────────────
// Starts the OpenRouter OAuth PKCE flow for ChatGPT subscription via Codex.
// Returns the auth_url the frontend should open in a popup/new tab.
router.post('/openai-codex/init', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) { res.status(401).json({ error: 'Não autorizado.' }); return; }

  const instance = await getInstanceByCustomerId(userId);
  if (!instance) { res.status(404).json({ error: 'Instância não encontrada.' }); return; }

  const callbackUrl = `${process.env.APP_URL}/auth/openai-codex/callback`;

  // Generate PKCE code_verifier and code_challenge (S256)
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Store encrypted code_verifier in instance metadata for the exchange step
  const existingMeta = (instance.metadata ?? {}) as Record<string, unknown>;
  await updateInstance(instance.id, {
    metadata: { ...existingMeta, codex_code_verifier: encrypt(codeVerifier) },
  });

  const authUrl = `https://openrouter.ai/auth?callback_url=${encodeURIComponent(callbackUrl)}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  console.log(`[auth/codex/init] OAuth flow started for instance=${instance.id} user=${userId}`);
  res.json({ auth_url: authUrl });
});

// ── POST /api/auth/openai-codex/exchange ──────────────────────────────────────
// Receives the authorization code from the OpenRouter callback, exchanges it
// for an API key, then sends the key to the VPS agent to configure Codex.
router.post('/openai-codex/exchange', async (req: Request, res: Response): Promise<void> => {
  const userId = await getUserId(req);
  if (!userId) { res.status(401).json({ error: 'Não autorizado.' }); return; }

  const { code } = (req.body ?? {}) as { code?: string };
  if (!code) { res.status(400).json({ error: 'code é obrigatório.' }); return; }

  const instance = await getInstanceByCustomerId(userId);
  if (!instance) { res.status(404).json({ error: 'Instância não encontrada.' }); return; }

  const meta = (instance.metadata ?? {}) as Record<string, unknown>;
  const codeVerifierEnc = meta.codex_code_verifier as string | undefined;
  if (!codeVerifierEnc) {
    res.status(400).json({ error: 'Fluxo OAuth não iniciado. Tente novamente.' });
    return;
  }

  let codeVerifier: string;
  try { codeVerifier = decrypt(codeVerifierEnc); } catch {
    res.status(500).json({ error: 'Falha ao recuperar code_verifier.' }); return;
  }

  try {
    // Exchange code + code_verifier for an API key at OpenRouter
    const { data: exchangeData } = await axios.post('https://openrouter.ai/api/v1/auth/keys', {
      code,
      code_verifier: codeVerifier,
      code_challenge_method: 'S256',
    }, { timeout: 15_000 });

    const apiKey = exchangeData?.key;
    if (!apiKey) {
      res.status(500).json({ error: 'OpenRouter não retornou uma chave.' });
      return;
    }

    // Send OAuth data to VPS agent
    const agentSecretEnc = meta.agent_secret as string | undefined;
    if (!agentSecretEnc) {
      res.status(500).json({ error: 'Instância sem agent configurado.' });
      return;
    }

    const agentSecret = decrypt(agentSecretEnc);
    const transport = await resolveAgentTransport(instance, agentSecret);
    if (!transport) {
      res.status(500).json({ error: 'Instância sem agent configurado.' });
      return;
    }

    await axios.post(
      `${transport.baseUrl}/configure-codex-oauth`,
      { oauth_data: { key: apiKey, provider: 'openai-codex' } },
      {
        headers: { 'x-agent-secret': agentSecret, 'Content-Type': 'application/json' },
        timeout: 30_000,
        httpsAgent: transport.httpsAgent,
      }
    );

    // Update instance metadata — mark ChatGPT as connected, cleanup verifier
    await updateInstance(instance.id, {
      metadata: {
        ...meta,
        ai_mode: 'chatgpt',
        chatgpt_connected: true,
        openai_key_saved: true,
        openai_key_validation_status: 'verified',
        openai_key_validation_error: undefined,
        openai_key_validated_at: new Date().toISOString(),
        codex_code_verifier: undefined,
      },
    });

    console.log(`[auth/codex/exchange] Codex OAuth completed for instance=${instance.id} user=${userId}`);
    res.json({ success: true });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'OAuth exchange failed';
    console.error('[auth/codex/exchange]', msg);
    res.status(500).json({ error: msg });
  }
});

export default router;
