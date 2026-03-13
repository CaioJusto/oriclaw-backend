import { Request, Response, NextFunction } from 'express';
// Bug fix #8: use the shared Supabase singleton instead of creating a second client
import { supabase } from '../services/supabase';
import { OriClawInstance } from '../types';

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Não autorizado. Faça login novamente.' });
    return;
  }
  const token = authHeader.slice(7);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    res.status(401).json({ error: 'Não autorizado. Faça login novamente.' });
    return;
  }
  req.user = { id: user.id, email: user.email ?? undefined };
  next();
}

/**
 * Shared auth helper — extracts user ID from Bearer token.
 * Used by routes that don't use requireAuth middleware.
 */
export async function getUserId(req: Request): Promise<string | null> {
  const authHeader = req.headers['authorization'] ?? '';
  const token = (authHeader as string).replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user.id;
}

/**
 * Superadmin middleware — only the admin_user_id from oriclaw_admin_settings
 * is allowed through. Returns 403 for any other authenticated user.
 */
export async function requireSuperAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Não autorizado. Faça login novamente.' });
    return;
  }
  const token = authHeader.slice(7);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    res.status(401).json({ error: 'Não autorizado. Faça login novamente.' });
    return;
  }

  const { data: settings } = await supabase
    .from('oriclaw_admin_settings')
    .select('admin_user_id')
    .limit(1)
    .maybeSingle();

  if (!settings || user.id !== settings.admin_user_id) {
    res.status(403).json({ error: 'Acesso restrito ao superadmin.' });
    return;
  }

  req.user = { id: user.id, email: user.email ?? undefined };
  next();
}

// Bug fix #7: typed parameter instead of `any`
export function sanitizeInstance(instance: OriClawInstance) {
  if (!instance) return instance;
  const { api_key_encrypted, ...rest } = instance;
  if (rest.metadata) {
    const {
      agent_secret,
      openai_access_token,
      openai_access_token_encrypted,
      openai_api_key_encrypted,
      openrouter_key,
      droplet_name: _dropletName,
      telegram_bot_token_encrypted: _tg,
      discord_bot_token_encrypted: _dc,
      openai_refresh_token_encrypted: _oauthRefresh,
      ...safeMetadata
    } = rest.metadata;
    rest.metadata = safeMetadata;
  }
  return rest;
}
