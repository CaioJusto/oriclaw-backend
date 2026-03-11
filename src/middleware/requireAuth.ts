import { Request, Response, NextFunction } from 'express';
import { createClient } from '@supabase/supabase-js';
import { OriClawInstance } from '../types';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

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

export function sanitizeInstance(instance: OriClawInstance) {
  if (!instance) return instance;
  const { api_key_encrypted, ...rest } = instance;
  if (rest.metadata) {
    const { agent_secret, openai_access_token, openai_access_token_encrypted, openrouter_key, ...safeMetadata } = rest.metadata;
    rest.metadata = safeMetadata;
  }
  return rest;
}
