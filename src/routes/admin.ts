import { Router, Request, Response } from 'express';
import { requireSuperAdmin, sanitizeInstance } from '../middleware/requireAuth';
import { supabase } from '../services/supabase';
import { fetchModels, getAdminSettings } from '../services/openrouter';
import { OriClawInstance } from '../types';

const router = Router();

// All admin routes require superadmin access
router.use(requireSuperAdmin);

// ── GET /api/admin/settings ──────────────────────────────────────────────────
router.get('/settings', async (_req: Request, res: Response) => {
  try {
    const settings = await getAdminSettings();
    if (!settings) {
      res.status(404).json({ error: 'Admin settings not found' });
      return;
    }

    res.json({
      default_model: settings.default_model,
      cost_multiplier: settings.cost_multiplier,
      openrouter_key_configured: !!process.env.ORICLAW_OPENROUTER_KEY,
      updated_at: settings.updated_at,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to fetch settings';
    console.error('[admin/settings] Error:', msg);
    res.status(500).json({ error: 'Erro ao buscar configurações.' });
  }
});

// ── PUT /api/admin/settings ──────────────────────────────────────────────────
router.put('/settings', async (req: Request, res: Response) => {
  try {
    const { default_model, cost_multiplier } = req.body;

    if (cost_multiplier !== undefined) {
      if (typeof cost_multiplier !== 'number' || cost_multiplier < 1 || cost_multiplier > 10) {
        res.status(400).json({ error: 'cost_multiplier deve ser um número entre 1 e 10.' });
        return;
      }
    }

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (default_model !== undefined) updates.default_model = default_model;
    if (cost_multiplier !== undefined) updates.cost_multiplier = cost_multiplier;

    const settings = await getAdminSettings();
    if (!settings) {
      res.status(404).json({ error: 'Admin settings not found' });
      return;
    }

    const { data, error } = await supabase
      .from('oriclaw_admin_settings')
      .update(updates)
      .eq('admin_user_id', settings.admin_user_id)
      .select('default_model, cost_multiplier, updated_at')
      .single();

    if (error) {
      console.error('[admin/settings] Update error:', error.message);
      res.status(500).json({ error: 'Erro ao atualizar configurações.' });
      return;
    }

    res.json(data);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to update settings';
    console.error('[admin/settings] Error:', msg);
    res.status(500).json({ error: 'Erro ao atualizar configurações.' });
  }
});

// ── GET /api/admin/models ────────────────────────────────────────────────────
router.get('/models', async (_req: Request, res: Response) => {
  try {
    const models = await fetchModels();
    res.json({ models });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to fetch models';
    console.error('[admin/models] Error:', msg);
    res.status(500).json({ error: 'Erro ao buscar modelos do OpenRouter.' });
  }
});

// ── GET /api/admin/usage?period=7d ───────────────────────────────────────────
router.get('/usage', async (req: Request, res: Response) => {
  try {
    const periodParam = (req.query.period as string) ?? '7d';
    const match = periodParam.match(/^(\d+)d$/);
    const days = match ? parseInt(match[1], 10) : 7;

    if (days < 1 || days > 365) {
      res.status(400).json({ error: 'period deve ser entre 1d e 365d.' });
      return;
    }

    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

    const { data: rows, error } = await supabase
      .from('oriclaw_token_usage')
      .select('customer_id, total_tokens, cost_usd, cost_brl, created_at')
      .gte('created_at', since)
      .order('created_at', { ascending: true });

    if (error) {
      console.error('[admin/usage] Query error:', error.message);
      res.status(500).json({ error: 'Erro ao buscar dados de uso.' });
      return;
    }

    // Aggregate totals
    let totalTokens = 0;
    let totalCostUsd = 0;
    let totalCostBrl = 0;
    const messages = rows?.length ?? 0;

    const byDay: Record<string, { tokens: number; cost_usd: number; cost_brl: number; messages: number }> = {};
    const userAgg: Record<string, { tokens: number; cost_brl: number; messages: number }> = {};

    for (const row of rows ?? []) {
      totalTokens += row.total_tokens ?? 0;
      totalCostUsd += row.cost_usd ?? 0;
      totalCostBrl += row.cost_brl ?? 0;

      // By day
      const day = row.created_at.slice(0, 10); // YYYY-MM-DD
      if (!byDay[day]) byDay[day] = { tokens: 0, cost_usd: 0, cost_brl: 0, messages: 0 };
      byDay[day].tokens += row.total_tokens ?? 0;
      byDay[day].cost_usd += row.cost_usd ?? 0;
      byDay[day].cost_brl += row.cost_brl ?? 0;
      byDay[day].messages += 1;

      // By user
      const cid = row.customer_id;
      if (!userAgg[cid]) userAgg[cid] = { tokens: 0, cost_brl: 0, messages: 0 };
      userAgg[cid].tokens += row.total_tokens ?? 0;
      userAgg[cid].cost_brl += row.cost_brl ?? 0;
      userAgg[cid].messages += 1;
    }

    // Top 10 users by cost_brl
    const topUsers = Object.entries(userAgg)
      .map(([customer_id, stats]) => ({ customer_id, ...stats }))
      .sort((a, b) => b.cost_brl - a.cost_brl)
      .slice(0, 10);

    res.json({
      totals: { total_tokens: totalTokens, cost_usd: totalCostUsd, cost_brl: totalCostBrl, messages },
      byDay,
      topUsers,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to fetch usage';
    console.error('[admin/usage] Error:', msg);
    res.status(500).json({ error: 'Erro ao buscar dados de uso.' });
  }
});

// ── GET /api/admin/instances ─────────────────────────────────────────────────
router.get('/instances', async (_req: Request, res: Response) => {
  try {
    const { data: instances, error } = await supabase
      .from('oriclaw_instances')
      .select('*')
      .neq('status', 'deleted')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('[admin/instances] Query error:', error.message);
      res.status(500).json({ error: 'Erro ao buscar instâncias.' });
      return;
    }

    // Fetch credit balances for all customer_ids
    const customerIds = [...new Set((instances ?? []).map((i) => i.customer_id))];

    let creditsMap: Record<string, number> = {};
    if (customerIds.length > 0) {
      const { data: credits } = await supabase
        .from('oriclaw_credits')
        .select('customer_id, balance_brl')
        .in('customer_id', customerIds);

      if (credits) {
        creditsMap = Object.fromEntries(credits.map((c) => [c.customer_id, c.balance_brl]));
      }
    }

    const sanitized = (instances ?? []).map((inst) => ({
      ...sanitizeInstance(inst as OriClawInstance),
      credit_balance_brl: creditsMap[inst.customer_id] ?? 0,
    }));

    res.json({ instances: sanitized });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to fetch instances';
    console.error('[admin/instances] Error:', msg);
    res.status(500).json({ error: 'Erro ao buscar instâncias.' });
  }
});

export default router;
