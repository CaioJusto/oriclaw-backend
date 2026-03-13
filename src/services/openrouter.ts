import axios from 'axios';
import { supabase } from './supabase';

// ── Types ────────────────────────────────────────────────────────────────────

interface ModelPricing {
  prompt: string;
  completion: string;
}

interface OpenRouterModel {
  id: string;
  name: string;
  pricing: ModelPricing;
}

interface AdminSettings {
  admin_user_id: string;
  default_model: string;
  cost_multiplier: number;
  updated_at: string;
}

// ── Cache ────────────────────────────────────────────────────────────────────

let cachedModels: OpenRouterModel[] | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// ── Functions ────────────────────────────────────────────────────────────────

/**
 * Fetches available models from OpenRouter API.
 * Caches results for 1 hour.
 */
export async function fetchModels(): Promise<OpenRouterModel[]> {
  const now = Date.now();
  if (cachedModels && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedModels;
  }

  const { data } = await axios.get<{ data: Array<{ id: string; name: string; pricing: ModelPricing }> }>(
    'https://openrouter.ai/api/v1/models'
  );

  cachedModels = data.data.map((m) => ({
    id: m.id,
    name: m.name,
    pricing: {
      prompt: m.pricing.prompt,
      completion: m.pricing.completion,
    },
  }));
  cacheTimestamp = now;

  console.log(`[openrouter] Cached ${cachedModels.length} models`);
  return cachedModels;
}

/**
 * Returns pricing for a specific model, or null if not found.
 */
export async function getModelPricing(modelId: string): Promise<ModelPricing | null> {
  const models = await fetchModels();
  const model = models.find((m) => m.id === modelId);
  return model?.pricing ?? null;
}

export function normalizeOpenRouterModelId(modelId: string | null | undefined): string | null {
  if (!modelId) return null;
  return modelId.startsWith('openrouter/') ? modelId.slice('openrouter/'.length) : modelId;
}

export async function calculateOpenRouterCostUsd(
  modelId: string,
  promptTokens: number,
  completionTokens: number
): Promise<number | null> {
  const normalizedModelId = normalizeOpenRouterModelId(modelId);
  if (!normalizedModelId) return null;

  const pricing = await getModelPricing(normalizedModelId);
  if (!pricing) return null;

  const promptUnitCost = Number.parseFloat(pricing.prompt);
  const completionUnitCost = Number.parseFloat(pricing.completion);
  if (!Number.isFinite(promptUnitCost) || !Number.isFinite(completionUnitCost)) return null;

  return (promptTokens * promptUnitCost) + (completionTokens * completionUnitCost);
}

/**
 * Queries oriclaw_admin_settings and returns the first row, or null.
 */
export async function getAdminSettings(): Promise<AdminSettings | null> {
  const { data, error } = await supabase
    .from('oriclaw_admin_settings')
    .select('admin_user_id, default_model, cost_multiplier, updated_at')
    .limit(1)
    .maybeSingle();

  if (error) {
    console.error('[openrouter] Error fetching admin settings:', error.message);
    return null;
  }

  return data as AdminSettings | null;
}
