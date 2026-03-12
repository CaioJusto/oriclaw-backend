import { Router, Request, Response } from 'express';
import { requireApiSecret } from '../middleware/auth';
import { requireAuth, sanitizeInstance } from '../middleware/requireAuth';
import {
  getInstanceByCustomerId,
  getInstanceById,
  updateInstance,
} from '../services/supabase';
import { getDroplet, deleteDroplet } from '../services/digitalocean';
import { provisionInstance, updateApiKey } from '../services/provisioning';

const router = Router();

// POST /api/instances/provision — internal, protected
router.post('/provision', requireApiSecret, async (req: Request, res: Response): Promise<void> => {
  const { customer_id, plan, email, api_key_anthropic, stripe_subscription_id } = (req.body ?? {}) as {
    customer_id?: string;
    plan?: string;
    email?: string;
    api_key_anthropic?: string;
    stripe_subscription_id?: string;
  };

  if (!customer_id || !plan || !email) {
    res.status(400).json({ error: 'customer_id, plan, and email are required' });
    return;
  }

  if (!['starter', 'pro', 'business'].includes(plan)) {
    res.status(400).json({ error: 'plan must be starter | pro | business' });
    return;
  }

  try {
    const result = await provisionInstance({
      customer_id,
      plan: plan as 'starter' | 'pro' | 'business',
      email,
      api_key_anthropic,
      stripe_subscription_id,
    });

    res.status(202).json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Provisioning failed';
    console.error('[POST /provision]', msg);
    res.status(500).json({ error: msg });
  }
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/instances/:customer_id — requires Supabase JWT; returns only own instance
router.get('/:customer_id', requireAuth, async (req: Request, res: Response): Promise<void> => {
  if (!UUID_RE.test(req.params.customer_id)) {
    res.status(400).json({ error: 'Invalid customer_id format' });
    return;
  }
  const userId = req.user?.id;
  // Verify the requesting user matches the customer_id in the URL
  if (userId !== req.params.customer_id) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  try {
    const instance = await getInstanceByCustomerId(req.params.customer_id);
    if (!instance) {
      res.status(404).json({ error: 'Instance not found' });
      return;
    }
    // Double-check ownership
    if (instance.customer_id !== userId) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    res.json(sanitizeInstance(instance));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Query failed';
    console.error('[GET /instances/:customer_id]', msg);
    const isDev = process.env.NODE_ENV !== 'production';
    res.status(500).json({ error: isDev ? msg : 'Erro ao buscar instância. Tente novamente.' });
  }
});

// POST /api/instances/:instance_id/update-apikey — internal
router.post('/:instance_id/update-apikey', requireApiSecret, async (req: Request, res: Response): Promise<void> => {
  const { api_key } = (req.body ?? {}) as { api_key?: string };

  if (!api_key) {
    res.status(400).json({ error: 'api_key is required' });
    return;
  }

  try {
    await updateApiKey(req.params.instance_id, api_key);
    res.json({ success: true });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Update failed';
    res.status(500).json({ error: msg });
  }
});

// GET /api/instances/:instance_id/status — requires Supabase JWT + ownership
router.get('/:instance_id/status', requireAuth, async (req: Request, res: Response): Promise<void> => {
  if (!UUID_RE.test(req.params.instance_id)) {
    res.status(400).json({ error: 'Invalid instance_id format' });
    return;
  }
  const userId = req.user?.id;
  try {
    const instance = await getInstanceById(req.params.instance_id);
    if (!instance) {
      res.status(404).json({ error: 'Instance not found' });
      return;
    }

    // Ownership check
    if (instance.customer_id !== userId) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    let dropletStatus: string | null = null;
    if (instance.droplet_id) {
      try {
        const droplet = await getDroplet(instance.droplet_id);
        dropletStatus = droplet.status;
      } catch {
        dropletStatus = 'unknown';
      }
    }

    res.json({
      instance_id: instance.id,
      status: instance.status,
      droplet_status: dropletStatus,
      droplet_ip: instance.droplet_ip,
      plan: instance.plan,
      created_at: instance.created_at,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Query failed';
    console.error('[GET /instances/:instance_id/status]', msg);
    const isDev = process.env.NODE_ENV !== 'production';
    res.status(500).json({ error: isDev ? msg : 'Erro ao buscar status da instância. Tente novamente.' });
  }
});

// DELETE /api/instances/:instance_id — internal
router.delete('/:instance_id', requireApiSecret, async (req: Request, res: Response): Promise<void> => {
  try {
    const instance = await getInstanceById(req.params.instance_id);
    if (!instance) {
      res.status(404).json({ error: 'Instance not found' });
      return;
    }

    if (instance.droplet_id) {
      await deleteDroplet(instance.droplet_id);
    }

    await updateInstance(instance.id, { status: 'deleted' });
    res.json({ success: true, instance_id: instance.id });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Deletion failed';
    res.status(500).json({ error: msg });
  }
});

export default router;
