# OriClaw Backend

> Provisioning API that automatically creates DigitalOcean Droplets for OpenClaw customers when they pay via Stripe.

## Architecture

```
Stripe Webhook ──► POST /webhooks/stripe
                         │
                         ▼
                  provisionInstance()
                         │
                 ┌───────┴────────┐
                 ▼               ▼
          DO Droplet         Supabase
          (created)       (record saved)
                 │
                 ▼
          Cloud-init runs
          (OpenClaw installed)
                 │
                 ▼
          Status → running
```

When a `customer.subscription.created` event fires:
1. Saves a `provisioning` record to Supabase
2. Fires off async droplet creation via DigitalOcean API
3. Polls until the droplet gets a public IP
4. Updates the record to `running`

## API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Health check |
| POST | `/webhooks/stripe` | Stripe sig | Stripe event handler |
| POST | `/api/instances/provision` | API_SECRET | Manually provision |
| GET | `/api/instances/:customer_id` | — | Get instance by customer |
| POST | `/api/instances/:instance_id/update-apikey` | API_SECRET | Update Anthropic API key |
| GET | `/api/instances/:instance_id/status` | — | Get instance + droplet status |
| DELETE | `/api/instances/:instance_id` | API_SECRET | Destroy instance |

### Auth

Protected routes require the `x-api-secret` header (or `Authorization: Bearer <secret>`):

```
x-api-secret: oriclaw_internal_secret_2026
```

## ENV Vars

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|----------|-------------|
| `DO_API_TOKEN` | DigitalOcean personal access token |
| `STRIPE_SECRET_KEY` | Stripe secret key (`sk_test_...` or `sk_live_...`) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (`whsec_...`) |
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key (bypasses RLS) |
| `API_SECRET` | Internal API secret for protected routes |
| `PORT` | Server port (default: `3001`) |

## Supabase Setup

Run this SQL in your Supabase SQL editor:

```sql
CREATE TABLE oriclaw_instances (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  customer_id text NOT NULL,
  email text NOT NULL,
  plan text NOT NULL, -- starter | pro | business
  droplet_id bigint,
  droplet_ip text,
  status text DEFAULT 'provisioning', -- provisioning | running | suspended | deleted
  stripe_subscription_id text,
  api_key_encrypted text, -- store encrypted API key
  metadata jsonb
);

CREATE INDEX ON oriclaw_instances(customer_id);
CREATE INDEX ON oriclaw_instances(stripe_subscription_id);
```

## Deploy to Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**
3. Select `CaioJusto/oriclaw-backend`
4. Add all ENV vars in the Railway dashboard (Variables tab)
5. Railway auto-detects `npm run build` + `npm start`
6. Copy your Railway public URL (e.g. `https://oriclaw-backend.up.railway.app`)

## Configure Stripe Webhook

1. Go to [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/webhooks)
2. Click **Add endpoint**
3. URL: `https://your-railway-url.up.railway.app/webhooks/stripe`
4. Select events:
   - `customer.subscription.created`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`
5. Copy the **Signing secret** → set as `STRIPE_WEBHOOK_SECRET` in Railway

## Local Development

```bash
# Install deps
npm install

# Copy env
cp .env.example .env
# Fill in real values

# Dev server with hot reload
npm run dev

# Build TypeScript
npm run build

# Start production build
npm start
```

## DigitalOcean Droplet Spec

| Field | Value |
|-------|-------|
| Region | `nyc3` (New York 3) |
| Size | `s-1vcpu-2gb` ($12/month) |
| Image | `ubuntu-22-04-x64` |
| Tags | `oriclaw`, `customer:<id>` |

The cloud-init script automatically installs Node.js 20 + OpenClaw globally, creates an `openclaw` system user, and sets up a systemd service that starts on boot.
