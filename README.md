# OriClaw Backend

Backend da plataforma **OriClaw** — SaaS que permite contratar um agente de IA com VPS dedicada em poucos cliques, voltado para o mercado brasileiro.

## O que é o OriClaw?

OriClaw é uma plataforma que provisiona automaticamente um agente de IA (baseado no OpenClaw) em uma VPS DigitalOcean exclusiva por cliente, com suporte a múltiplos canais (WhatsApp, Telegram, Discord) e múltiplos modos de IA (BYOK, Créditos OriClaw, ChatGPT Plus via OAuth).

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                        Cliente Final                             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│               Frontend — Next.js 14 (Vercel)                     │
│           oriclaw.com.br  |  Supabase Auth                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│            Backend — Node.js/Express/TS (Railway)                │
│   /api/instances  |  /api/billing  |  /api/channels  |  /api/ai │
│                   Supabase (DB)  |  Stripe (billing)             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ DigitalOcean API
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│          VPS — DigitalOcean Droplet s-1vcpu-2gb                  │
│               (uma por cliente, cloud-init)                       │
│                                                                   │
│   ┌─────────────────────┐   ┌──────────────────────────────┐    │
│   │  VPS Agent :8080    │   │   OpenClaw Gateway :3000     │    │
│   │  Express + Node.js  │──▶│  WhatsApp / Telegram / Discord│   │
│   │  gerencia canais    │   │  Anthropic / OpenAI / Google  │   │
│   └─────────────────────┘   └──────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Pré-requisitos

- **Node.js 20+**
- **npm 9+**
- Conta Supabase com projeto configurado
- Conta Stripe com webhooks configurados
- Token da API DigitalOcean
- (Opcional) Conta OpenRouter para modo créditos OriClaw
- (Opcional) App OAuth OpenAI para modo ChatGPT Plus

## Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
# ── Supabase ──────────────────────────────────────────────────────
# URL do projeto Supabase (ex: https://xxxx.supabase.co)
SUPABASE_URL=

# Chave anon pública do Supabase (usada para auth no lado cliente)
SUPABASE_ANON_KEY=

# Chave service_role do Supabase (acesso admin ao banco — NUNCA expor no frontend)
SUPABASE_SERVICE_ROLE_KEY=

# ── Stripe ────────────────────────────────────────────────────────
# Chave secreta da API Stripe (sk_live_... ou sk_test_...)
STRIPE_SECRET_KEY=

# Secret do webhook Stripe para validar assinaturas dos eventos
STRIPE_WEBHOOK_SECRET=

# ── DigitalOcean ──────────────────────────────────────────────────
# Token de API do DigitalOcean para criar/deletar droplets
DIGITALOCEAN_TOKEN=

# ── Criptografia ──────────────────────────────────────────────────
# Chave de criptografia AES-256-GCM — DEVE ser 64 caracteres hex
# Gerar com: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# ATENÇÃO: Não alterar em produção sem migrar os dados criptografados existentes
ENCRYPTION_KEY=

# ── OriClaw / OpenRouter ──────────────────────────────────────────
# Chave OpenRouter usada quando o cliente usa Créditos OriClaw (modo gerenciado)
ORICLAW_OPENROUTER_KEY=

# ── CORS ──────────────────────────────────────────────────────────
# URL do frontend em produção (ex: https://oriclaw.com.br)
# Usado para restringir CORS nas rotas da API
CORS_ORIGIN=

# ── Ambiente ──────────────────────────────────────────────────────
# "development" | "production"
NODE_ENV=development

# ── OpenAI OAuth (ChatGPT Plus) ───────────────────────────────────
# Client ID do app OAuth OpenAI — para modo ChatGPT Plus
OPENAI_CLIENT_ID=

# Client Secret do app OAuth OpenAI — para modo ChatGPT Plus
OPENAI_CLIENT_SECRET=
```

## Rodando Localmente

```bash
# 1. Instalar dependências
npm install

# 2. Copiar e preencher variáveis de ambiente
cp .env.example .env
# edite o .env com suas chaves

# 3. Iniciar servidor de desenvolvimento (com hot-reload)
npm run dev
```

O servidor sobe em `http://localhost:3001` por padrão.

## Deploy no Railway

1. Conecte o repositório ao Railway via Dashboard ou CLI:
   ```bash
   railway link
   ```

2. Configure as variáveis de ambiente no Railway (Dashboard → Variables ou via CLI):
   ```bash
   railway variables set SUPABASE_URL=... STRIPE_SECRET_KEY=... # etc
   ```

3. O deploy acontece automaticamente a cada push na branch `main`.

4. Para forçar um deploy manual:
   ```bash
   railway up --service oriclaw-backend --detach
   ```

5. Configure o webhook do Stripe apontando para:
   ```
   https://<seu-dominio-railway>/api/billing/webhook
   ```

## Estrutura de Pastas

```
oriclaw-backend/
├── src/
│   ├── routes/          # Rotas Express (instances, billing, channels, ai, auth)
│   ├── services/        # Lógica de negócio
│   │   ├── cloudInit.ts     # Geração do cloud-init para provisionar VPS
│   │   ├── digitalOcean.ts  # Integração com API DO (criar/deletar droplets)
│   │   ├── stripe.ts        # Integração Stripe (subscriptions, créditos)
│   │   ├── supabase.ts      # Cliente Supabase admin
│   │   └── crypto.ts        # encrypt() / decrypt() com AES-256-GCM
│   ├── middleware/      # Auth, rate limiting, validação
│   └── index.ts         # Entry point — configura Express e rotas
├── vps-agent/
│   └── server.js        # Código do agente que roda em cada droplet DO
│                        # ⚠️ ESPELHADO em src/services/cloudInit.ts
├── dist/                # Build TypeScript (gerado por npm run build)
├── .env                 # Variáveis locais (não commitado)
├── .env.example         # Template de variáveis
├── package.json
└── tsconfig.json
```

## Banco de Dados (Supabase)

### ⚠️ Migrations — RLS obrigatório

Execute o arquivo `supabase/migrations/001_rls.sql` no Supabase SQL Editor (ou via `supabase db push`) para habilitar Row Level Security (RLS) em todas as tabelas e criar a tabela de audit log.

```bash
# Via Supabase CLI
supabase db push

# Ou manualmente: copie o conteúdo de supabase/migrations/001_rls.sql
# e execute no SQL Editor do painel Supabase
```

> ⚠️ Sem as políticas RLS, usuários com acesso direto à API Supabase (via chave `anon`) conseguem ver dados de outros clientes. O backend usa a chave de `service_role` que contorna RLS — isso é intencional para operações internas.

### Tabelas Necessárias

#### `oriclaw_instances`
Armazena cada instância de agente provisionada por cliente.

```sql
CREATE TABLE oriclaw_instances (
  id                            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  customer_id                   TEXT NOT NULL,          -- user_id do Supabase Auth
  status                        TEXT NOT NULL DEFAULT 'provisioning',
                                                        -- provisioning | active | suspended | error
  plan                          TEXT NOT NULL,          -- starter | pro | business
  droplet_id                    INTEGER,                -- ID do droplet no DigitalOcean
  droplet_ip                    TEXT,                   -- IP público do droplet
  agent_secret                  TEXT,                   -- Secret para autenticar no VPS agent (criptografado)
  
  -- Canais
  whatsapp_enabled              BOOLEAN DEFAULT false,
  telegram_enabled              BOOLEAN DEFAULT false,
  discord_enabled               BOOLEAN DEFAULT false,
  telegram_bot_token_encrypted  TEXT,
  discord_bot_token_encrypted   TEXT,
  discord_guild_id              TEXT,
  
  -- Modo IA
  ai_mode                       TEXT DEFAULT 'credits', -- byok | credits | chatgpt_plus
  ai_provider                   TEXT,                   -- anthropic | openai | google | openrouter
  api_key_encrypted             TEXT,                   -- API key BYOK (criptografada)
  openai_access_token_encrypted TEXT,                   -- OAuth token ChatGPT Plus (criptografado)
  openai_refresh_token_encrypted TEXT,
  
  -- Stripe
  stripe_subscription_id        TEXT,
  stripe_customer_id            TEXT,
  
  created_at                    TIMESTAMPTZ DEFAULT now(),
  updated_at                    TIMESTAMPTZ DEFAULT now()
);

-- RLS: usuário só vê suas próprias instâncias
ALTER TABLE oriclaw_instances ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owner_access" ON oriclaw_instances
  USING (customer_id = auth.uid()::text);
```

#### `oriclaw_credits`
Saldo de créditos para o modo gerenciado (OriClaw OpenRouter).

```sql
CREATE TABLE oriclaw_credits (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  customer_id TEXT NOT NULL UNIQUE,
  balance     INTEGER NOT NULL DEFAULT 0,   -- créditos disponíveis
  created_at  TIMESTAMPTZ DEFAULT now(),
  updated_at  TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE oriclaw_credits ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owner_access" ON oriclaw_credits
  USING (customer_id = auth.uid()::text);
```

#### `stripe_processed_events`
Idempotência para webhooks Stripe — evita processar o mesmo evento duas vezes.

```sql
CREATE TABLE stripe_processed_events (
  event_id    TEXT PRIMARY KEY,             -- stripe event ID (evt_...)
  processed_at TIMESTAMPTZ DEFAULT now()
);
```

## Fluxo de Provisionamento

```
1. Cliente faz checkout no Frontend (Stripe Checkout)
         │
         ▼
2. Stripe dispara webhook → POST /api/billing/webhook
         │
         ▼
3. Backend valida assinatura do webhook
         │
         ▼
4. Evento checkout.session.completed → resolvePlan()
         │
         ▼
5. createDroplet() → DigitalOcean API
   - Cria droplet s-1vcpu-2gb na região nyc3
   - Passa cloud-init com script de bootstrap
         │
         ▼
6. cloud-init no droplet:
   - Instala Node.js, npm, OpenClaw
   - Copia código do VPS Agent (server.js)
   - Configura UFW (porta 8080 liberada)
   - Sobe VPS Agent como serviço systemd
   - Sobe OpenClaw na porta 3000
         │
         ▼
7. Backend salva instância no Supabase com status "active"
         │
         ▼
8. Cliente vê painel com IP da VPS e pode conectar canais
```

## Planos Disponíveis

| Plano     | Preço      | Recursos                          |
|-----------|------------|-----------------------------------|
| Starter   | R$97/mês   | 1 canal, modo créditos            |
| Pro       | R$147/mês  | 3 canais, BYOK ou créditos        |
| Business  | R$247/mês  | canais ilimitados, todos os modos |

## Segurança

- API keys de clientes são **sempre** criptografadas com AES-256-GCM antes de salvar
- Cada instância tem um `agent_secret` único para autenticar no VPS agent
- VPS protegida com UFW (apenas portas 22, 8080, 3000)
- `sanitizeInstance()` remove campos sensíveis antes de qualquer resposta ao frontend
- Rate limiting por `user_id` (não por IP, pois o proxy Next.js compartilha IPs)
