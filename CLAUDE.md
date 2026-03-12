# CLAUDE.md — OriClaw Backend

> Instruções para agentes de IA (Claude Code, Codex, etc.) que trabalham neste repositório.
> Leia este arquivo antes de qualquer modificação no código.

## Visão Geral

O **OriClaw Backend** é uma API REST em **Node.js + Express + TypeScript** que orquestra toda a infraestrutura da plataforma OriClaw:

- **Provisionamento de VPS** via DigitalOcean API (droplets cloud-init)
- **Billing** via Stripe (subscriptions mensais + créditos pré-pagos)
- **Gerenciamento de canais** (WhatsApp, Telegram, Discord) — comunica com o VPS Agent
- **Modos de IA**: BYOK (Anthropic/OpenAI/Google/OpenRouter), Créditos OriClaw (OpenRouter gerenciado), ChatGPT Plus (OAuth)
- **Auth**: delegada ao Supabase Auth — o backend valida JWTs do Supabase em cada request

Deploy em **Railway**. Banco de dados em **Supabase (PostgreSQL)**.

## Comandos Úteis

```bash
npm run dev       # servidor de desenvolvimento com hot-reload (ts-node-dev)
npm run build     # compilar TypeScript → dist/
npm run start     # produção (node dist/index.js)
npm test          # testes (se houver)
```

Estrutura de build: `dist/` (gerado por `tsc`, não commitado).

## Arquitetura — Camadas

```
Request HTTP
    │
    ▼
src/routes/          ← Define endpoints, valida params básicos, chama services
    │
    ▼
src/middleware/      ← Auth JWT (Supabase), rate limit por user_id, validação
    │
    ▼
src/services/        ← Lógica de negócio, sem acoplamento com Express
    ├── supabase.ts      → cliente admin Supabase (service_role)
    ├── digitalOcean.ts  → criar/listar/deletar droplets
    ├── stripe.ts        → subscriptions, webhooks, créditos
    ├── cloudInit.ts     → gera script cloud-init (contém VPS agent embedded)
    └── crypto.ts        → encrypt() / decrypt() AES-256-GCM
    │
    ▼
Supabase / DigitalOcean API / Stripe API / VPS Agent (:8080)
```

## Convenções de Código

- **TypeScript estrito** — sem `any` sem justificativa
- **Async/await** para todo código assíncrono (sem `.then()` encadeado)
- Erros de negócio retornam `{ error: string }` com o status HTTP correto (400, 403, 404, 409, 500)
- **Nunca logar API keys, secrets ou tokens** — nem em desenvolvimento
- Prefixo nos logs: `console.log('[modulo]', ...)` — ex: `console.log('[cloudInit] gerando script para', instanceId)`
- Validar `req.user?.id` antes de qualquer acesso ao banco

## Segurança — Regras Críticas

> ⚠️ Estas regras não são negociáveis. Violá-las pode expor dados de clientes.

1. **NUNCA** retornar ao frontend os campos:
   - `agent_secret`
   - `api_key_encrypted`
   - `openai_access_token_encrypted`
   - `openai_refresh_token_encrypted`
   - `telegram_bot_token_encrypted`
   - `discord_bot_token_encrypted`

2. **SEMPRE** usar `sanitizeInstance()` antes de retornar qualquer objeto de instância ao cliente.

3. **SEMPRE** checar ownership antes de operar em uma instância:
   ```typescript
   if (instance.customer_id !== userId) {
     return res.status(403).json({ error: 'Forbidden' });
   }
   ```

4. **API keys** são sempre criptografadas com `encrypt()` antes de salvar no Supabase.

5. **Descriptografar** com `decrypt()` **somente** no momento de enviar ao VPS Agent — nunca armazenar em memória por mais tempo que o necessário.

6. Rate limit é por `req.user?.id`, **não por IP** — IPs são compartilhados via proxy do Next.js/Vercel.

## VPS Agent

O VPS Agent é um servidor Express simples que roda em **cada droplet DigitalOcean na porta 8080**.

- **Autenticação:** header `x-agent-secret` com o secret único da instância
- **Responsabilidades:** iniciar/parar OpenClaw, configurar canais, ler logs do journald, gerenciar `.env` do OpenClaw

### ⚠️ REGRA CRÍTICA: Sincronização Dupla

O código do VPS Agent existe em **dois lugares**:

| Arquivo | Uso |
|---------|-----|
| `vps-agent/server.js` | Desenvolvimento e referência |
| `src/services/cloudInit.ts` | String embedded no cloud-init (bootstrap da VPS) |

**Ao modificar `vps-agent/server.js`, SEMPRE atualizar a cópia embedded em `src/services/cloudInit.ts`.**
Esquecer isso faz com que VPS novas subam com código antigo enquanto VPS existentes têm código novo — bugs difíceis de rastrear.

### Chamar o VPS Agent

```typescript
const response = await fetch(`http://${instance.droplet_ip}:8080/algum-endpoint`, {
  method: 'POST',
  headers: {
    'x-agent-secret': decrypt(instance.agent_secret),
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ ... }),
});
```

## Banco de Dados (Supabase)

### `oriclaw_instances`
Registro central de cada instância provisionada.

Campos sensíveis (sempre criptografados):
- `agent_secret` — secret do VPS agent
- `api_key_encrypted` — API key BYOK do cliente
- `openai_access_token_encrypted` / `openai_refresh_token_encrypted` — OAuth ChatGPT Plus
- `telegram_bot_token_encrypted` / `discord_bot_token_encrypted`

Campos de status:
- `status`: `provisioning` → `active` → `suspended` / `error`
- `droplet_id` / `droplet_ip`: preenchidos após criação do droplet

### `oriclaw_credits`
Saldo de créditos por `customer_id`. Decrementado a cada uso no modo créditos OriClaw.

### `stripe_processed_events`
Tabela de idempotência para webhooks Stripe. Antes de processar qualquer evento, checar se `event_id` já existe aqui. Inserir após processar com sucesso.

### Acessar o banco

```typescript
import { supabaseAdmin } from '../services/supabase';

// Nunca usar o cliente anon no backend — sempre o admin (service_role)
const { data, error } = await supabaseAdmin
  .from('oriclaw_instances')
  .select('*')
  .eq('customer_id', userId)
  .single();
```

## Stripe

### Eventos Tratados no Webhook (`POST /api/billing/webhook`)

| Evento | Ação |
|--------|------|
| `checkout.session.completed` | Provisiona nova VPS, cria instância no Supabase |
| `customer.subscription.updated` | Atualiza plano da instância |
| `customer.subscription.deleted` | Suspende instância (não deleta droplet imediatamente) |
| `invoice.payment_failed` | Marca instância como `payment_failed` |

### Fluxo de Billing

```
Stripe Checkout → webhook → resolvePlan() → createDroplet() → salvar instância
```

### `resolvePlan()`

> **Atenção:** `price_data` inline no Checkout Session não expõe `metadata` acessível no webhook.
> Por isso, `resolvePlan()` usa `subscription.metadata.plan` como fallback — o plano deve ser
> salvo em `metadata` no momento da criação da subscription.

## Armadilhas Comuns

### 1. `vps-agent/server.js` ≠ `cloudInit.ts`
Como descrito acima — sempre sincronizar. Esta é a causa mais comum de bugs em produção.

### 2. `resolvePlan()` e metadata do Stripe
`price_data` inline não expõe metadata no webhook. Use `subscription.metadata.plan` ou `session.metadata.plan`.

### 3. Logs do WhatsApp — usar `getJournalLogsSinceLastStart`
Para verificar se o WhatsApp está conectado/desconectado, use:
```typescript
getJournalLogsSinceLastStart(ip, secret) // ← correto
getJournalLogs(ip, secret)               // ← retorna logs antigos, falso positivo
```
`getJournalLogs` pode retornar logs de uma sessão anterior onde o WhatsApp estava OK.

### 4. `sanitizeEnvValue()` no .env da VPS
Ao escrever qualquer valor no `.env` do OpenClaw na VPS, **sempre** passar por `sanitizeEnvValue()`:
```typescript
const safeValue = sanitizeEnvValue(userInput);
// remove newlines, aspas que quebrariam o formato .env
```

### 5. Rate limit por user_id, não por IP
```typescript
// ✅ Correto
const identifier = req.user?.id;

// ❌ Errado — IP compartilhado via proxy Next.js
const identifier = req.ip;
```

### 6. Droplet em provisioning — sem IP imediato
Após criar o droplet via DO API, o IP pode demorar alguns segundos para ser atribuído.
Há um loop de polling no serviço que aguarda o droplet estar `active` antes de salvar o IP.

## Checklist antes de abrir PR

- [ ] `npm run build` sem erros
- [ ] Nenhum campo sensível exposto em resposta de rota
- [ ] `sanitizeInstance()` em toda rota que retorna dados de instância
- [ ] Ownership check em toda rota que opera em instância específica
- [ ] Se modificou `vps-agent/server.js`, atualizou `cloudInit.ts`
- [ ] Novos logs usam prefixo `[modulo]` e não logam secrets
- [ ] Novos webhooks Stripe adicionados à tabela de idempotência
