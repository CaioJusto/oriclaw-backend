# SKILL: oriclaw-ops

## Descrição

Operações de manutenção e deploy do **OriClaw SaaS**. Use esta skill quando precisar:

- Fazer deploy de nova versão do backend (Railway) ou frontend (Vercel)
- Verificar saúde das instâncias ativas
- Investigar erros de provisionamento de VPS
- Gerenciar dados nas tabelas Supabase do OriClaw
- Diagnosticar problemas com canais (WhatsApp, Telegram, Discord)
- Auditar billing e créditos no Stripe

## Ferramentas Necessárias

- `railway` — Railway CLI (deploy e logs do backend)
- `vercel` — Vercel CLI (deploy do frontend)
- `gh` — GitHub CLI (PRs, issues, status de CI)
- `curl` — Chamadas às APIs Supabase REST, DigitalOcean, VPS Agent
- `doctl` — DigitalOcean CLI (opcional, para inspecionar droplets)

## Repositórios

| Componente | Repositório | Deploy |
|------------|-------------|--------|
| Backend    | `CaioJusto/oriclaw-backend` | Railway (auto-deploy no push main) |
| Frontend   | `CaioJusto/oriclaw-landing` | Vercel (auto-deploy no push main) |

## Deploy Backend (Railway)

```bash
cd /tmp/oriclaw-review-backend   # ou o diretório local do repo

# Commit e push (Railway detecta via webhook e deploya automaticamente)
git add -A
git commit -m "fix: descrição do que foi corrigido"
git push origin main

# Verificar status do deploy:
railway logs --service oriclaw-backend --tail

# Forçar deploy manual (sem push):
railway up --service oriclaw-backend --detach
```

## Deploy Frontend (Vercel)

```bash
cd /tmp/oriclaw-review-landing   # ou o diretório local do repo

# Deploy em produção:
vercel --token <VERCEL_TOKEN> --prod

# Ou via push (se Vercel estiver conectado ao GitHub):
git add -A && git commit -m "..." && git push origin main
```

## Verificar Instâncias Presas em Provisioning

Instâncias podem ficar presas no status `provisioning` se o cloud-init falhar ou se o droplet demorar mais que o esperado.

```bash
# Listar instâncias em provisioning há mais de 30 minutos
curl -s \
  -H "apikey: <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>" \
  "https://pskvfegwnqdfbstqkpob.supabase.co/rest/v1/oriclaw_instances?status=eq.provisioning&select=id,created_at,customer_id,droplet_id,droplet_ip" \
  | jq .

# Atualizar status manualmente para 'error' (após investigar):
curl -s -X PATCH \
  -H "apikey: <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"status": "error"}' \
  "https://pskvfegwnqdfbstqkpob.supabase.co/rest/v1/oriclaw_instances?id=eq.<INSTANCE_ID>"
```

## Verificar Saúde de uma Instância Específica

```bash
# Checar se o VPS Agent responde (requer agent_secret descriptografado)
curl -s \
  -H "x-agent-secret: <AGENT_SECRET>" \
  "http://<DROPLET_IP>:8080/health"

# Ver logs do OpenClaw no droplet (via VPS Agent)
curl -s \
  -H "x-agent-secret: <AGENT_SECRET>" \
  "http://<DROPLET_IP>:8080/logs"

# Verificar status do WhatsApp (usa journald desde último restart)
curl -s \
  -H "x-agent-secret: <AGENT_SECRET>" \
  "http://<DROPLET_IP>:8080/whatsapp/status"
```

## Consultar Droplets no DigitalOcean

```bash
# Listar todos os droplets OriClaw (via DO API)
curl -s \
  -H "Authorization: Bearer <DIGITALOCEAN_TOKEN>" \
  "https://api.digitalocean.com/v2/droplets?tag_name=oriclaw&per_page=50" \
  | jq '.droplets[] | {id, name, status, ip: .networks.v4[0].ip_address, created_at}'

# Deletar droplet específico (CUIDADO — irreversível)
curl -s -X DELETE \
  -H "Authorization: Bearer <DIGITALOCEAN_TOKEN>" \
  "https://api.digitalocean.com/v2/droplets/<DROPLET_ID>"
```

## Gerenciar Créditos

```bash
# Ver saldo de créditos de um cliente
curl -s \
  -H "apikey: <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>" \
  "https://pskvfegwnqdfbstqkpob.supabase.co/rest/v1/oriclaw_credits?customer_id=eq.<USER_ID>&select=*"

# Adicionar créditos manualmente
curl -s -X PATCH \
  -H "apikey: <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"balance": <NOVO_SALDO>}' \
  "https://pskvfegwnqdfbstqkpob.supabase.co/rest/v1/oriclaw_credits?customer_id=eq.<USER_ID>"
```

## Verificar Eventos Stripe Processados

```bash
# Checar se um evento foi processado (idempotência)
curl -s \
  -H "apikey: <SUPABASE_SERVICE_ROLE_KEY>" \
  -H "Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>" \
  "https://pskvfegwnqdfbstqkpob.supabase.co/rest/v1/stripe_processed_events?event_id=eq.<EVT_ID>&select=*"
```

## Chaves e Endpoints Importantes

| Recurso | URL / Referência |
|---------|-----------------|
| Backend Railway | *(preencher após deploy — ver Railway Dashboard)* |
| Frontend | https://oriclaw.com.br |
| Supabase Dashboard | https://supabase.com/dashboard/project/pskvfegwnqdfbstqkpob |
| Supabase REST API | https://pskvfegwnqdfbstqkpob.supabase.co |
| Stripe Dashboard | https://dashboard.stripe.com |
| DigitalOcean | https://cloud.digitalocean.com |

## Variáveis de Ambiente Obrigatórias

| Variável | Formato | Onde obter |
|----------|---------|-----------|
| `SUPABASE_URL` | `https://xxxx.supabase.co` | Supabase Dashboard → Settings → API |
| `SUPABASE_ANON_KEY` | `eyJ...` (JWT) | Supabase Dashboard → Settings → API |
| `SUPABASE_SERVICE_ROLE_KEY` | `eyJ...` (JWT) | Supabase Dashboard → Settings → API |
| `STRIPE_SECRET_KEY` | `sk_live_...` ou `sk_test_...` | Stripe Dashboard → Developers → API Keys |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...` | Stripe Dashboard → Webhooks → endpoint |
| `DIGITALOCEAN_TOKEN` | string longa | DO Dashboard → API → Tokens |
| `ENCRYPTION_KEY` | 64 chars hex | `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `ORICLAW_OPENROUTER_KEY` | `sk-or-...` | OpenRouter Dashboard |
| `CORS_ORIGIN` | `https://oriclaw.com.br` | URL de produção do frontend |
| `NODE_ENV` | `production` | Definir manualmente no Railway |
| `OPENAI_CLIENT_ID` | string | OpenAI Platform → OAuth Apps |
| `OPENAI_CLIENT_SECRET` | string | OpenAI Platform → OAuth Apps |

## Troubleshooting

### Instância presa em `provisioning`
1. Verificar se o droplet foi criado no DO (buscar por `droplet_id` na instância)
2. Se droplet existe: aguardar até 30min (cloud-init pode demorar)
3. Se passaram 30min: SSH no droplet e verificar `cloud-init-output.log`
4. Se droplet não existe: o webhook pode ter falhado — verificar logs do Railway
5. Última opção: atualizar status para `error` manualmente e notificar o cliente

### VPS Agent não responde (porta 8080)
1. Verificar se o droplet está ativo no DO Dashboard
2. Verificar UFW: `ufw status` (porta 8080 deve estar permitida)
3. Verificar se o serviço systemd está rodando: `systemctl status oriclaw-agent`
4. Ver logs do agente: `journalctl -u oriclaw-agent -n 100`

### WhatsApp não conecta
1. Verificar se o OpenClaw está rodando: `systemctl status openclaw`
2. Ver logs do OpenClaw: `journalctl -u openclaw -n 100 --since "last boot"`
3. Usar `getJournalLogsSinceLastStart` — não `getJournalLogs` (evita falsos positivos de sessões antigas)
4. Se necessário: reiniciar OpenClaw via VPS Agent (`POST /openclaw/restart`)

### Créditos não creditados após pagamento
1. Verificar no Stripe se o evento `checkout.session.completed` foi disparado
2. Buscar o `event_id` na tabela `stripe_processed_events` — se não estiver lá, o webhook falhou
3. Verificar logs do Railway no horário do pagamento
4. Processar manualmente via Stripe Dashboard → Webhooks → reenviar evento

### Deploy não subiu após push
1. Verificar `railway logs --service oriclaw-backend`
2. Verificar se há erros de TypeScript: `npm run build` localmente
3. Verificar se as variáveis de ambiente estão configuradas no Railway

## Segurança — Regras de Operação

- **Nunca expor `AGENT_SECRET` em logs** — descriptografar apenas para uso imediato
- **`ENCRYPTION_KEY` é imutável em produção** — alterar sem migrar dados criptografados corrompe todas as API keys salvas
- **Antes de deploy major**: rodar `npm run build` e revisar mudanças em `cloudInit.ts` e `vps-agent/server.js`
- **Acesso SSH a droplets**: apenas para debug emergencial — toda operação rotineira deve ser via VPS Agent API
- **Webhook Stripe**: sempre validar assinatura com `stripe.webhooks.constructEvent()` antes de processar
