# @dcprotocol/server

Local REST API + approval UI for DCP Vault. Binds to `127.0.0.1` only.

Use this when:
- You want browser‑based approvals
- Your agent runtime can’t spawn MCP subprocesses
- You need a local HTTP interface

## Install

```bash
npm install @dcprotocol/server
```

## Run

```bash
npx @dcprotocol/server
```

Open:
```
http://127.0.0.1:8420
```

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VAULT_DIR` | Vault storage directory | `~/.dcp` |
| `VAULT_PORT` | Server port | `8420` |
| `DCP_MCP_SESSION_MINUTES` | MCP auto‑unlock window after UI unlock | `30` |

## Unlock / Lock

Unlock the REST process:

```bash
curl -X POST http://127.0.0.1:8420/v1/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<your-passphrase>"}'
```

Lock:
```bash
curl -X POST http://127.0.0.1:8420/v1/vault/lock
```

Unlock MCP via the UI or:

```bash
curl -X POST http://127.0.0.1:8420/v1/vault/unlock-mcp \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<your-passphrase>"}'
```
Unlock‑MCP uses the OS keychain; the passphrase is never written to disk.

## Read / Sign (REST)

```bash
curl -X POST http://127.0.0.1:8420/v1/vault/read \
  -H "Content-Type: application/json" \
  -d '{"scope":"identity.email","agent_name":"my-bot"}'

curl -X POST http://127.0.0.1:8420/v1/vault/sign \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","unsigned_tx":"<base64>","agent_name":"my-bot"}'
```

## Endpoints

**Browser UI**
- `GET /` — local approval UI (dark/light toggle, auto‑refresh)

**Core**
- `GET /health`
- `GET /scopes`
- `GET /address/:chain`
- `GET /budget/check` (requires `chain` for USDC/USDT)
- `GET /agents`
- `GET /consent`
- `POST /consent/:id/approve`
- `POST /consent/:id/deny`
- `POST /revoke/:agent`

**v1**
- `POST /v1/vault/read`
- `POST /v1/vault/sign`
- `GET /v1/vault/activity` (supports `limit`, `agent`, `type`, `since`)
- `POST /v1/vault/unlock`
- `POST /v1/vault/lock`
- `POST /v1/vault/agents/:id/revoke`
- `GET /v1/vault/mcp-status`

Docs: see the root README for the full security model.
