# @dcprotocol/server

Local REST API + approval UI for DCP Vault. Binds to `127.0.0.1` only.

Use this when:
- You want browser‑based approvals
- Your agent runtime can’t spawn MCP subprocesses
- You need a local HTTP interface
- You want to connect a local vault to the default public relay or your own relay for remote agents

## Install

```bash
npm install @dcprotocol/server
```

On Debian/Ubuntu, local keychain-backed usage may require `libsecret-1-0`.

## Run

```bash
npx -y @dcprotocol/server
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
| `DCP_RELAY_URL` | Relay URL for remote agent access | unset |
| `DCP_MCP_SESSION_MINUTES` | MCP auto‑unlock window after UI unlock | `30` |

If `DCP_RELAY_URL` is set, the server will connect the local vault to that relay after startup/unlock.

Use `wss://relay.dcp.1ly.store` if you want the default public relay run by the DCP maintainers, or set your own relay URL instead.

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

**Owner / relay**
- `GET /v1/relay/info`
- `POST /v1/relay/config`
- `POST /v1/pairing/start`
- `GET /v1/services`
- `POST /v1/services`
- `PATCH /v1/services/:id`
- `DELETE /v1/services/:id`

## Remote Agent Flow

This package is the local vault side of the relay flow:

1. Start the server locally
2. Set a relay URL
3. Create a pairing token or trust a service
4. Let a remote agent connect through `@dcprotocol/client` or the DCP proxy
5. Approve consent locally when required

For the full end-user flow, see the root README and the desktop package README.

Docs: see the root README for the full security model.
