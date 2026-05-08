# @dcprotocol/vault

Local vault runtime with CLI and REST server for DCP. This package provides both the human operator interface (CLI) and the local HTTP server for agent access.

## Installation

```bash
npm install -g @dcprotocol/vault
```

## Quick Start

### Initialize a vault

```bash
dcp init
```

This will:
- Prompt for a passphrase
- Generate a recovery phrase (write it down!)
- Create the vault at `~/.dcp`

### Create a wallet

```bash
dcp create-wallet --chain solana
```

### Add some data

```bash
dcp add address.home
dcp add identity.email
dcp add credentials.api.openai
```

### Start the REST server

```bash
dcp-vault start
# or
npx -y @dcprotocol/vault start
```

The server listens on `http://127.0.0.1:8421` (localhost only).

## CLI Commands

| Command | Description |
|---------|-------------|
| `dcp init` | Initialize new vault with passphrase and recovery phrase |
| `dcp create-wallet --chain <chain>` | Create a wallet (solana, ethereum, base) |
| `dcp add <scope>` | Add item to vault (prompts for data) |
| `dcp remove <scope>` | Remove item from vault |
| `dcp read <scope>` | Read decrypted item |
| `dcp list` | List all items in vault |
| `dcp pairing start <name>` | Create pairing token for VPS agent |
| `dcp trust <service-id>` | Trust a known service |
| `dcp connect <service-id>` | Connect to a trusted service |
| `dcp agents` | List agent connections |
| `dcp revoke <agent-id>` | Revoke agent session |
| `dcp approve <consent-id>` | Approve pending consent |
| `dcp activity` | View audit log |
| `dcp config` | Manage vault configuration |
| `dcp recovery` | Recovery phrase operations |
| `dcp status` | Show vault status |

## Server Commands

| Command | Description |
|---------|-------------|
| `dcp-vault start` | Start the REST server |
| `dcp-vault start --port 9000` | Start on custom port |

## REST API

The server binds to `127.0.0.1:8421` only (localhost).

### Health & Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/scopes` | GET | List available scopes |
| `/address/:chain` | GET | Get wallet address |
| `/budget/check` | GET | Check spend budget |
| `/agents` | GET | List active agent sessions |
| `/consent` | GET | List pending consents |
| `/consent/:id/approve` | POST | Approve consent |
| `/consent/:id/deny` | POST | Deny consent |
| `/revoke/:agent` | POST | Revoke agent session |

### Vault Operations

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/vault/unlock` | POST | Unlock vault |
| `/v1/vault/lock` | POST | Lock vault |
| `/v1/vault/read` | POST | Read scope (with consent) |
| `/v1/vault/write` | POST | Write scope |
| `/v1/vault/sign` | POST | Sign transaction |
| `/v1/vault/sign-message` | POST | Sign message |
| `/v1/vault/sign_typed_data` | POST | Sign EIP-712 typed data |
| `/v1/vault/sign_x402` | POST | Sign x402 payload |
| `/v1/vault/activity` | GET | Get audit events |

### Owner/Desktop Routes

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/desktop/register` | POST | Register desktop identity |
| `/v1/desktop/challenge` | GET | Fetch auth challenge |
| `/v1/desktop/verify` | POST | Verify challenge |
| `/v1/relay/info` | GET | Get relay bundle |
| `/v1/relay/config` | POST | Update relay URL |
| `/v1/pairing/start` | POST | Create pairing token |
| `/v1/vault/budgets` | GET/POST | Read/update budgets |
| `/v1/services` | GET/POST | List/create trusted services |
| `/v1/services/:id` | PATCH/DELETE | Update/revoke service |

## Example API Calls

### Unlock vault

```bash
curl -X POST http://127.0.0.1:8421/v1/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"your-passphrase"}'
```

### Read data

```bash
curl -X POST http://127.0.0.1:8421/v1/vault/read \
  -H "Content-Type: application/json" \
  -d '{"scope":"identity.email","agent_name":"my-bot"}'
```

### Sign message

```bash
curl -X POST http://127.0.0.1:8421/v1/vault/sign_message \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","message":"hello","agent_name":"my-bot"}'
```

### Create pairing token

```bash
curl -X POST http://127.0.0.1:8421/v1/pairing/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <owner-token>" \
  -d '{"agent_name":"my-vps-agent","scopes":["sign:solana"],"budget":{"daily":10,"currency":"SOL"}}'
```

## Pairing Flow

Generate a pairing token for a VPS agent:

```bash
dcp pairing start my-vps-agent \
  --scopes sign:solana,read:credentials.api.* \
  --budget 10usdc/day \
  --auto-approve-under 1usdc
```

This outputs a `dcp_pair_v1_...` token that can be used with `dcp-agent pair`.

## Relay Connection

Connect the vault to a relay for remote agent access:

```bash
# Via CLI
dcp connect --relay wss://relay.dcp.1ly.store

# Or via REST API
curl -X POST http://127.0.0.1:8421/v1/relay/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <owner-token>" \
  -d '{"relay_url":"wss://relay.dcp.1ly.store"}'
```

## Security Features

- **Unlock Rate Limiting**: 5 failed attempts/minute → 5 minute lockout
- **Owner Authentication**: Challenge-response with Ed25519 keypairs
- **Session Timeouts**: 30 minutes idle, 4 hours max
- **Consent Flow**: All sensitive operations require user approval
- **Audit Logging**: All operations are logged

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VAULT_DIR` | Vault storage directory | `~/.dcp` |
| `VAULT_PORT` | REST server port | `8421` |

## Related Packages

- `@dcprotocol/core` - Core crypto and storage
- `@dcprotocol/agent` - Agent binary for VPS/MCP
- `@dcprotocol/relay` - Relay server
- `@dcprotocol/telegram` - Telegram notifications

## License

Apache-2.0
