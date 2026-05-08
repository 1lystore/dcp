# DCP — Delegated Custody Protocol

**Your keys and sensitive data stay in your vault. Agents get results, not possession.**

DCP is an open protocol and reference implementation for letting AI agents use wallets, API keys, identity data, addresses, and other sensitive records without taking custody of the raw secrets.

## What DCP Gives You

- A local encrypted vault for wallets, credentials, identity, addresses, and preferences
- Local MCP and REST interfaces for same-machine agents
- Relay support for remote services and VPS agents
- Consent, sessions, budgets, and audit logs around every access path
- A desktop app for normal users and a CLI/SDK path for developers
- Telegram notifications for remote consent approval

## Packages

| Package | Purpose |
| --- | --- |
| `@dcprotocol/core` | Encryption, storage, wallet management, pairing, budgets, and audit primitives |
| `@dcprotocol/vault` | CLI + REST server for vault operations |
| `@dcprotocol/agent` | Lightweight agent binary with MCP server, HTTP proxy, and pairing |
| `@dcprotocol/relay` | Reference relay server for the default public relay or your own deployment |
| `@dcprotocol/telegram` | Telegram notification service for consent approvals |
| `@dcprotocol/desktop` | Desktop app (Tauri + React) |

## Ways To Run DCP

### 1. Desktop app

Use this if you want the easiest local human-operated vault.

Good for:
- normal users
- local desktop approvals
- hosted relay setup
- generating VPS agent pairing commands
- Telegram notification setup

### 2. CLI + local REST server

Use this if you want an HTTP interface for local tools or browser-based approvals.

```bash
# Install vault CLI
npm install -g @dcprotocol/vault

# Initialize and run
dcp init
dcp-vault start
```

Good for:
- local development
- non-MCP agent runtimes
- headless environments
- SSH-managed vaults

### 3. MCP agent (for Claude Desktop, Cursor, etc.)

Use this when your agent runtime supports MCP.

```bash
# Install agent
npm install -g @dcprotocol/agent

# Pair with vault (get token from desktop or CLI)
dcp-agent pair dcp_pair_v1_...

# Run in MCP mode
dcp-agent run --mode mcp
```

Good for:
- Claude Desktop
- Cursor
- VS Code
- any MCP-compatible host

### 4. VPS agent + relay

Use this when your agent runs on a different machine from the vault.

```bash
# On VPS: one-liner install
curl -fsSL https://dcp.1ly.store/install | sh -s -- --pair dcp_pair_v1_...

# Or manually
dcp-agent pair dcp_pair_v1_...
dcp-agent run --mode proxy --daemon
```

Good for:
- remote VPS agents
- OpenClaw on a server
- agent fleets
- systemd services

## Prerequisites

- Node.js `>=22 <23`
- Run `nvm use` from the repo root before installing or building
- pnpm (`npm install -g pnpm` or use corepack)
- Rust stable is required only for the desktop app
- `better-sqlite3`, `keytar`, and `sodium-native` may need a rebuild if you switch Node versions

### Linux notes

- `@dcprotocol/core` and `@dcprotocol/vault` use local native/keychain components
- on Debian/Ubuntu, install `libsecret-1-0` for keychain-backed operator flows
- for remote VPS agents, use `@dcprotocol/agent`; it is the lightweight path and does not require the local human CLI stack

## Developer Setup

### Clone and install

```bash
git clone https://github.com/1lystore/dcp.git
cd dcp
pnpm install
```

### Build everything

```bash
pnpm run build
```

### Run the full test suite

```bash
pnpm test

# Or individual packages
pnpm --filter @dcprotocol/core run test     # 198 tests
pnpm --filter @dcprotocol/vault run test    # 104 tests
pnpm --filter @dcprotocol/agent run test    # 42 tests
pnpm --filter @dcprotocol/telegram run test # 59 tests
```

### If native modules break

```bash
pnpm rebuild better-sqlite3
```

## Normal User Flow

### Desktop app from source

```bash
pnpm install
pnpm run build
cd packages/dcp-desktop
pnpm run tauri:dev
```

### Build a distributable app bundle

```bash
cd packages/dcp-desktop
pnpm run bundle
pnpm run tauri:build
```

macOS bundle outputs:
- `packages/dcp-desktop/src-tauri/target/release/bundle/macos/DCP Vault.app`
- `packages/dcp-desktop/src-tauri/target/release/bundle/dmg/DCP Vault_0.2.0_aarch64.dmg`

### Normal user path inside the desktop app

1. Create or unlock the vault
2. Create one or more wallets
3. Open **Connect**
4. Set relay to `wss://relay.dcp.1ly.store` or your own relay
5. Open **Agents** to generate pairing tokens for VPS agents
6. Open **Settings** to trust services, configure budgets, or set up Telegram notifications
7. Approve requests in the built-in consent UI or via Telegram

## Developer Flow: CLI + Local REST

Install the published CLI:

```bash
npm install -g @dcprotocol/vault
```

Initialize a vault and create a wallet:

```bash
dcp init
dcp create-wallet --chain solana
```

Add some records:

```bash
dcp add address.home
dcp add identity.email
dcp add credentials.api.openai
```

Start the local REST server:

```bash
dcp-vault start
# or
npx -y @dcprotocol/vault start
```

The server listens on `http://127.0.0.1:8421`.

## Developer Flow: MCP Agent

Install the agent package:

```bash
npm install -g @dcprotocol/agent
```

Pair with a vault (get token from desktop app or `dcp pairing start`):

```bash
dcp-agent pair dcp_pair_v1_...
```

Add MCP server to your MCP client config:

```json
{
  "mcpServers": {
    "dcp": {
      "command": "dcp-agent",
      "args": ["run", "--mode", "mcp"]
    }
  }
}
```

Available MCP tools:
- `vault_get_address` - Get public wallet address
- `vault_budget_check` - Check budget limits
- `vault_read` - Read data or credentials
- `vault_sign_tx` - Sign transactions
- `vault_sign_message` - Sign messages
- `vault_sign_typed_data` - Sign EIP-712 typed data
- `vault_write` - Write allowed scopes

## Developer Flow: Programmatic Access

For programmatic access, use the REST API or MCP tools:

**REST API** (local agents):
```ts
const response = await fetch('http://127.0.0.1:8421/v1/vault/sign_message', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    chain: 'solana',
    message: 'hello from DCP',
    agent_name: 'my-agent'
  })
});
```

**MCP** (Claude Desktop, Cursor, etc.):
```json
{
  "mcpServers": {
    "dcp": {
      "command": "dcp-agent",
      "args": ["run", "--mode", "mcp"]
    }
  }
}
```

For remote access via relay, use `@dcprotocol/agent` which handles pairing and encrypted transport.

## Remote Agent / VPS Flow

This is the simplest operator flow for a remote agent that must use your local DCP vault.

### Vault side

1. Run the vault locally via Desktop or CLI
2. Connect it to a relay
3. Generate a pairing token with scopes and budgets

With the CLI:

```bash
dcp pairing start my-vps-agent \
  --scopes sign:solana,budget:check \
  --budget 10usdc/day \
  --auto-approve-under 1usdc
```

With the desktop app:
- open **Agents** page
- configure permissions and budget
- click **Generate Pairing Token**
- copy the generated VPS command

### VPS side

**Option 1: One-liner install**

```bash
curl -fsSL https://dcp.1ly.store/install | sh -s -- --pair dcp_pair_v1_...
```

**Option 2: Manual setup**

```bash
# Install
npm install -g @dcprotocol/agent

# Pair (one-time)
dcp-agent pair dcp_pair_v1_...

# Run as proxy daemon
dcp-agent run --mode proxy --daemon

# Or install as systemd service
dcp-agent install-service
```

Then your remote agent can talk to local DCP-style endpoints:

```bash
export DCP_URL=http://127.0.0.1:8420
```

### Agent modes

| Mode | Description | Use case |
| --- | --- | --- |
| `proxy` | HTTP REST proxy on 127.0.0.1:8420 | OpenClaw, custom agents |
| `mcp` | stdio MCP server | Claude Desktop, Cursor |
| `http-mcp` | Streamable HTTP MCP | VPS agents, Hermes |

### OpenClaw integration

DCP Agent implements the OpenClaw exec provider protocol:

```json5
// openclaw.json5
{
  secrets: {
    providers: {
      dcp: {
        source: "exec",
        command: "dcp-agent",
        args: ["secrets"]
      }
    }
  }
}
```

## Service / Marketplace Flow

Use this flow when the remote party is a stable service with its own identity, such as `1ly` or `Virtuals`.

### Trust a known service

```bash
dcp trust 1ly
```

### Connect it

```bash
dcp connect 1ly
```

### Custom services

```bash
dcp trust my-service \
  --key ed25519:<base64-public-key> \
  --scopes sign:solana,read:credentials.api.* \
  --budget 10usdc/day \
  --auto-approve-under 1usdc

dcp connect my-service \
  --url https://example.com/api/dcp/connect \
  --auth-url https://example.com/settings/dcp
```

`dcp connect` sends the vault routing bundle to the service:
- `vault_id`
- `hpke_public_key`
- `relay_url`
- granted scopes

### Known services

The registry includes verified services such as:
- `1ly` - 1ly Store marketplace
- `Virtuals` - Virtuals Protocol

## Relay Server

### Default public relay

The DCP maintainers run a default public relay at:

```text
wss://relay.dcp.1ly.store
```

Use it for convenience while testing or for normal desktop users.

This relay is:
- optional
- replaceable
- not required by the protocol

You can swap it for your own relay anywhere DCP asks for a relay URL.

The default public relay is used throughout the repo examples for:
- `@dcprotocol/agent`
- desktop Connect page
- `dcp connect`

### Self-hosted relay

If you do not want to depend on the public relay, run your own. The protocol does not require `relay.dcp.1ly.store`.

Install or run it directly:

```bash
npx -y @dcprotocol/relay
```

Run with flags:

```bash
npx -y @dcprotocol/relay --port 8421 --host 0.0.0.0 --rate-limit 60 --debug
```

### Relay environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `DCP_RELAY_PORT` | Relay listen port | `8421` |
| `DCP_RELAY_HOST` | Relay bind host | `0.0.0.0` |
| `DCP_RELAY_DEBUG` | Debug logging | `false` |
| `DCP_RELAY_RATE_LIMIT` | Max requests per vault per minute | `60` |

### Relay endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Health check |
| `/stats` | GET | Relay stats |
| `/metrics` | GET | JSON or Prometheus metrics |
| `/relay/request` | POST | Submit encrypted request |
| `/relay/response/:requestId` | GET | Poll for encrypted response |
| `/relay/poll` | POST | Long-poll fallback for vaults |
| `/relay/respond` | POST | Long-poll response submission |
| `/ws` | WebSocket | Vault connection endpoint |
| `/ws-client` | WebSocket | Client/service connection endpoint |

### Relay deployment notes

- Relay is transport only. It should not see plaintext vault data.
- Relay can be hosted publicly.
- Vaults connect outbound to the relay.
- Remote services or proxies target the relay, not the local vault directly.
- Metrics and rate limiting are built in.

## REST API Surface (`@dcprotocol/vault`)

DCP vault server binds to `127.0.0.1:8421` only by default. It is for local use.

### Core routes

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Health check |
| `/scopes` | GET | List stored scopes |
| `/address/:chain` | GET | Get wallet address |
| `/budget/check` | GET | Budget check |
| `/agents` | GET | List active sessions |
| `/consent` | GET | List pending consents |
| `/consent/:id/approve` | POST | Approve consent |
| `/consent/:id/deny` | POST | Deny consent |
| `/revoke/:agent` | POST | Revoke all sessions for an agent |

### Vault operation routes

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/v1/vault/unlock` | POST | Unlock the vault |
| `/v1/vault/lock` | POST | Lock the vault |
| `/v1/vault/read` | POST | Read a scope with consent/session checks |
| `/v1/vault/write` | POST | Write an allowed scope |
| `/v1/vault/sign` | POST | Sign a transaction |
| `/v1/vault/sign-message` | POST | Sign a message |
| `/v1/vault/sign_typed_data` | POST | Sign EIP-712 typed data |
| `/v1/vault/sign_x402` | POST | Sign x402 payload |
| `/v1/vault/activity` | GET | Read audit activity |

### Owner/Desktop routes

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/v1/desktop/register` | POST | Register desktop identity |
| `/v1/desktop/challenge` | GET | Fetch challenge for desktop auth |
| `/v1/desktop/verify` | POST | Verify challenge and issue owner token |
| `/v1/relay/info` | GET | Get vault relay bundle |
| `/v1/relay/config` | POST | Update relay URL |
| `/v1/pairing/start` | POST | Create pairing token |
| `/v1/vault/budgets` | GET/POST | Read/update vault budgets |
| `/v1/services` | GET/POST | List/create trusted services |
| `/v1/services/:id` | PATCH/DELETE | Update/revoke trusted service |

### Example REST calls

Unlock:

```bash
curl -X POST http://127.0.0.1:8421/v1/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<your-passphrase>"}'
```

Read:

```bash
curl -X POST http://127.0.0.1:8421/v1/vault/read \
  -H "Content-Type: application/json" \
  -d '{"scope":"identity.email","agent_name":"my-bot"}'
```

Sign message:

```bash
curl -X POST http://127.0.0.1:8421/v1/vault/sign_message \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","message":"hello","agent_name":"my-bot"}'
```

## MCP Tools (`@dcprotocol/agent`)

Available MCP tools when running `dcp-agent run --mode mcp`:

| Tool | Purpose |
| --- | --- |
| `vault_get_address` | Get a public address |
| `vault_budget_check` | Check budget limits |
| `vault_read` | Read data or credentials |
| `vault_sign_tx` | Sign a transaction |
| `vault_sign_message` | Sign a message |
| `vault_sign_typed_data` | Sign EIP-712 typed data |
| `vault_write` | Write supported scopes |

## CLI Commands (`@dcprotocol/vault`)

| Command | Purpose |
| --- | --- |
| `dcp init` | Initialize new vault with passphrase |
| `dcp create-wallet` | Create a wallet |
| `dcp add <scope>` | Add item to vault |
| `dcp remove <scope>` | Remove item from vault |
| `dcp read <scope>` | Read decrypted item |
| `dcp list` | List all items |
| `dcp pairing start` | Create pairing token |
| `dcp trust <service>` | Trust a service |
| `dcp connect <service>` | Connect to a service |
| `dcp agents` | List agent connections |
| `dcp revoke <agent>` | Revoke agent session |
| `dcp activity` | View audit log |
| `dcp status` | Show vault status |

## Agent Commands (`@dcprotocol/agent`)

| Command | Purpose |
| --- | --- |
| `dcp-agent pair <grant>` | Pair with vault |
| `dcp-agent run` | Run agent (--mode proxy/mcp/http-mcp) |
| `dcp-agent status` | Show agent status |
| `dcp-agent list` | List configured agents |
| `dcp-agent remove <id>` | Remove agent config |
| `dcp-agent secrets` | OpenClaw secrets provider |
| `dcp-agent get-secret <scope>` | Fetch single secret |
| `dcp-agent install-service` | Install as systemd service |
| `dcp-agent uninstall-service` | Uninstall systemd service |

## Environment Variables

### Vault (`@dcprotocol/vault`)

| Variable | Purpose | Default |
| --- | --- | --- |
| `VAULT_DIR` | Vault storage directory | `~/.dcp` |
| `VAULT_PORT` | REST server port | `8421` |

### Agent (`@dcprotocol/agent`)

| Variable | Purpose | Default |
| --- | --- | --- |
| `DCP_AGENT_PORT` | Proxy server port | `8420` |
| `DCP_AGENT_DEBUG` | Enable debug logging | `false` |

### Relay (`@dcprotocol/relay`)

| Variable | Purpose | Default |
| --- | --- | --- |
| `DCP_RELAY_PORT` | Relay listen port | `8421` |
| `DCP_RELAY_HOST` | Relay bind host | `0.0.0.0` |
| `DCP_RELAY_DEBUG` | Debug logging | `false` |
| `DCP_RELAY_RATE_LIMIT` | Max requests per vault per minute | `60` |

### Telegram (`@dcprotocol/telegram`)

| Variable | Purpose | Default |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | Required |
| `DCP_TELEGRAM_PORT` | Webhook server port | `8422` |
| `DCP_TELEGRAM_SECRET` | Webhook verification secret | Auto-generated |

## Security Model

DCP is built around one rule:

**Critical secrets stay in the vault.**

That means:
- private keys never leave the vault
- agents get signatures, not raw keys
- services get transport to the vault, not custody of the vault
- budgets and thresholds limit damage from bad prompts or bad logic
- every request is auditable
- relay is transport, not plaintext business logic

See `SECURITY.md` for the full threat model.

## Troubleshooting

### Native dependency mismatch

```bash
pnpm rebuild better-sqlite3
```

### Local ports already in use

DCP defaults:
- `8420` for the agent proxy
- `8421` for the vault server and desktop app
- `8422` for the Telegram webhook server

Check who is using them:

```bash
lsof -nP -iTCP:8420 -sTCP:LISTEN  # Agent proxy
lsof -nP -iTCP:8421 -sTCP:LISTEN  # Vault server / Desktop app
lsof -nP -iTCP:8422 -sTCP:LISTEN  # Telegram service
```

### Desktop build runs but the installed app looks stale

Open the newly built bundle directly first:

```bash
open "packages/dcp-desktop/src-tauri/target/release/bundle/macos/DCP Vault.app"
```

Then replace the older installed copy.

## Package-Specific Docs

- `packages/dcp-core/README.md` - Core crypto and storage
- `packages/dcp-vault/README.md` - CLI and server
- `packages/dcp-agent/README.md` - Agent binary and MCP
- `packages/dcp-relay/README.md` - Relay server
- `packages/dcp-telegram/README.md` - Telegram notifications
- `packages/dcp-desktop/README.md` - Desktop app

## Additional Docs

- `ARCHITECTURE.md`
- `SECURITY.md`
- `SCHEMA.md`
- `CONTRIBUTING.md`
- `RELEASE.md`

## License

Apache-2.0
