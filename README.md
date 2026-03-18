# DCP — Delegated Custody Protocol

**Your keys and sensitive data stay in your vault. Agents get results, not possession.**

DCP is an open protocol and reference implementation for letting AI agents use wallets, API keys, identity data, addresses, and other sensitive records without taking custody of the raw secrets.

## What DCP Gives You

- A local encrypted vault for wallets, credentials, identity, addresses, and preferences
- Local MCP and REST interfaces for same-machine agents
- Relay support for remote services and VPS agents
- Consent, sessions, budgets, and audit logs around every access path
- A desktop app for normal users and a CLI/SDK path for developers

## Packages

| Package | Purpose | Published |
| --- | --- | --- |
| `@dcprotocol/cli` | Human/operator CLI for vault setup, approval, trust, connect, pairing, and proxy flows | Yes |
| `@dcprotocol/client` | Universal agent SDK for local or relay-backed access to a vault | Yes |
| `@dcprotocol/core` | Encryption, storage, schema, budgets, trusted services, and audit primitives | Yes |
| `@dcprotocol/server` | Local REST server and browser approval UI | Yes |
| `@dcprotocol/mcp` | MCP server for Claude, Cursor, OpenClaw, and similar tools | Yes |
| `@dcprotocol/relay` | Hosted or self-hosted relay for remote agents and services | Yes |
| `@dcprotocol/relay-client` | Vault-side relay client used by the server/runtime | Yes |
| `packages/dcp-desktop` | Desktop app source and bundle packaging | No |

## Ways To Run DCP

### 1. Desktop app

Use this if you want the easiest local human-operated vault.

Good for:
- normal users
- local desktop approvals
- hosted relay setup
- generating a single VPS proxy command

### 2. CLI + local REST server

Use this if you want an HTTP interface for local tools or browser-based approvals.

Good for:
- local development
- non-MCP agent runtimes
- headless environments
- SSH-managed vaults

### 3. CLI + MCP server

Use this when your agent runtime supports MCP.

Good for:
- Claude Desktop
- Cursor
- OpenClaw
- any MCP-compatible host

### 4. `@dcprotocol/client`

Use this when you want to integrate DCP directly into code.

Good for:
- custom apps
- non-MCP agents
- direct local REST access
- direct relay-backed service integrations

### 5. VPS proxy + relay

Use this when your agent runs on a different machine from the vault, but you still want the agent to talk to a simple localhost-style DCP endpoint.

Good for:
- remote VPS agents
- OpenClaw on a server
- agent fleets that should not speak relay directly

## Prerequisites

- Node.js `>=18 <23`
- Node 20 LTS is the safest default for native module stability
- Rust stable is required only for the desktop app
- `better-sqlite3` may need a rebuild if you switch Node versions

## Developer Setup

### Clone and install

```bash
git clone https://github.com/1lystore/dcp.git
cd dcp
npm install
```

### Build everything

```bash
npm run build
```

### Run the full test suite

```bash
npm test
```

### If native modules break

```bash
npm rebuild better-sqlite3
```

## Normal User Flow

### Desktop app from source

```bash
npm install
npm -w @dcprotocol/server run build
cd packages/dcp-desktop
npm run tauri:dev
```

### Build a distributable app bundle

```bash
cd packages/dcp-desktop
npm run tauri:build
```

macOS bundle outputs:
- `packages/dcp-desktop/src-tauri/target/release/bundle/macos/DCP Vault.app`
- `packages/dcp-desktop/src-tauri/target/release/bundle/dmg/DCP Vault_0.1.0_aarch64.dmg`

### Normal user path inside the desktop app

1. Create or unlock the vault
2. Create one or more wallets
3. Open **Connect**
4. Set relay to `wss://relay.dcp.1ly.store` or your own relay
5. Open **Settings** to trust a service or configure budgets
6. Approve requests in the built-in consent UI

## Developer Flow: CLI + Local REST

Install the published CLI:

```bash
npm install -g @dcprotocol/cli
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
npx @dcprotocol/server
```

Open the local approval UI at `http://127.0.0.1:8420`.

## Developer Flow: MCP

Add the DCP MCP server to your MCP client:

```json
{
  "mcpServers": {
    "dcp": {
      "command": "npx",
      "args": ["@dcprotocol/mcp"]
    }
  }
}
```

Recommended environment for stable session reuse:

```bash
MCP_AGENT_NAME=claude-desktop
```

If the vault is locked, call `vault_unlock` once before reads or signing.

## Developer Flow: `@dcprotocol/client`

Install:

```bash
npm install @dcprotocol/client
```

Local-first example:

```ts
import { DcpClient } from '@dcprotocol/client';

const dcp = new DcpClient({
  mode: 'auto',
  agentName: 'my-agent',
  vaultId: process.env.DCP_VAULT_ID,
  relayUrl: process.env.DCP_RELAY_URL,
  vaultHpkePublicKey: process.env.DCP_VAULT_HPKE_PUBLIC_KEY,
  serviceId: process.env.DCP_SERVICE_ID,
  servicePrivateKey: process.env.DCP_SERVICE_PRIVATE_KEY,
});

const { address } = await dcp.getAddress('solana');
const result = await dcp.signMessage({
  chain: 'solana',
  message: 'hello from DCP',
});
```

Direct relay mode requires a service identity key. If you do not want the agent process to hold that identity, use `dcp proxy` on the remote machine instead.

## Remote Agent / VPS Flow

This is the simplest operator flow for a remote agent that must use your local DCP vault.

### Vault side

1. Run the vault locally via Desktop or CLI/server
2. Connect it to a relay
3. Generate a pairing token with scopes and budgets

With the CLI:

```bash
dcp pairing start openclaw-vps \
  --scopes sign:solana,budget:check \
  --budget 10usdc/day \
  --auto-approve-under 1usdc
```

With the desktop app:
- open **Connect**
- click **Use relay.dcp.1ly.store**
- click **Save Relay**
- choose permissions and budget
- click **Generate Pairing Token**
- copy the generated VPS command

### VPS side

Run the one-command proxy setup:

```bash
npx -y @dcprotocol/cli proxy \
  --pair "<pairing-token>" \
  --service-id "openclaw-vps" \
  --vault "<vault-id>" \
  --hpke-key "<vault-hpke-public-key>" \
  --relay "wss://relay.dcp.1ly.store" \
  --port 8420
```

Then your remote agent can talk to local DCP-style endpoints on the VPS:

```bash
export DCP_URL=http://127.0.0.1:8420
export DCP_MODE=local
```

That keeps the agent logic simple. The proxy handles relay transport and service identity.

## Service / Marketplace Flow

Use this flow when the remote party is a stable service with its own identity, such as `1ly`.

### Trust the service

```bash
dcp trust 1ly
```

### Connect it

```bash
dcp connect 1ly
```

For custom services:

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

## Relay Server

### Hosted relay

The default public relay URL used throughout the repo is:

```text
wss://relay.dcp.1ly.store
```

This is the default for:
- `@dcprotocol/client`
- desktop Connect page
- `dcp connect`
- `dcp proxy`

### Self-hosted relay

Install or run it directly:

```bash
npx @dcprotocol/relay
```

Run with flags:

```bash
npx @dcprotocol/relay --port 8421 --host 0.0.0.0 --rate-limit 60 --debug
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

## REST API Surface (`@dcprotocol/server`)

DCP server binds to `127.0.0.1` only by default. It is for local use.

### Core local routes

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Local approval UI |
| `/health` | GET | Health check |
| `/scopes` | GET | List stored scopes |
| `/address/:chain` | GET | Get wallet address |
| `/budget/check` | GET | Budget check |
| `/agents` | GET | List active sessions |
| `/consent` | GET | List pending consents |
| `/consent/:id/approve` | POST | Approve consent |
| `/consent/:id/deny` | POST | Deny consent |
| `/revoke/:agent` | POST | Revoke all sessions for an agent |
| `/v1/vault/unlock` | POST | Unlock the server process |
| `/v1/vault/lock` | POST | Lock the server process |
| `/v1/vault/unlock-mcp` | POST | Queue MCP unlock via keychain |
| `/v1/vault/mcp-status` | GET | MCP lock/running status |

### Owner-only routes

These are mainly for the desktop app and authenticated local owner operations.

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/v1/desktop/register` | POST | Register desktop identity |
| `/v1/desktop/challenge` | GET | Fetch challenge for desktop auth |
| `/v1/desktop/verify` | POST | Verify challenge and issue owner token |
| `/v1/relay/info` | GET | Get vault relay bundle |
| `/v1/relay/config` | POST | Update relay URL or relay pairing token |
| `/v1/pairing/start` | POST | Create pairing token for a VPS/service |
| `/v1/vault/budgets` | GET | Read vault budgets |
| `/v1/vault/budgets` | POST | Update vault budgets |
| `/v1/services` | GET | List trusted services |
| `/v1/services/known` | GET | List known service presets |
| `/v1/services` | POST | Create trusted service |
| `/v1/services/:id` | PATCH | Update trusted service |
| `/v1/services/:id` | DELETE | Revoke trusted service |

### Vault operation routes

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/v1/vault/read` | POST | Read a scope with consent/session checks |
| `/v1/vault/write` | POST | Write an allowed scope |
| `/v1/vault/delete` | POST | Delete an allowed scope |
| `/v1/vault/sign` | POST | Sign a transaction |
| `/v1/vault/sign-message` | POST | Sign a message |
| `/v1/vault/sign_message` | POST | Alias for message signing |
| `/v1/vault/sign_typed_data` | POST | Sign EIP-712 typed data |
| `/v1/vault/sign_x402` | POST | Sign x402 payload |
| `/v1/vault/activity` | GET | Read audit activity |
| `/v1/vault/agents/:id/revoke` | POST | Revoke a specific session |

### Example REST calls

Unlock:

```bash
curl -X POST http://127.0.0.1:8420/v1/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<your-passphrase>"}'
```

Read:

```bash
curl -X POST http://127.0.0.1:8420/v1/vault/read \
  -H "Content-Type: application/json" \
  -d '{"scope":"identity.email","agent_name":"my-bot"}'
```

Sign message:

```bash
curl -X POST http://127.0.0.1:8420/v1/vault/sign_message \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","message":"hello","agent_name":"my-bot"}'
```

## MCP Tools (`@dcprotocol/mcp`)

Available tools:

| Tool | Purpose |
| --- | --- |
| `vault_list_scopes` | List available scopes |
| `vault_get_address` | Get a public address |
| `vault_budget_check` | Check budget limits |
| `vault_read` | Read data or credentials |
| `vault_sign_tx` | Sign a transaction |
| `vault_sign_message` | Sign a message |
| `vault_sign_typed_data` | Sign EIP-712 typed data |
| `vault_sign_x402` | Sign x402 payloads |
| `vault_write` | Write supported scopes |
| `vault_unlock` | Unlock MCP process access |
| `vault_lock` | Lock MCP process access |

## Client SDK Methods (`@dcprotocol/client`)

| Method | Purpose |
| --- | --- |
| `isAvailable()` | Check whether the vault can be reached |
| `getAddress(chain)` | Get a public wallet address |
| `signTx(input)` | Sign a transaction |
| `signMessage(input)` | Sign a message |
| `signTypedData(input)` | Sign EIP-712 typed data |
| `signX402(input)` | Sign x402 payload |
| `readCredential(scope, fields?)` | Read a scope |
| `readData(scope, fields?)` | Alias for `readCredential` |
| `writeCredential(scope, data)` | Write an allowed scope |
| `budgetCheck(input)` | Check a budget before signing |
| `pairService(input)` | Pair a remote proxy/service |
| `clearSession()` | Drop cached session IDs |
| `close()` | Close sockets and zeroize local key material |

## Shared Environment Variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `VAULT_DIR` | CLI, MCP, server | Vault storage directory |
| `VAULT_PORT` | Server | REST server port |
| `DCP_URL` | Client, agents via proxy | Local DCP URL |
| `DCP_MODE` | Client | `auto`, `local`, or `relay` |
| `DCP_VAULT_ID` | Client, proxy | Target vault ID for relay |
| `DCP_RELAY_URL` | Client, proxy, server | Relay URL |
| `DCP_VAULT_HPKE_PUBLIC_KEY` | Client, proxy | Vault relay encryption key |
| `DCP_SERVICE_ID` | Client, proxy | Service identity |
| `DCP_SERVICE_PRIVATE_KEY` | Client, proxy | Service signing key |
| `MCP_AGENT_NAME` | MCP, client | Stable agent name |
| `DCP_MCP_ALLOW_TTY` | MCP | Allow interactive terminal prompts |
| `DCP_MCP_SESSION_MINUTES` | MCP, server | Auto-unlock session duration |
| `DCP_CLI_SESSION_MINUTES` | CLI | CLI unlock cache duration |
| `DCP_CLI_INSECURE_SESSION` | CLI | File-based session fallback |

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
npm rebuild better-sqlite3
```

### Local ports already in use

DCP defaults:
- `8420` for the local vault server
- `8421` for a local relay during development

Check who is using them:

```bash
lsof -nP -iTCP:8420 -sTCP:LISTEN
lsof -nP -iTCP:8421 -sTCP:LISTEN
```

### Desktop build runs but the installed app looks stale

Open the newly built bundle directly first:

```bash
open "packages/dcp-desktop/src-tauri/target/release/bundle/macos/DCP Vault.app"
```

Then replace the older installed copy.

## Package-Specific Docs

- `packages/dcp-cli/README.md`
- `packages/dcp-client/README.md`
- `packages/dcp-desktop/README.md`
- `packages/dcp-relay/README.md`
- `packages/dcp-server/README.md`
- `packages/dcp-mcp/README.md`

## Additional Docs

- `ARCHITECTURE.md`
- `SECURITY.md`
- `SCHEMA.md`
- `CONTRIBUTING.md`
- `RELEASE.md`

## License

Apache-2.0
