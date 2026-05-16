# Architecture

DCP is a local vault and approval layer for AI agents.

The core rule is simple: agents may use approved capabilities, but they should not receive raw private keys, API keys, or other secrets.

## Current Package Map

```text
packages/
  dcp-core/          crypto, storage, wallet, budget, pairing, shared types
  dcp-vault/         local vault CLI and HTTP server
  dcp-agent/         MCP, HTTP MCP, local proxy, and remote sidecar runtime
  dcp-client/        programmatic client used by agent/vault internals
  dcp-relay/         encrypted relay service for remote agents
  dcp-relay-client/  internal relay transport client
  dcp-telegram/      Telegram pairing and approval service
  dcp-desktop/       Tauri desktop app
```

There is no separate `dcp-cli`, `dcp-server`, or `dcp-mcp` package in the current architecture. Those responsibilities now live in `dcp-vault` and `dcp-agent`.

## High-Level System

```text
                 local machine

  ┌──────────────────────────────────────────────────────────────┐
  │ DCP Desktop                                                   │
  │ - create/unlock vault                                         │
  │ - manage identity, credentials, wallets                       │
  │ - configure agent policy                                      │
  │ - approve/deny requests                                       │
  │ - create remote invites                                       │
  └───────────────┬──────────────────────────────────────────────┘
                  │ owns/starts local runtime
                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ dcp-vault                                                     │
  │ - CLI: dcp init, add, list, agents, revoke, pairing           │
  │ - HTTP server: health, read, write, sign, consent, audit      │
  │ - policy and approval checks                                  │
  └───────────────┬──────────────────────────────────────────────┘
                  │ uses
                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ dcp-core                                                      │
  │ - SQLite storage                                              │
  │ - encrypted records                                           │
  │ - wallet creation/signing                                     │
  │ - budgets and audit events                                    │
  │ - pairing and shared protocol types                           │
  └──────────────────────────────────────────────────────────────┘
```

## Local Agent Paths

Agents connect through `dcp-agent`.

```text
Claude/Cursor/VS Code/Hermes
      │ stdio MCP
      ▼
  dcp-agent run --mode mcp
      │
      ▼
  local DCP vault
```

```text
OpenClaw/Hermes/custom agent
      │ HTTP MCP
      ▼
  dcp-agent run --mode http-mcp --port 8420
      │
      ▼
  local DCP vault
```

```text
custom HTTP caller
      │ proxy-compatible HTTP
      ▼
  dcp-agent run --mode proxy --port 8420
      │
      ▼
  local DCP vault or relay path
```

The agent runtime never needs direct access to vault private keys.

## Remote/VPS Path

The remote path is sidecar + relay.

```text
remote VPS
┌────────────────────┐
│ AI agent            │
│ OpenClaw/Hermes/etc │
└─────────┬──────────┘
          │ localhost HTTP MCP
          ▼
┌────────────────────┐        encrypted envelopes        ┌────────────────────┐
│ dcp-agent sidecar   │ ───────────────────────────────▶ │ dcp-relay           │
│ 127.0.0.1:8420      │ ◀─────────────────────────────── │ public/staging      │
└────────────────────┘                                  └─────────┬──────────┘
                                                                  │
                                                                  ▼
                                                        ┌────────────────────┐
                                                        │ local DCP vault     │
                                                        │ Desktop approves    │
                                                        └────────────────────┘
```

The relay routes encrypted data. It is not supposed to see plaintext secrets, transaction payloads, private keys, or credential values.

## Telegram Approval Path

Telegram is a second approval surface, not a vault.

```text
agent request
    │
    ▼
local vault creates pending consent
    │
    ├── Desktop shows approval
    │
    └── dcp-telegram sends privacy-safe message
          │
          ▼
      user taps Approve/Deny
          │
          ▼
      approval command is queued
          │
          ▼
      vault processes result
```

Telegram messages must stay privacy-safe. They may include agent name, request category, and basic human-readable context. They must not include private keys, API keys, raw transaction payloads, credentials, or full sensitive values.

Example approved format:

```text
🔐 Approval Needed

Claude Desktop wants to send 0.02 SOL on Solana.

⏱️ Reply within 4m 58s
```

## Storage Model

Default vault directory:

```text
~/.dcp
```

Primary local database:

```text
~/.dcp/vault.db
```

Important tables:

```text
vault_records        encrypted identity, preference, credential, wallet records
agent_connections    paired local/remote agents and status
agent_sessions       temporary approvals/session grants
pending_consents     requests awaiting approval
spend_events         budget/accounting events
audit_events         immutable operation log
telegram_*           pairing, notification, nonce, and approval command state
```

Master key storage:

```text
primary:  OS keychain where available
fallback: local key file with owner-only permissions
```

## Request Flow

### Read

```text
agent -> dcp-agent -> vault server -> policy check
                              │
                              ├── if allowed: decrypt non-critical record
                              ├── if approval needed: create pending consent
                              └── if critical: return reference/error, not raw secret
```

### Sign

```text
agent -> dcp-agent -> vault server -> policy + budget check
                              │
                              ├── if approval needed: create pending consent
                              ├── if denied/revoked/over budget: fail clearly
                              └── if allowed: decrypt wallet key in-process, sign, zeroize
```

The private key should never be returned to the agent, logged, sent to Telegram, or routed through the relay.

## Package Dependency Direction

```text
dcp-vault       -> dcp-core, dcp-client, dcp-relay-client
dcp-agent       -> dcp-core, dcp-client
dcp-client      -> dcp-core
dcp-relay-client-> dcp-relay
dcp-telegram    -> dcp-core
dcp-desktop     -> bundled dcp-vault runtime
```

`dcp-core` should not depend on higher-level packages.

## Build Artifacts

Desktop generated resources live under:

```text
packages/dcp-desktop/src-tauri/resources/
  dcp-helper-bundle.cjs
  dcp-vault-bundle.cjs
  dcp-vault-runtime/
```

Do not hand-edit generated bundles. Regenerate them with:

```bash
pnpm -r run build
pnpm --filter @dcprotocol/desktop run bundle:helper
```

## Readiness Gates

Before beta release:

```bash
node scripts/publish-guard.mjs
pnpm -r run typecheck
pnpm -r run test
pnpm -r run build
./scripts/test-security.sh
```

Also required:

- clean-room npm tarball install
- local MCP agent test
- local HTTP MCP test
- same-machine VPS simulation
- live Telegram pairing and approval test
- real VPS/staging relay test before public beta
