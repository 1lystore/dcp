# DCP — Delegated Custody Protocol

**Your keys. Your data. Agents use them — never see them.**

DCP is an open protocol for secure agent operations. Store your wallet keys, personal data, and sensitive credentials in an encrypted local vault. AI agents request access, you consent, the vault executes internally. Agents get results — never raw secrets.

## The Problem

AI agents are doing more every day — booking flights, buying groceries, trading crypto, managing subscriptions, filing paperwork. To do any of this, they need access to your most sensitive data.

```
Your travel agent needs your passport number.
Your shopping agent needs your shipping address and sizes.
Your trading agent needs your wallet private key.
Your financial agent needs to make payments on your behalf.
Your health agent needs your allergies and prescriptions.

Today, you have two options:

  1. Re-enter everything, every time, for every agent.
     "What size? Ship where? Passport number? Which wallet?"
     Same questions. Every agent. Forever.

  2. Hand your secrets directly to agents.
     Private keys in .env files. Passwords in memory.
     One prompt injection = everything leaks.

Both options are broken.
```

DCP is the third option: store everything once in an encrypted vault. Agents request access, you consent, the vault handles it. Sensitive data like addresses flows with permission. Critical data like private keys never leaves — the vault executes operations internally and returns only the result.

```
Without DCP:
  You: "Buy me running shoes"
  Agent: "What size? Ship where? Max budget? Brand?"
  [4 questions before anything happens]

  You: "Swap 1 SOL for USDC"
  Agent holds your private key in plaintext memory.
  Agent gets prompt-injected. Wallet drained.

With DCP:
  You: "Buy me running shoes"
  Agent reads vault -> Size 11, home address, max $150, Nike
  Agent: "Found Nike Pegasus for $129. Buy?"
  You: "Yes"

  You: "Swap 1 SOL for USDC"
  Agent sends unsigned tx -> vault signs internally -> returns signed tx
  Agent never sees the private key. Nothing to leak.
```

## Quickstart (Local OSS)

All npm packages are published under the **@dcprotocol** scope.  
Do **not** install the unscoped package name `dcp`.

### 1. Install

```bash
npm install -g @dcprotocol/cli
```

### 2. Initialize your vault

```bash
dcp init
```

**Important:** your 12‑word recovery phrase is shown **once** and is **never stored**. Save it.

### 3. Create a wallet (choose one)

```bash
dcp create-wallet --chain solana
# or
dcp create-wallet --chain ethereum
# or
dcp create-wallet --chain base
```

### 4. Add personal data (optional)

```bash
dcp add address.home
dcp add identity.email
dcp add preferences.sizes
```

### 5. Start the REST server (optional)

```bash
npx @dcprotocol/server
```

Open `http://127.0.0.1:8420` to approve/deny requests in the browser.
The UI also includes an **Unlock MCP** button to unlock the MCP process without typing your passphrase in Claude.

### 6. Connect an MCP agent

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

If the vault is locked, call `vault_unlock` once from the agent before reads/signing.
By default MCP uses **non‑TTY** consent: it creates a pending request and waits until you approve in the UI or CLI.  
To allow interactive terminal prompts, set `DCP_MCP_ALLOW_TTY=1`.

If you use multiple MCP processes, set a stable agent name to keep sessions consistent:

```bash
MCP_AGENT_NAME=claude-desktop
```

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VAULT_DIR` | Vault storage directory | `~/.dcp` |
| `VAULT_PORT` | REST server port | `8420` |
| `DCP_MCP_ALLOW_TTY` | Enable terminal consent prompts | `0` |
| `MCP_AGENT_NAME` | Stable agent name for session reuse | `MCP Agent` |
| `DCP_CLI_SESSION_MINUTES` | CLI unlock cache duration | `30` |
| `DCP_CLI_INSECURE_SESSION` | File‑based cache when keychain unavailable | `0` |
| `DCP_MCP_SESSION_MINUTES` | MCP auto‑unlock session duration | `30` |

## Sessions, Limits, and Rate Limiting

**Session timeouts**
- 30 minutes idle
- 4 hours max duration

**Default budgets (per currency)**
- SOL: `tx_limit=5`, `daily_budget=20`, `approval_threshold=2`
- ETH: `tx_limit=0.5`, `daily_budget=1`, `approval_threshold=0.1`
- USDC: `tx_limit=200`, `daily_budget=500`, `approval_threshold=100`
- USDT: `tx_limit=200`, `daily_budget=500`, `approval_threshold=100`
- BASE_ETH: `tx_limit=0.2`, `daily_budget=0.5`, `approval_threshold=0.05`

**Rate limiting**
- 5 executions/minute per agent session

**Stablecoin note**
- For **USDC/USDT**, include the chain when checking budgets via REST/MCP (`chain: solana|ethereum|base`).

### 7. Approve a consent request (when prompted)

```bash
dcp approve --list
dcp approve <consent_id>
```

### Quick Demo (1–2 minutes)

```bash
./examples/demo.sh
```

Runs end-to-end: init vault, create wallet, add sample data, start server, and run both examples.


## What Agents Can Do

| Agent Calls | Agent Gets | Sees Raw Secret? |
|-------------|-----------|------------------|
| `vault_sign_tx({ chain, unsigned_tx })` | Signed transaction | Never |
| `vault_get_address(chain)` | Public address | N/A (public) |
| `vault_read("address.home")` | Address JSON | With consent |
| `vault_read("preferences.sizes")` | Sizes JSON | With consent |
| `vault_read("crypto.wallet.solana")` | Reference only | Never |

**Rule: critical data (private keys) never leaves the vault. Agents get USE of data, not POSSESSION.**

## How Signing Works

```
You: "Swap 1.5 SOL for USDC on Jupiter"

Agent builds unsigned swap transaction
Agent calls -> `vault_sign_tx({ chain, unsigned_tx })`

  Vault checks:
    - Agent has consent (session approved)
    - 1.5 SOL <= 5 SOL per-tx limit
    - Daily spend: 1.5 / 20 SOL budget
    - Below 2 SOL threshold -> auto-approved

  Vault internally:
    Decrypt key -> sign tx -> zeroize key from memory (~5ms)

  Returns -> signed transaction bytes

Agent submits to Solana -> confirmed.
Private key exposure: zero.
```

## Budget Controls

```bash
dcp config set tx_limit.SOL 5            # max per transaction
dcp config set daily_budget.USDC 100     # max per day
dcp config set approval_threshold.SOL 2  # above this -> manual approve
```

Compromised agent tries to drain wallet:

- 100 SOL transfer -> **BLOCKED** (exceeds tx limit)
- 4 SOL transfer -> **PAUSED** (above threshold, you must approve)
- Many 1.9 SOL transfers -> **BLOCKED** after daily limit hit

Worst case with DCP: bounded by your daily budget. Without DCP: entire wallet gone instantly.

## Also Stores Personal Data

Not just wallets. Store anything agents need:

```bash
dcp add identity.name
dcp add identity.email
dcp add identity.phone
dcp add identity.passport
dcp add identity.drivers_license

dcp add address.home
dcp add address.work

dcp add preferences.sizes
dcp add preferences.brands
dcp add preferences.diet
dcp add preferences.travel

dcp add credentials.api
dcp add health.profile
dcp add budget.default
```

Every record includes `schema_version`. See full canonical schema in `SCHEMA.md`.

## Choose the Right Package

| Package | When to use it |
|---------|----------------|
| `@dcprotocol/cli` | You’re a human managing the vault (init, add data, approve) |
| `@dcprotocol/mcp` | Your agent runtime supports MCP (Claude, Cursor, OpenClaw) |
| `@dcprotocol/server` | You want a local REST API + browser approval UI |
| `@dcprotocol/core` | You’re embedding DCP inside your own app or service |

## CLI Reference

| Command | Description |
|---------|-------------|
| `dcp init` | Initialize vault (shows recovery phrase once) |
| `dcp create-wallet --chain <solana|ethereum|base>` | Generate wallet (key never leaves vault) |
| `dcp add <scope>` | Store personal data |
| `dcp read <scope>` | Read STANDARD/SENSITIVE data (CRITICAL never shown) |
| `dcp list` | List stored items (no values shown) |
| `dcp update <scope>` | Update existing data |
| `dcp remove <scope>` | Remove data |
| `dcp status` | Show vault status |
| `dcp approve` | Approve pending consent requests |
| `dcp agents` | List active sessions |
| `dcp revoke <agent|session_id>` | Revoke agent access |
| `dcp config` | View/edit budget limits |
| `dcp activity` | View audit log |
| `dcp recovery show-phrase` | Explain recovery phrase is only shown once |
| `dcp recovery restore` | Restore vault from phrase |

## REST API

For non-MCP agents. Binds to `127.0.0.1:8420` only (never exposed to internet).

```bash
npx @dcprotocol/server

# Unlock the vault for this REST process
curl -X POST http://127.0.0.1:8420/v1/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<your-passphrase>"}'

# Unlock MCP (local bridge)
curl -X POST http://127.0.0.1:8420/v1/vault/unlock-mcp \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<your-passphrase>"}'

# Sign a transaction
curl -X POST http://127.0.0.1:8420/v1/vault/sign \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","unsigned_tx":"<base64>","agent_name":"my-bot"}'

# Read personal data
curl -X POST http://127.0.0.1:8420/v1/vault/read \
  -H "Content-Type: application/json" \
  -d '{"scope":"address.home","agent_name":"my-bot"}'

# Lock the vault when done
curl -X POST http://127.0.0.1:8420/v1/vault/lock
```

## Architecture

```
+-------------+
|  AI Agent   |  Never sees private keys or critical data
+------+------+
       | MCP / REST
       v
+----------------------------------------------+
|                DCP Core                       |
|  +--------+ +--------+ +--------+ +--------+ |
|  | Crypto | | Wallet | | Budget | | Audit  | |
|  | Engine | | Manager| | Engine | | Logger | |
|  +--------+ +--------+ +--------+ +--------+ |
|  +------------------------------------------+ |
|  |  SQLite (encrypted) + OS Keychain        | |
|  +------------------------------------------+ |
+----------------------------------------------+
```

No Docker. No database server. No cloud. SQLite file + OS Keychain.

## Security

| Threat | Protection |
|--------|-----------|
| Prompt injection leaks key | Key never in agent memory. Nothing to leak. |
| Database stolen | Encrypted blobs. Master key in OS Keychain, not in DB. |
| Agent overspends | Per-tx limits, daily budgets, approval thresholds. |
| Brute force | Argon2id (64MB memory, 3 iterations). |
| Replay attack | Idempotency keys, expiring tokens, nonce-based. |
| Network sniffing | REST binds to localhost only. |

Full threat model: [SECURITY.md](./SECURITY.md)

## Common Error Codes

| Code | Meaning |
|------|---------|
| `VAULT_LOCKED` | Vault process is locked (unlock required) |
| `CONSENT_DENIED` | User denied consent |
| `CONSENT_TIMEOUT` | Consent expired |
| `RECORD_NOT_FOUND` | Scope not found |
| `BUDGET_EXCEEDED_TX` | Per‑tx limit exceeded |
| `BUDGET_EXCEEDED_DAILY` | Daily budget exceeded |
| `RATE_LIMITED` | Too many requests per minute |

## Packages

| Package | Description |
|---------|-------------|
| `@dcprotocol/core` | Encryption, wallet, storage, budget, audit |
| `@dcprotocol/cli` | Command-line interface |
| `@dcprotocol/mcp` | MCP server for AI agents |
| `@dcprotocol/server` | REST API (localhost:8420) |

## Supported Chains

| Chain | Key Type | Status |
|-------|----------|--------|
| Solana | Ed25519 | Supported |
| Ethereum | secp256k1 | Supported |
| Base | secp256k1 | Supported |

## Development

```bash
git clone https://github.com/1lystore/dcp.git
cd dcp && npm install && npm run build
npm test
```

## Community

- [Discord](https://discord.gg/3pgAgQgpBn) — `#dcp-general` for questions, `#dcp-help` for support
- [GitHub Issues](https://github.com/1lystore/dcp/issues) — Bug reports & feature requests

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). We accept: bug fixes, new chain support, new data schemas, framework integrations, docs, tests.

## License

Apache-2.0 — see `LICENSE`.

## Links

- [Discord](https://discord.gg/3pgAgQgpBn)
- [Architecture](./ARCHITECTURE.md)
- [Security Model](./SECURITY.md)
- [Roadmap](./ROADMAP.md)
- [Contributing](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Release](./RELEASE.md)
