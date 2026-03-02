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
| `vault_read("crypto.wallet.sol")` | Reference only | Never |

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
dcp config set tx_limit.USDC 100      # max per day
dcp config set approval_threshold.SOL 2  # above this -> manual approve
```

Compromised agent tries to drain wallet:

- 100 SOL transfer -> **BLOCKED** (exceeds tx limit)
- 4 SOL transfer -> **PAUSED** (above threshold, you must approve)
- Many 1.9 SOL transfers -> **BLOCKED** after daily limit hit

Worst case with DCP: ~1 SOL/day. Without DCP: entire wallet gone instantly.

## Also Stores Personal Data

Not just wallets. Store anything agents need:

```bash
dcp add address.home           # shipping address
dcp add identity.name          # your name
dcp add identity.email         # email
dcp add preferences.sizes      # shoe size, shirt size
dcp add preferences.diet       # dietary restrictions
```

Any agent reads with your consent. Store once, use everywhere.

## CLI Reference

| Command | Description |
|---------|-------------|
| `dcp init` | Initialize vault (shows recovery phrase once) |
| `dcp create-wallet --chain <solana|ethereum|base>` | Generate wallet (key never leaves vault) |
| `dcp add <scope>` | Store personal data |
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

# Sign a transaction
curl -X POST http://127.0.0.1:8420/v1/vault/sign \
  -d '{"chain":"solana","unsigned_tx":"<base64>","agent_name":"my-bot"}'

# Read personal data
curl -X POST http://127.0.0.1:8420/v1/vault/read \
  -d '{"scope":"address.home","agent_name":"my-bot"}'
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

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). We accept: bug fixes, new chain support, new data schemas, framework integrations, docs, tests.

## License

Apache-2.0 — see `LICENSE`.

## Links

- [Architecture](./ARCHITECTURE.md)
- [Security Model](./SECURITY.md)
- [Roadmap](./ROADMAP.md)
- [Contributing](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Release](./RELEASE.md)