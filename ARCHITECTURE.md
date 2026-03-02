# Architecture

This document describes the architecture of **DCP (Delegated Custody Protocol)** and its open-source reference implementation, **DCP Vault**.

## What Is DCP?

DCP is a secure personal data layer for AI agents. Humans store their data once — addresses, preferences, wallets, credentials — and any authorized AI agent can access it with consent. Critical data (private keys, API keys) is never exposed; agents get the *use* of the data (signed transactions, API calls) without seeing raw values.

**Core principle:** Agents get USE of data, not the VALUES.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACES                                 │
├────────────────────────┬────────────────────────┬───────────────────────────┤
│       CLI (Human)      │    REST Server (API)   │     MCP Server (Agent)    │
│   dcp <command>  │   localhost:8420       │    Claude integration     │
└────────────────────────┴───────────┬────────────┴───────────────────────────┘
                                     │
┌────────────────────────────────────┴────────────────────────────────────────┐
│                             DCP CORE                                       │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────┤
│  Crypto Engine  │  Wallet Manager │  Budget Engine  │   Storage Layer       │
│  - XChaCha20    │  - Solana       │  - Rate limits  │   - SQLite DB         │
│  - Argon2id     │  - Ethereum     │  - Budgets      │   - Encrypted records │
│  - Envelope enc │  - Base         │  - Approvals    │   - Sessions          │
│  - Zeroization  │  - Signing      │                 │   - Audit log         │
└─────────────────┴─────────────────┴─────────────────┴───────────────────────┘
                                     │
┌────────────────────────────────────┴────────────────────────────────────────┐
│                             STORAGE                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  SQLite Database (~/.dcp/vault.db)                                    │
│  - vault_records: Encrypted records (wallets, personal data)                  │
│  - sessions: Active agent sessions with granted scopes                      │
│  - pending_consents: Consent requests awaiting approval                     │
│  - spend_events: Transaction history for budget tracking                    │
│  - audit_events: Immutable operation log                                    │
│  - config: Vault settings (budgets, timeouts)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  Master Key Storage                                                          │
│  - Primary: OS Keychain (macOS Keychain, Windows Credential Manager)        │
│  - Fallback: ~/.dcp/master.key (encrypted file)                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Package Structure

```
dcp/
├── packages/
│   ├── dcp-core/          # Core library
│   │   ├── src/
│   │   │   ├── crypto.ts    # Encryption primitives
│   │   │   ├── wallet.ts    # Wallet creation & signing
│   │   │   ├── storage.ts   # SQLite & keychain
│   │   │   ├── budget.ts    # Budget engine
│   │   │   └── types.ts     # TypeScript types
│   │   └── tests/
│   │
│   ├── dcp-cli/           # Command-line interface
│   │   ├── src/
│   │   │   ├── cli.ts       # Main entry point
│   │   │   ├── commands/    # Individual commands
│   │   │   └── utils.ts     # CLI utilities
│   │   └── tests/
│   │
│   ├── dcp-server/        # REST API server
│   │   └── src/
│   │       └── index.ts     # Fastify server
│   │
│   └── dcp-mcp/           # MCP protocol server
│       └── src/
│           └── index.ts     # MCP tools
│
└── examples/                # Integration examples
    ├── sign-solana-tx/
    └── read-personal-data/
```

## Data Flow

### Transaction Signing

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Agent   │     │   MCP/   │     │  Vault   │     │  Crypto  │
│          │     │   REST   │     │  Storage │     │  Engine  │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ 1. Request     │                │                │
     │    sign tx     │                │                │
     │───────────────▶│                │                │
     │                │                │                │
     │                │ 2. Check       │                │
     │                │    session     │                │
     │                │───────────────▶│                │
     │                │                │                │
     │                │ 3. No session? │                │
     │                │    Create      │                │
     │                │    consent     │                │
     │                │◀───────────────│                │
     │                │                │                │
     │ 4. Consent     │                │                │
     │    required    │                │                │
     │◀───────────────│                │                │
     │                │                │                │
     │                │                │                │
     │    === USER APPROVES VIA CLI ===│                │
     │                │                │                │
     │                │                │                │
     │ 5. Retry       │                │                │
     │    sign tx     │                │                │
     │───────────────▶│                │                │
     │                │                │                │
     │                │ 6. Check       │                │
     │                │    budget      │                │
     │                │───────────────▶│                │
     │                │                │                │
     │                │ 7. Get         │                │
     │                │    encrypted   │                │
     │                │    wallet      │                │
     │                │───────────────▶│                │
     │                │                │                │
     │                │                │ 8. Decrypt     │
     │                │                │    & sign      │
     │                │                │───────────────▶│
     │                │                │                │
     │                │                │ 9. Return      │
     │                │                │    signed tx   │
     │                │                │◀───────────────│
     │                │                │                │
     │                │ 10. Record     │                │
     │                │     spend      │                │
     │                │───────────────▶│                │
     │                │                │                │
     │ 11. Return     │                │                │
     │     signature  │                │                │
     │◀───────────────│                │                │
     │                │                │                │
```

### Data Read

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Agent   │     │   MCP/   │     │  Vault   │     │  Crypto  │
│          │     │   REST   │     │  Storage │     │  Engine  │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ 1. Read scope  │                │                │
     │───────────────▶│                │                │
     │                │                │                │
     │                │ 2. Check       │                │
     │                │    sensitivity │                │
     │                │───────────────▶│                │
     │                │                │                │
     │                │ 3. Critical?   │                │
     │                │    Return      │                │
     │                │    reference   │                │
     │◀───────────────│ only           │                │
     │                │                │                │
     │                │ 4. Otherwise,  │                │
     │                │    check       │                │
     │                │    consent     │                │
     │                │───────────────▶│                │
     │                │                │                │
     │                │                │ 5. Decrypt     │
     │                │                │    payload     │
     │                │                │───────────────▶│
     │                │                │                │
     │ 6. Return data │                │                │
     │◀───────────────│◀───────────────│◀───────────────│
     │                │                │                │
```

## Recovery Model

DCP uses a 12-word BIP-39 recovery phrase generated at init.
The phrase is shown **once** and is **never stored**.
Restoring requires re-entering the phrase and setting a new passphrase.

## Capability Tokens

DCP uses **PASETO v4.local** for capability tokens (not JWT).
Tokens are scoped, time-limited, and validated on every request.

## Non-TTY Consent Flow

When the MCP server runs without a TTY:

1. A consent request is written to `pending_consents`.
2. The user approves via `dcp approve` or the REST consent endpoint.
3. The MCP server polls `pending_consents` until approved/denied/expired.
4. On approval, a session is created and the request continues.


## Database Schema

### vault_records

Stores encrypted records (wallets, personal data).

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID primary key |
| scope | TEXT | Hierarchical scope (e.g., `address.home`) |
| item_type | TEXT | `WALLET_KEY` or `PERSONAL_DATA` |
| sensitivity | TEXT | `standard`, `sensitive`, `critical` |
| chain | TEXT | Blockchain (for wallets) |
| public_address | TEXT | Public address (for wallets) |
| encrypted_payload | BLOB | Envelope-encrypted data |
| created_at | TEXT | ISO timestamp |
| updated_at | TEXT | ISO timestamp |

### sessions

Active agent sessions with granted permissions.

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID primary key |
| agent_name | TEXT | Agent identifier |
| granted_scopes | TEXT | JSON array of scopes |
| consent_mode | TEXT | `once` or `session` |
| expires_at | TEXT | Session expiry |
| revoked_at | TEXT | Revocation timestamp |
| created_at | TEXT | Creation timestamp |
| last_used_at | TEXT | Last activity |

### pending_consents

Consent requests awaiting user approval.

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID primary key |
| agent_name | TEXT | Requesting agent |
| action | TEXT | `read` or `sign_tx` |
| scope | TEXT | Requested scope |
| status | TEXT | `pending`, `approved`, `denied`, `expired` |
| details | TEXT | JSON context |
| expires_at | TEXT | Consent expiry (5 min default) |
| session_id | TEXT | Created session (if approved with session) |

### spend_events

Transaction history for budget tracking.

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID primary key |
| session_id | TEXT | Originating session |
| amount | REAL | Transaction amount |
| currency | TEXT | Currency (SOL, ETH) |
| chain | TEXT | Blockchain |
| operation | TEXT | Operation type |
| status | TEXT | `committed` or `rolled_back` |
| idempotency_key | TEXT | Prevents duplicates |
| created_at | TEXT | Timestamp |

### audit_events

Immutable operation log.

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID primary key |
| event_type | TEXT | `GRANT`, `DENY`, `EXECUTE`, `READ`, `REVOKE`, `CONFIG`, `EXPIRE` |
| agent_name | TEXT | Acting agent |
| scope | TEXT | Affected scope |
| operation | TEXT | Specific operation |
| outcome | TEXT | `success`, `denied`, `expired` |
| details | TEXT | JSON context |
| created_at | TEXT | Timestamp |

## Encryption Architecture

### Master Key Storage

The master key is protected by Argon2id key derivation:

```
User Passphrase ──▶ Argon2id ──▶ Wrapping Key ──┐
                    (64MB RAM)                   │
                    (3 iter)                     ▼
                                         ┌──────────────┐
                                         │  Master Key  │
                                         │  (encrypted) │
                                         └──────────────┘
```

Storage locations (in order of preference):
1. OS Keychain (macOS Keychain, Windows Credential Manager)
2. Encrypted file (`~/.dcp/master.key`)

### Envelope Encryption

Every record uses envelope encryption:

```
┌─────────────────────────────────────────────────────────┐
│                    Encrypted Payload                     │
├─────────────────────────────────────────────────────────┤
│  DEK Nonce (24 bytes)                                   │
│  DEK Ciphertext (32 bytes encrypted DEK + 16 byte tag)  │
│  Data Nonce (24 bytes)                                  │
│  Data Ciphertext (variable + 16 byte tag)               │
└─────────────────────────────────────────────────────────┘
```

Decryption:
1. Use master key to decrypt DEK
2. Use DEK to decrypt data
3. Zeroize DEK from memory

## Session Management

### Session Lifecycle

```
                    ┌─────────────────┐
                    │     Created     │
                    │  (via consent)  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     Active      │◀──────┐
                    │                 │       │ Touch
                    └────────┬────────┘───────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
     ┌────────────────┐ ┌─────────┐ ┌─────────────┐
     │  Idle Timeout  │ │ Max TTL │ │   Revoked   │
     │   (30 min)     │ │ (4 hr)  │ │  (manual)   │
     └────────────────┘ └─────────┘ └─────────────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     Expired     │
                    └─────────────────┘
```

### Scope Matching

Sessions grant access to specific scopes. Matching supports wildcards:

| Granted Scope | Request Scope | Match? |
|---------------|---------------|--------|
| `address.home` | `address.home` | Yes |
| `address.*` | `address.home` | Yes |
| `address.*` | `address.work` | Yes |
| `address.home` | `address.work` | No |
| `identity.*` | `address.home` | No |

## Budget Engine

### Check Flow

```
Request: Sign 0.5 SOL transaction
          │
          ▼
┌─────────────────────────┐
│ Check per-tx limit      │
│ (default: 1.0 SOL)      │
└────────────┬────────────┘
             │ ✓ Under limit
             ▼
┌─────────────────────────┐
│ Check daily remaining   │
│ (default: 10.0 SOL)     │
└────────────┬────────────┘
             │ ✓ Under budget
             ▼
┌─────────────────────────┐
│ Check approval threshold│
│ (default: 0.5 SOL)      │
└────────────┬────────────┘
             │ ✓ Under threshold
             ▼
┌─────────────────────────┐
│ ALLOWED (no consent)    │
└─────────────────────────┘

If 0.6 SOL requested:
             │ ✗ Above threshold
             ▼
┌─────────────────────────┐
│ ALLOWED (with consent)  │
└─────────────────────────┘
```

### Budget Reset

Daily budgets reset at midnight UTC. The rolling 24-hour spend is calculated from `spend_events`.

## MCP Integration

The MCP server exposes vault operations as tools:

| Tool | Description |
|------|-------------|
| `vault_get_scopes` | List available data scopes |
| `vault_read` | Read personal data |
| `vault_get_wallet_address` | Get wallet public address |
| `vault_sign_tx` | Sign a blockchain transaction |
| `vault_check_budget` | Check remaining spending budget |

### Tool Schema Example

```json
{
  "name": "vault_sign_tx",
  "description": "Sign a blockchain transaction",
  "inputSchema": {
    "type": "object",
    "properties": {
      "chain": {
        "type": "string",
        "enum": ["solana", "ethereum", "base"]
      },
      "unsigned_tx": {
        "type": "string",
        "description": "Base64-encoded unsigned transaction"
      },
      "amount": {
        "type": "number",
        "description": "Transaction amount (for budget tracking)"
      },
      "currency": {
        "type": "string",
        "description": "Currency (SOL, ETH, BASE_ETH)"
      }
    },
    "required": ["chain", "unsigned_tx"]
  }
}
```

## Configuration

Vault configuration is stored in the `config` table:

| Key | Default | Description |
|-----|---------|-------------|
| `tx_limit` | 5 | Max per-transaction (SOL) |
| `daily_budget` | 20 | Max daily spend (SOL) |
| `approval_threshold` | 2 | Consent required above this |
| `rate_limit_per_minute` | 5 | API rate limit |
| `session_timeout_minutes` | 30 | Session idle timeout |
| `session_max_hours` | 4 | Session max duration |

## Error Handling

All errors use a consistent format:

```json
{
  "error": {
    "code": "BUDGET_EXCEEDED_TX",
    "message": "Transaction exceeds per-transaction limit",
    "context": {
      "requested": 2.0,
      "limit": 1.0
    }
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `VAULT_LOCKED` | Vault needs to be unlocked |
| `RECORD_NOT_FOUND` | Requested scope doesn't exist |
| `CONSENT_REQUIRED` | Operation needs user approval |
| `CONSENT_DENIED` | User denied the consent request |
| `CONSENT_TIMEOUT` | Consent request expired |
| `BUDGET_EXCEEDED_TX` | Over per-transaction limit |
| `BUDGET_EXCEEDED_DAILY` | Over daily budget |
| `SESSION_EXPIRED` | Session no longer valid |
| `RATE_LIMITED` | Too many requests |
