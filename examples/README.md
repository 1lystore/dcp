# DCP Vault Examples

Example integrations showing how AI agents interact with DCP Vault.

## Prerequisites

Before running examples, ensure you have:

1. **Initialized a vault:**
   ```bash
   dcp init
   ```

2. **Created a wallet (for signing examples):**
   ```bash
   dcp create-wallet --chain solana
   ```

3. **Added some data (for read examples):**
   ```bash
   dcp add address.home
   dcp add preferences.sizes
   ```

4. **Started the DCP server:**
   ```bash
   cd packages/dcp-server && npm run dev
   # or
   npx @dcprotocol/server
   ```

5. **Unlocked the vault:**
   The vault must be unlocked before the REST API can decrypt data or sign transactions. Run `dcp init` and enter your passphrase; the vault stays unlocked for this session.

## Examples

## Quick Demo (1–2 minutes)

Run the end-to-end demo script from repo root:

```bash
./examples/demo.sh
```

This will:
- install deps
- build packages
- init a vault
- create a Solana wallet
- add sample data
- start the REST server
- run both examples

You will be prompted for consent in the terminal.


### sign-solana-tx

Demonstrates signing a Solana transaction without the agent ever seeing the private key.

```bash
cd examples/sign-solana-tx
npm install
npm start
```

Flow:
1. Agent builds unsigned transaction
2. Agent calls `POST /v1/vault/sign`
3. User approves consent (CLI or REST)
4. Vault signs and returns signed transaction
5. Agent broadcasts the signed transaction

### read-personal-data

Demonstrates reading encrypted personal data with user consent.

```bash
cd examples/read-personal-data
npm install
npm start
```

Flow:
1. Agent requests data from a scope
2. User approves consent
3. Vault decrypts and returns data
4. (Optional) User grants session for future requests

## API Reference

The DCP server runs at `http://127.0.0.1:8420` (localhost only).

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/scopes` | List available data scopes |
| GET | `/address/:chain` | Get wallet address |
| GET | `/budget/check` | Check spending budget |
| GET | `/agents` | List active sessions |
| GET | `/consent` | List pending consents |
| POST | `/consent/:id/approve` | Approve a consent request |
| POST | `/consent/:id/deny` | Deny a consent request |

### V1 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/vault/read` | Read data (with consent) |
| POST | `/v1/vault/sign` | Sign transaction (with consent + budget) |
| GET | `/v1/vault/activity` | Get audit events |
| POST | `/v1/vault/agents/:id/revoke` | Revoke a session |

## Session Management

Sessions allow agents to make multiple requests without repeated consent prompts.

Grant a session when approving:
```bash
curl -X POST http://127.0.0.1:8420/consent/<id>/approve \
  -H "Content-Type: application/json" \
  -d '{"session": true}'
```

Sessions expire after:
- 30 minutes of inactivity
- 4 hours maximum duration
- Manual revocation

## Security Notes

- The DCP server only binds to `127.0.0.1` (localhost)
- Private keys never leave the vault
- All data is encrypted with XChaCha20-Poly1305
- Passphrase-based key derivation uses Argon2id
- Critical data (wallet keys) cannot be read directly
