# @dcprotocol/core

Core cryptography + storage layer for DCP. This is the low‑level engine that powers the CLI, MCP server, and REST server.

If you’re building your own tooling or embedding DCP into another service, this is the package you use. Most users should start with `@dcprotocol/cli`, `@dcprotocol/mcp`, or `@dcprotocol/server`.

## Install

```bash
npm install @dcprotocol/core
```

## What It Provides

- Envelope encryption (XChaCha20-Poly1305)
- Master key management (Argon2id wrapping)
- SQLite storage schema + CRUD for vault records
- Wallet creation + signing helpers (Solana + EVM)
- Budget engine + audit logging

## API Overview (Common Exports)

**Crypto**
- `generateKey`, `generateNonce`, `generateSalt`
- `deriveKeyFromPassphrase`
- `encrypt`, `decrypt`
- `envelopeEncrypt`, `envelopeDecrypt`
- `zeroize`, `secureAlloc`
- `generateRecoveryMnemonic`, `deriveKeyFromMnemonic`, `validateMnemonic`

**Wallets**
- `createWallet`, `importWallet`, `isChainSupported`
- `signTransaction`, `signSolanaMessage`, `signEvmMessage`
- `getPublicAddress`

**Storage**
- `VaultStorage` with `initializeSchema`, `createRecord`, `getRecord`, `listRecords`,
  `createSession`, `listActiveSessions`, `getPendingConsents`, `logAudit`, `recordSpend`

**Budget**
- `BudgetEngine` with `checkBudget`, `enforceBudget`, `getLimits`, `setConfig`

## Example: Initialize + Store a Record

```ts
import { VaultStorage } from '@dcprotocol/core';

const storage = new VaultStorage();
storage.initializeSchema();

// Initialize master key once (during setup)
await storage.initializeMasterKey('your-passphrase');

// Store a record (data is encrypted automatically)
storage.createRecord({
  scope: 'identity.email',
  item_type: 'IDENTITY',
  sensitivity: 'sensitive',
  data: { email: 'user@example.com' },
});
```

## Notes

- This package assumes **local‑first** storage (SQLite + OS keychain).
- If you need agent access, use `@dcprotocol/mcp` or `@dcprotocol/server`.
- See the root README for the full architecture and security model.
