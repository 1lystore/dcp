# @dcprotocol/core

Core cryptography, wallet management, and storage layer for DCP. This is the low‑level engine that powers the vault, agent, and desktop app.

If you're building your own tooling or embedding DCP into another service, this is the package you use. Most users should start with `@dcprotocol/vault` or `@dcprotocol/agent`.

## Install

```bash
npm install @dcprotocol/core
```

## What It Provides

- Envelope encryption (XChaCha20-Poly1305)
- Master key management (Argon2id wrapping)
- SQLite storage schema + CRUD for vault records
- Wallet creation + signing helpers (Solana + EVM)
- Pairing grants and session tokens (Ed25519 signed)
- Budget engine + audit logging
- Trusted services registry

## API Overview (Common Exports)

### Crypto

- `generateKey`, `generateNonce`, `generateSalt`
- `deriveKeyFromPassphrase` - Argon2id (m=64MB, t=3, p=4)
- `encrypt`, `decrypt` - XChaCha20-Poly1305
- `envelopeEncrypt`, `envelopeDecrypt` - Two-layer encryption
- `zeroize`, `secureAlloc` - Secure memory management
- `generateRecoveryMnemonic`, `deriveKeyFromMnemonic`, `validateMnemonic` - BIP-39
- `generateSigningKeyPair`, `signMessage`, `verifySignature` - Ed25519

### Wallets

- `generateWalletKeypair` - Create Ed25519 (Solana) or secp256k1 (EVM) keypairs
- `encryptWalletKey` - Encrypt private key with master key
- `signTransaction` - Sign Solana/EVM transactions
- `signSolanaMessage`, `signEvmMessage` - Sign messages
- `signEvmTypedData` - EIP-712 typed data signing
- `getPublicAddress` - Extract address from encrypted key
- Supported chains: `solana`, `ethereum`, `base`

### Pairing

- `createSignedPairingGrant` - Create signed pairing grant (`dcp_pair_v1_*`)
- `decodePairingGrant`, `verifyPairingGrant` - Parse and verify grants
- `createVpsPairingInvite`, `parseVpsPairingInvite` - VPS agent invites
- `createSessionToken`, `decodeSessionToken`, `verifySessionToken` - Session tokens

### Storage

- `VaultStorage` with `initializeSchema`, `createRecord`, `getRecord`, `listRecords`
- Session management: `createSession`, `listActiveSessions`, `getPendingConsents`
- Audit: `logAudit`, `recordSpend`

### Budget

- `BudgetEngine` with `checkBudget`, `enforceBudget`, `getLimits`, `setConfig`
- Default limits: 20 SOL/day, 1 ETH/day, 500 USDC/day

### Services

- `KNOWN_SERVICES` - Registry of verified services (1ly, Virtuals, etc.)
- `getKnownService`, `listKnownServices`, `isKnownService`
- `DEFAULT_RELAY_URL` - Default public relay

### Types

- `Chain = 'solana' | 'base' | 'ethereum'`
- `ItemType = 'WALLET_KEY' | 'ADDRESS' | 'IDENTITY' | 'PREFERENCES' | 'CREDENTIALS' | 'HEALTH' | 'BUDGET'`
- `SensitivityLevel = 'standard' | 'sensitive' | 'critical'`
- `VaultRecord`, `AgentSession`, `SignedPairingGrant`, `VaultError`

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

## Example: Create a Pairing Grant

```ts
import { createSignedPairingGrant, generateSigningKeyPair } from '@dcprotocol/core';

const signingKeyPair = generateSigningKeyPair();

const grant = createSignedPairingGrant({
  vaultId: 'vault_abc123',
  agentName: 'my-vps-agent',
  scopes: ['sign:solana', 'read:credentials.api.*'],
  tier: 'pro',
  relayUrl: 'wss://relay.dcp.1ly.store',
  expiresAt: Date.now() + 3600000, // 1 hour
}, signingKeyPair.privateKey);

console.log(grant); // dcp_pair_v1_...
```

## Notes

- This package assumes **local‑first** storage (SQLite + OS keychain).
- It includes native dependencies: `better-sqlite3`, `keytar`, `sodium-native`.
- On Linux, keychain usage may require `libsecret-1-0`.
- For agent/server access, use `@dcprotocol/vault` or `@dcprotocol/agent`.
- See the root README for the full architecture and security model.
