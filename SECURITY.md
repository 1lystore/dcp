# Security Model

This document covers the security model for **DCP (Delegated Custody Protocol)** and its open-source reference implementation, **DCP Vault**.

## Design Philosophy

DCP Vault protects personal data from unauthorized access — including from AI agents that use the vault for legitimate operations. The core principle:

**Agents get USE of data, not the VALUES.**

- Standard data (addresses, preferences): Agents can read with consent
- Critical data (private keys, API keys): Agents never see raw values; they get results (signed transactions, API responses)

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| AI agent accessing private keys | Keys never exposed; agents only receive signed outputs |
| Brute force passphrase attack | Argon2id with memory-hard parameters (64MB, 3 iterations) |
| Memory extraction attacks | Sensitive buffers zeroized after use |
| Network interception | REST server binds to localhost only (127.0.0.1) |
| Unauthorized data access | Consent required for every read/sign operation |
| Runaway agent spending | Budget limits, approval thresholds, session timeouts |
| Database theft | All data encrypted at rest with envelope encryption |
| Recovery phrase theft | Phrase is shown once and not stored; if compromised, attacker can restore |

### Out of Scope (Current OSS)

| Threat | Notes |
|--------|-------|
| Physical device compromise | Assumes trusted execution environment |
| Operating system compromise | Assumes OS security is maintained |
| Side-channel attacks | Not hardened against timing/cache attacks |
| Hardware key storage | Uses software encryption (HSM support planned) |

## Cryptographic Design

### Key Hierarchy

```
Recovery Phrase (12-word BIP-39 mnemonic)
          │
          ▼
    Master Key (32 bytes)
          │
          ├──▶ Encrypted with Argon2id-derived wrapping key
          │         (stored in OS Keychain or encrypted file)
          │
          └──▶ DEK per record
                    │
                    ▼
              Encrypted data (XChaCha20-Poly1305)
```

### Algorithms

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Symmetric encryption | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce |
| Key derivation | Argon2id | 64MB memory, 3 iterations, 4 parallelism |
| Recovery phrase | BIP-39 | 128-bit entropy, 12 words |
| Master key derivation | PBKDF2 (via BIP-39) | SHA-512, 2048 iterations |
| Nonce generation | crypto.randomBytes | 24 bytes per encryption |

### Envelope Encryption

Every record uses two-layer envelope encryption:

1. **Data Encryption Key (DEK)**: Random 32-byte key generated per record
2. **Record encryption**: Data encrypted with DEK using XChaCha20-Poly1305
3. **DEK encryption**: DEK encrypted with Master Key using XChaCha20-Poly1305

This design enables:
- Re-keying without re-encrypting all data
- Per-record access control (future)
- Efficient key rotation

### Memory Safety

Sensitive data is zeroized immediately after use:

```typescript
// Example from dcp-core
const masterKey = deriveKeyFromMnemonic(mnemonic);
try {
  // Use master key
  await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
} finally {
  // CRITICAL: Zeroize from memory
  zeroize(masterKey);
}
```

All functions handling secrets follow this pattern:
- `deriveKeyFromPassphrase()` - wrapping key zeroized after use
- `envelopeDecrypt()` - DEK zeroized after decryption
- `signTransaction()` - private key zeroized after signing

## Access Control

### Consent Model

Every agent operation requires consent:

| Mode | Description | Use Case |
|------|-------------|----------|
| `once` | Single operation, then expires | One-off requests |
| `session` | Valid for scope until timeout | Repeated operations |

Session limits:
- **Idle timeout**: 30 minutes of inactivity
- **Max duration**: 4 hours absolute
- **Manual revocation**: User can revoke anytime

### Budget Engine

Transaction signing enforces spending limits:

| Limit | Default | Description |
|-------|---------|-------------|
| `tx_limit` | 5 SOL | Maximum per transaction |
| `daily_budget` | 20 SOL | Maximum per 24 hours |
| `approval_threshold` | 2 SOL | Require consent above this |

Budget exceeded = operation denied immediately.

### Sensitivity Levels

| Level | Description | Agent Access |
|-------|-------------|--------------|
| `standard` | Non-sensitive preferences | Can read with consent |
| `sensitive` | PII (name, address, email) | Can read with consent |
| `critical` | Private keys, passport | Cannot read directly |

Critical data (wallet keys) can only be used via `sign` operations; the raw data is never returned to agents.

## Network Security

### Localhost Binding

The REST server binds exclusively to `127.0.0.1`:

```typescript
const HOST = '127.0.0.1'; // SECURITY: localhost only
await server.listen({ port, host: HOST });
```

This ensures:
- No network exposure
- Only local processes can connect
- Firewall rules don't apply

### CORS Configuration

CORS is permissive (`origin: true`) because:
- Server is localhost-only
- Browser-based UIs need access
- All operations require consent anyway

## Audit Trail

All operations are logged to an immutable audit table:

| Event Type | Description |
|------------|-------------|
| `GRANT` | Consent approved |
| `DENY` | Consent denied |
| `EXECUTE` | Transaction signed |
| `READ` | Data read |
| `REVOKE` | Session revoked |
| `CONFIG` | Configuration changed |
| `EXPIRE` | Session/consent expired |

Audit logs include:
- Timestamp
- Agent name
- Operation type
- Scope accessed
- Outcome (success/denied)
- Additional context

## Recovery

### Backup

The 12-word recovery phrase is the only backup mechanism:
- Generated from 128-bit entropy
- Master key derived deterministically via BIP-39
- Same phrase = same master key = access to all data

### Restore Process

1. User enters recovery phrase
2. Master key derived from phrase
3. Master key re-encrypted with new passphrase
4. Existing encrypted data becomes accessible

**Warning**: Recovery phrase provides complete vault access. Store offline in secure location.

## Security Recommendations

### For Users

1. **Use a strong passphrase**: 12+ characters, mix of types
2. **Store recovery phrase offline**: Paper in secure location
3. **Review consent requests**: Don't approve blindly
4. **Set conservative budgets**: Start low, increase as needed
5. **Monitor activity logs**: Run `dcp activity` regularly
6. **Revoke unused sessions**: Don't leave sessions active

### For Agent Developers

1. **Request minimal scopes**: Only what you need
2. **Include descriptions**: Help users understand requests
3. **Handle consent gracefully**: Don't spam with requests
4. **Respect rate limits**: 5 requests/minute default
5. **Use sessions appropriately**: Don't request session for one-off operations

## Vulnerability Reporting

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers
3. Allow time for a fix before public disclosure

## Compliance Notes

DCP Vault is designed for personal use. For enterprise deployment with compliance requirements (GDPR, SOC2, etc.), additional measures may be needed:
- Hardware security module (HSM) integration
- External audit logging
- Access control policies
- Data retention policies
