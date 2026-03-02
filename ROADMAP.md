# DCP Roadmap

This roadmap reflects the intended direction of DCP (Delegated Custody Protocol). It is not a commitment — priorities may shift based on community feedback and real-world usage.

Want to help? Items marked **[help wanted]** are great places to contribute.

---

## Phase 1 — Foundation (Current)

The minimum viable protocol: wallet signing, personal data storage, consent flow, budget enforcement.

- [x] Core encryption engine (XChaCha20-Poly1305, Argon2id)
- [x] Envelope encryption with per-record DEKs
- [x] OS Keychain integration (macOS Keychain, Linux libsecret, Windows Credential Manager)
- [x] SQLite embedded storage (no server, no Docker)
- [x] Wallet generation — Solana (Ed25519)
- [x] Wallet generation — Ethereum/Base (secp256k1)
- [x] Transaction signing (vault_sign_tx) — key never exposed
- [x] Personal data storage (address, identity, preferences)
- [x] Three sensitivity levels (standard, sensitive, critical)
- [x] Consent flow — terminal prompts (approve once / session / deny)
- [x] Budget engine — per-tx limits, daily limits, approval thresholds
- [x] Spend tracking with idempotency keys
- [x] Audit trail (grant, read, execute, deny, revoke events)
- [x] MCP server (@dcprotocol/mcp) — subprocess model
- [x] REST API server (localhost:8420)
- [x] CLI — init, create-wallet, add, list, agents, revoke, activity, config
- [x] Recovery phrase (BIP-39 mnemonic) on init


## Phase 2 — Hardening & Ecosystem

Making DCP production-ready and easier to integrate with any agent framework.

### Developer Experience
- [ ] Wallet import (`dcp import-wallet`) **[help wanted]**
- [ ] Interactive setup wizard (`dcp init --guided`)
- [ ] Better error messages with fix suggestions
- [ ] `dcp doctor` command (checks vault health, permissions, keychain access)
- [ ] Comprehensive examples for common workflows
- [ ] Integration guides for popular agent frameworks **[help wanted]**

### SDK & Framework Support
- [ ] TypeScript/JavaScript SDK (`@dcprotocol/sdk`)
- [ ] Python SDK (`dcp-python`) **[help wanted]**
- [ ] LangChain integration (tool wrapper) **[help wanted]**
- [ ] CrewAI integration **[help wanted]**
- [ ] AutoGen integration **[help wanted]**
- [ ] OpenAI function calling adapter **[help wanted]**

### Chain Expansion
- [ ] Polygon (secp256k1) **[help wanted]**
- [ ] Arbitrum (secp256k1) **[help wanted]**
- [ ] Optimism (secp256k1) **[help wanted]**
- [ ] BNB Chain / BSC (secp256k1) **[help wanted]**
- [ ] Avalanche (secp256k1) **[help wanted]**
- [ ] Bitcoin (secp256k1, ECDSA) **[help wanted]**

Each chain addition includes: wallet creation, transaction signing, address derivation, and chain-specific budget defaults.

### Data & Schemas
- [ ] More item types: driver's license, health profile, payment preferences **[help wanted]**
- [ ] Schema versioning and migration tooling
- [ ] Bulk import (`dcp import` from JSON/YAML)
- [ ] Bulk export (`dcp export` — encrypted archive for backup)

### Consent & Policy
- [ ] PASETO v4 capability tokens (scoped, time-limited) **[help wanted]**
- [ ] Saved consent profiles (`dcp profile create "Shopping"`)
- [ ] Category-based auto-consent (e.g., all shopping agents get address + sizes)
- [ ] Consent decay — "Allow Always" expires after 90 days of inactivity

### Security Hardening
- [ ] Constant-time token comparison
- [ ] Memory zeroization audit (verify all sensitive buffers are wiped)
- [ ] Fuzzing for crypto operations
- [ ] Third-party security audit (when funding allows)

## Phase 3 — Advanced Custody

Moving from single-device to multi-device and advanced cryptographic models.

### Multi-Device & Recovery
- [ ] Device-based recovery (two devices can recover a lost vault)
- [ ] Social recovery (trusted contacts hold key shards)
- [ ] Hardware wallet support — Ledger (sign via USB HID) **[help wanted]**
- [ ] Hardware wallet support — Trezor **[help wanted]**

### Delegation
- [ ] Agent-to-agent delegation (Agent A grants Agent B scoped access)
- [ ] Delegation chains with attenuation (each hop can only narrow, never widen)
- [ ] Pre-authorized delegation profiles for autonomous agent workflows

### Advanced Signing
- [ ] MPC (Multi-Party Computation) key splitting — key shards across devices
- [ ] Threshold signatures (2-of-3, 3-of-5)
- [ ] Blind signing for privacy-preserving operations
- [ ] Transaction simulation before signing (show expected outcome)
- [ ] Message signing (`vault_sign_message` for off-chain use cases)

### Audit & Compliance
- [ ] On-chain audit anchoring (periodic hash of audit log to Solana/Base)
- [ ] Tamper-evident audit log (HMAC chain)
- [ ] Audit log export (JSON, CSV) for compliance reporting
- [ ] Anomaly detection (unusual spending patterns trigger alerts)

## Phase 4 — Protocol Maturation

Making DCP a formal standard that any implementation can conform to.

### Formal Specification
- [ ] DCP protocol specification document (versioned, RFC-style)
- [ ] Conformance test suite — any vault implementation can verify compatibility
- [ ] Reference implementation clearly separated from protocol spec
- [ ] Interoperability testing between implementations

### Advanced Privacy
- [ ] SD-JWT selective disclosure (share only specific fields from a record)
- [ ] Zero-knowledge proofs for age/identity verification without revealing data
- [ ] Encrypted search over vault records

### Ecosystem
- [ ] Multi-vault support (separate vaults for personal, work, trading)
- [ ] Vault-to-vault secure data sharing
- [ ] Plugin system for custom item types and operations
- [ ] Community-maintained schema registry

---

## Contributing

Every item marked **[help wanted]** is a good starting point. See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### High-Impact Contributions Right Now

1. **Python SDK** — the #1 request for non-JS agent frameworks
2. **New chain support** — EVM chains are straightforward (shared secp256k1 logic)
3. **Framework integrations** — LangChain, CrewAI, AutoGen wrappers
4. **New data schemas** — driver's license, health records, travel documents
5. **Documentation & examples** — real-world agent workflows

### Proposing New Features

Open a [GitHub Issue](https://github.com/1lystore/dcp/issues) with the `proposal` label. Include: what problem it solves, proposed API surface, and security implications. Features that change encryption, consent, or key management require discussion before implementation.

---

*This roadmap is updated as the project evolves. Last updated: March 2026.*