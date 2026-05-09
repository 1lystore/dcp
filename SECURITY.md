# Security Model

DCP is designed to let AI agents use approved capabilities without receiving raw private keys or unrestricted vault access.

Current status: beta-readiness. This document describes the intended security posture of the current open-source implementation. It is not a completed external audit.

## Core Rule

Agents get use of data, not blanket access to the vault.

Examples:

- A wallet key is used to sign; the private key is not returned.
- A credential can be exposed only through an explicit scoped read path and policy decision.
- A remote agent talks through a sidecar and relay; the relay should only see encrypted envelopes.

## Main Components

```text
dcp-desktop     user approval UI and local vault manager
dcp-vault       local CLI and HTTP server
dcp-core        encryption, storage, wallet, budget, pairing, audit types
dcp-agent       MCP / HTTP MCP / proxy / remote sidecar runtime
dcp-relay       encrypted message relay for remote agents
dcp-telegram    Telegram pairing and approval service
```

## Threat Model

### In Scope

| Threat | Mitigation |
|---|---|
| Agent asks for wallet private key | Critical wallet records are not readable; signing happens inside the vault process |
| Agent exceeds policy or budget | Policy checks, budgets, approval thresholds, revoke checks |
| Agent keeps using old access after revoke | Agent/session state is checked on future requests |
| Relay operator reads request contents | Relay path is designed around encrypted envelopes |
| Telegram leaks secret values | Telegram notification formatter must stay privacy-safe |
| Local DB is copied | Vault records are encrypted at rest |
| Duplicate/replayed Telegram approval command | Nonce/single-use command checks |
| Accidental package publication of old/internal surfaces | `scripts/publish-guard.mjs` |

### Out Of Scope

| Threat | Notes |
|---|---|
| Fully compromised OS account | A local attacker with user-level access may inspect processes/files |
| Malware on the same machine | Localhost services assume a trusted local environment |
| Physical device compromise | Use OS/device security controls |
| Side-channel attacks | Not hardened against timing/cache/EM side channels |
| Malicious browser extensions or local process injection | Outside current protection boundary |
| Formal compliance guarantees | No SOC2/GDPR/HIPAA guarantee in this repo |

## Data Classes

| Class | Examples | Expected Agent Access |
|---|---|---|
| Standard | preferences, non-sensitive settings | May be read with policy/consent |
| Sensitive | name, email, address, API credentials | May require explicit approval and scope |
| Critical | wallet private keys, master key material | Must not be returned directly |

Credential reads are sensitive. If a policy allows `read:credentials.*`, the agent may receive that credential value. Do not grant broad credential scopes casually.

## Cryptography

Current core primitives:

| Area | Primitive |
|---|---|
| Record encryption | XChaCha20-Poly1305 |
| Key derivation | Argon2id for passphrase wrapping |
| Recovery phrase | BIP-39 mnemonic |
| Signing identity | Ed25519 |
| Canonical request signing | recursive canonical JSON helper |

Record encryption uses envelope encryption:

```text
record data -> random DEK -> encrypted payload
DEK         -> master key -> encrypted DEK
```

Sensitive buffers should be zeroized after use where practical. JavaScript cannot guarantee full memory erasure, so do not claim hard memory-safety guarantees beyond best-effort zeroization.

## Local Vault Security

The local vault server is intended to bind to localhost for development and Desktop use.

Important local assumptions:

- Localhost is not a security boundary against malware running as the same user.
- Vault unlock state matters.
- Agent requests must still pass policy/consent checks.
- Owner/Desktop flows may have elevated local control compared with normal agent requests.

## Approval Model

Requests can be:

- allowed by policy/session
- blocked by policy/revoke/budget
- converted into a pending consent
- denied by user action
- expired by timeout

Approval surfaces:

- Desktop approval UI
- Telegram approval notification/inline buttons
- local consent endpoints used by tooling/tests

Telegram approval should remain single-use and privacy-safe.

## Telegram Privacy Rule

Telegram messages may include:

- agent name
- high-level request category
- simple human-readable context
- expiration countdown

Telegram messages must not include:

- private keys
- API keys
- raw transaction payloads
- seed phrases
- full credentials
- decrypted vault record bodies

Approved notification style:

```text
🔐 Approval Needed

Claude Desktop wants to send 0.02 ETH on Base.

⏱️ Reply within 4m 58s
```

## Remote/VPS Security

Remote agents use a sidecar pattern:

```text
remote agent -> localhost sidecar -> encrypted relay -> local vault
```

Security expectations:

- sidecar listens on `127.0.0.1`
- sidecar stores only its own pairing/agent material
- relay cannot read plaintext payloads
- vault can revoke the remote agent
- pairing requires a user-visible verification/approval step

Real VPS behavior must be validated before public beta.

## Audit Log

The vault stores local audit events for security-sensitive actions such as:

- consent grant/deny
- reads
- signing/execution
- revoke
- config changes
- expiration

Audit events should include enough metadata to understand what happened without leaking raw secrets.

## Package And Release Safety

Before publishing beta packages:

```bash
node scripts/publish-guard.mjs
pnpm -r run typecheck
pnpm -r run test
pnpm -r run build
./scripts/test-security.sh
```

Also run:

- clean-room npm tarball install
- production dependency audit
- stale package-name scan
- secret/log scan

## Secret/Log Scan

Use:

```bash
rg -n "private_key|servicePrivateKey|mnemonic|seed|secret|api_key|token|signature" packages scripts -g '!**/dist/**' -g '!**/node_modules/**'
```

Review results manually. Some names are legitimate fields or tests, but logs and user-facing messages must not reveal secret values.

## User Guidance

- Use a strong passphrase.
- Store the recovery phrase offline.
- Keep budgets low at first.
- Review agent scopes before approving.
- Revoke agents you no longer use.
- Do not approve broad credential access unless you understand the agent.

## Developer Guidance

- Request the narrowest scope possible.
- Prefer signing/use operations over raw secret reads.
- Include clear descriptions for user approvals.
- Handle denied/timeout/revoked errors cleanly.
- Do not log request payloads that may contain secrets.
- Keep Telegram copy privacy-safe.

## Vulnerability Reporting

Do not open a public issue for a suspected vulnerability.

Report privately to the maintainers with:

- affected package/flow
- reproduction steps
- expected impact
- any logs or payloads with secrets redacted

Allow time for a fix before public disclosure.
