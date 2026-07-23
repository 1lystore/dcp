# Changelog

All notable changes to this repository will be documented here.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

Security hardening pass across the published packages. All changes are backward
compatible for normal flows; the Telegram cloud service and the vault must be
released together (the desktop↔cloud auth contract tightened — see below).

### Security
- `telegram`: `/register` is now trust-on-first-use — the first key registered for
  a vault wins, idempotent re-registration of the same key is allowed, and replacing
  an existing key with a different one requires a signature from the currently
  registered key. Closes an account-takeover hole where anyone who knew a `vault_id`
  could overwrite its trust-anchor key and forge webhooks.
- `telegram`: `/api/approvals/*` (list + processed) and pairing `unlink` now require
  an Ed25519 signature from the vault's registered key, with an ownership check so a
  signature for vault A cannot touch vault B. `vault` signs these calls accordingly.
- `core`/`vault`: agent transaction consent is now bound to the amount + destination
  the owner approved — an approval for transaction A can no longer be reused to sign a
  different transaction B.
- `vault`: `sign_message` is gated on its own consent scope, so a session approved for
  sending transactions no longer silently authorizes signing arbitrary off-chain
  messages.
- `vault`: `GET /v1/vault/activity` now requires the owner token (the audit trail
  exposes amounts, destinations, and which credentials were read).
- `core`/`agent`/`relay`: the pairing verification phrase moved to a single shared
  implementation using the BIP-39 2048-word list and 4 words (~2^44 collision
  resistance, up from ~2^15), defeating offline phrase-collision grinding by a MITM.
- `relay`: `/oauth/authorize` validates `redirect_uri` — rejects non-http(s) schemes
  and, for registered clients, enforces an exact allow-list match (OAuth 2.1).

### Fixed
- `core`: `checkBudget` rejects non-finite/negative amounts (fail closed) so a crafted
  `NaN`/negative amount can no longer bypass per-tx and daily limits.
- `agent`: HTTP MCP server shuts down cleanly on repeated Ctrl+C — idempotent stop,
  force-closes long-lived Streamable-HTTP connections (no more hang), and a hard
  timeout guarantees exit.
- `wallet-core`: `solana-reads` degrades gracefully when SPL-token reads are gated
  (returns an empty, flagged token list instead of blanking the wallet).

### Publishing
- `@dcprotocol/wallet-core` must be published (it is a new `workspace:*` dependency of
  `core`, `agent`, and `vault`). Publish with **`pnpm publish`**, never `npm publish`:
  only pnpm rewrites `workspace:*` → the concrete version; a plain `npm publish` ships
  a literal `workspace:*` and every install fails.

## 3.0.0 — 2026-06-15

Major, lockstep release of all published `@dcprotocol/*` packages (`core`, `vault`,
`agent`, `client`, `relay`, `relay-client`) to a single `3.0.0`. The version jump
realigns published npm content with the current source — earlier `2.0.x` npm
artifacts had drifted from the repo (same numbers, stale content), which could
leave downloaded apps calling symbols that were not in the published build.

### Added
- `core`: agent connection display-name update support (`updateAgentConnection({ name })`)
  and the vault `PATCH` agent endpoint accepts an optional `name` (display-only rename).

### Fixed
- `core`: keychain master-key storage now deletes any existing entry before writing,
  so a vault recreated at the same path can never inherit a stale key (prevents a
  class of recovery-phrase mismatches).
- `core`/`vault`: owner-mode reads (the desktop reading its own data) no longer
  pollute the audit log as agent activity.

### Migration notes
- Bump all `@dcprotocol/*` dependencies to `^3.0.0` together; mixing `2.x` and `3.x`
  across these packages is unsupported.
- No API removals. Code written against `2.x` continues to work; the major bump
  reflects the lockstep republish, not breaking signatures.

## 2.0.4 — 2026-05-20

### Fixed
- Fixed auto-approved budget accounting so `sign_x402` and `/v1/vault/sign` spend is recorded even when no wallet session exists.
- Kept internal budget ledger sessions out of user-facing agent lists, so Desktop does not show accounting-only sessions as connected agents.
- Added regression coverage for repeated under-threshold spend reaching the daily budget limit.

### Thanks
- Thanks to @TateLyman for reporting and fixing the auto-approved spend accounting issue, including the follow-up tests and internal-session UX cleanup.

## 0.2.0 — 2026-03-19

### Added
- `@dcprotocol/client`, a programmatic client for local or relay-backed vault experiments.
- `@dcprotocol/agent`, a lightweight runtime for local MCP, HTTP MCP, and remote/VPS sidecar use.
- CLI support for trusted services with `dcp trust`.
- CLI support for service connection handoff with `dcp connect`.
- CLI support for short-lived proxy pairing tokens with `dcp pairing start`.
- CLI support for remote localhost proxies with `dcp proxy`.
- Desktop Trusted Services management UI.
- Desktop Connect flow for hosted relay setup, trusted service links, and VPS pairing commands.
- Pairing token flow for remote agents that should use a local proxy instead of direct relay credentials.
- End-to-end scripts for relay and pairing flows.

### Changed
- Desktop production builds now bundle a complete Node runtime plus packaged DCP server runtime for end-user installs.
- Desktop close/quit behavior now matches standard desktop apps: closing hides to tray, quitting stops the bundled server.
- Local developer docs now cover CLI, agent, desktop, relay, and VPS proxy setup.
- Local CORS handling accepts localhost origins across dev ports for local approval and onboarding flows.

### Fixed
- Packaged desktop app now launches the bundled server from a stable runtime path instead of depending on a dev-only layout.
- Relay package no longer auto-starts when imported as a library.
- Vault schema migrations now run on startup so older vaults get pairing and trusted-service tables automatically.
- Desktop packaging ignores generated runtime artifacts and removes noisy debug output from public source.
- Relay and pairing end-to-end flows were stabilized and verified.

## 0.1.1 — 2026-03-04

### Added
- Local approval UI + consent flow for REST/MCP (session support and MCP unlock bridge).
- `dcp read` command and expanded scope set (drivers_license, travel, credentials, health, budget).
- Canonical schema v1.0 (`SCHEMA.md`) and improved docs.
- CLI session cache (keychain-backed, 30-minute default).

### Fixed
- Wallet scope consistency across CLI/MCP/REST.
- EVM signing accepts JSON TransactionRequest or raw RLP hex.
- Keychain fallback and unlock flows hardened; no passphrase is written to disk.
- Non-TTY consent and locked-vault handling stabilized for MCP/REST.
