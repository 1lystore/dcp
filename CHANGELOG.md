# Changelog

All notable changes to this repository will be documented here.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

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
