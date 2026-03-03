# Changelog

All notable changes to this repository will be documented here.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## 0.1.1 — 2026-03-04

### Added
- Local approval UI + consent flow for REST/MCP (session support and MCP unlock bridge).
- `dcp read` command and expanded scope set (drivers_license, travel, credentials, health, budget).
- Canonical schema v1.0 (`SCHEMA.md`) and improved docs.
- CLI session cache (keychain-backed, 30‑minute default).

### Fixed
- Wallet scope consistency across CLI/MCP/REST.
- EVM signing accepts JSON TransactionRequest or raw RLP hex.
- Keychain fallback and unlock flows hardened; no passphrase is written to disk.
- Non‑TTY consent and locked‑vault handling stabilized for MCP/REST.
