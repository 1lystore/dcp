# @dcprotocol/cli

DCP command‑line tool for creating a vault, managing data, and approving agent access.

This is the primary interface for developers and power users.

## Install

```bash
npm install -g @dcprotocol/cli
```

## Quick Start

```bash
dcp init
dcp create-wallet --chain solana
dcp add address.home
dcp list
```

## Common Commands

- `dcp init` — initialize vault (shows recovery phrase once)
- `dcp create-wallet --chain solana|base|ethereum`
- `dcp add <scope>` — add data (address, identity, preferences)
- `dcp read <scope>` — display STANDARD/SENSITIVE data
- `dcp list` — list scopes (no values shown)
- `dcp update <scope>` / `dcp remove <scope>`
- `dcp status` — show vault status and counts
- `dcp approve --list` — view pending consents
- `dcp approve <id> --session` — approve a consent and create session
- `dcp agents` / `dcp revoke <id>`
- `dcp config` — budgets and limits
- `dcp activity` — audit log
- `dcp recovery restore` — restore from phrase

## Useful Flags

**init**
- `-f, --force` — reinitialize even if a vault exists

**list**
- `-t, --type <wallet|identity|address|preferences|credentials|health|budget>`
- `-c, --chain <solana|base|ethereum>`
- `-v, --verbose` — show created/updated timestamps

**add / update**
- `-d, --data <json>` — non‑interactive JSON input
- `-s, --sensitivity <standard|sensitive|critical>` (add only)

**remove / revoke**
- `-f, --force` — skip confirmation

**activity**
- `--limit <n>`, `--agent <name>`, `--type <type>`, `--last <duration>`

## CLI Session Cache

After one successful unlock, the CLI caches unlock state for 30 minutes (local only).  
This avoids repeated passphrase prompts during setup.

Override with:
- `DCP_CLI_SESSION_MINUTES` (minutes)
- `DCP_CLI_INSECURE_SESSION=1` (file‑based cache if keychain unavailable)

## Consent Flow

When agents request data or signing, DCP creates a pending consent. You can approve via:

```bash
dcp approve --list
dcp approve <consent_id> --session
```

Or via the local approval UI at `http://127.0.0.1:8420` if the REST server is running.

## Sensitivity Levels

- **STANDARD**: consent required for reads
- **SENSITIVE**: consent + purpose required
- **CRITICAL**: never shown in plaintext (reference only)

## Notes

- CLI is local‑first. Your data never leaves your machine.
- For agent integration, use `@dcprotocol/mcp` or `@dcprotocol/server`.
- See the root README for full docs.
- Full scope definitions and fields live in `SCHEMA.md`.
