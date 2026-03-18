# @dcprotocol/cli

CLI for operating a DCP vault.

This is the main tool for developers, operators, and headless environments.

## Install

```bash
npm install -g @dcprotocol/cli
```

## Linux Notes

- This is the human/operator CLI, not the recommended VPS-agent package.
- On Debian/Ubuntu, install `libsecret-1-0` for keychain-backed local vault usage.
- For remote agents and VPS hosts, prefer `@dcprotocol/proxy` and `dcp-proxy`.
- Example relay URLs in this README use the default public relay `wss://relay.dcp.1ly.store`; replace it if you run your own relay.

## What The CLI Covers

- initialize and recover a vault
- create wallets and store data
- run approvals and manage sessions
- trust and connect remote services
- generate pairing tokens for VPS agents
- run a local proxy for remote agents

## Fastest Local Setup

```bash
dcp init
dcp create-wallet --chain solana
dcp add address.home
dcp add identity.email
npx -y @dcprotocol/server
```

Open `http://127.0.0.1:8420` for the local approval UI.

## Command Groups

### Vault setup and data

| Command | Purpose |
| --- | --- |
| `dcp init` | Initialize a new vault |
| `dcp recovery restore` | Restore from recovery phrase |
| `dcp create-wallet --chain <chain>` | Create a wallet inside the vault |
| `dcp add <scope>` | Add a scope interactively |
| `dcp update <scope>` | Update a stored record |
| `dcp remove <scope>` | Delete a stored record |
| `dcp read <scope>` | Read a stored record |
| `dcp list` | List scopes in the vault |
| `dcp status` | Show summary status |
| `dcp config` | View or update budgets and limits |
| `dcp activity` | Show audit logs |

### Approvals and sessions

| Command | Purpose |
| --- | --- |
| `dcp approve --list` | List pending consent requests |
| `dcp approve <consent-id>` | Approve a request |
| `dcp approve <consent-id> --session` | Approve and create a reusable session |
| `dcp agents` | List active agent sessions |
| `dcp revoke <session-or-agent>` | Revoke a session or agent |

### Remote services

| Command | Purpose |
| --- | --- |
| `dcp trust <service>` | Add or update a trusted service |
| `dcp trust <service> --list` | List trusted services |
| `dcp trust <service> --revoke` | Revoke a trusted service |
| `dcp connect <service>` | Send vault routing info to a service |

### Remote VPS / proxy

| Command | Purpose |
| --- | --- |
| `dcp pairing start <service>` | Create a short-lived pairing token |
| `dcp proxy ...` | Run a proxy from the operator CLI (advanced/local compatibility) |

## Common Flows

### 1. Trust a verified service

```bash
dcp trust 1ly
```

### 2. Trust a custom service

```bash
dcp trust openclaw-prod \
  --key ed25519:<base64-public-key> \
  --scopes sign:solana,read:credentials.api.* \
  --budget 10usdc/day \
  --auto-approve-under 1usdc
```

### 3. Connect a trusted service

```bash
dcp connect 1ly
```

For a custom service:

```bash
dcp connect openclaw-prod \
  --url https://example.com/api/dcp/connect \
  --auth-url https://example.com/settings/dcp
```

### 4. Create a pairing token for a VPS proxy

```bash
dcp pairing start openclaw-vps \
  --scopes sign:solana,budget:check \
  --budget 10usdc/day \
  --auto-approve-under 1usdc
```

### 5. Start a proxy on the VPS

```bash
npx -y -p @dcprotocol/proxy dcp-proxy \
  --pair "<pairing-token>" \
  --service-id "openclaw-vps" \
  --vault "<vault-id>" \
  --hpke-key "<vault-hpke-public-key>" \
  --relay "wss://relay.dcp.1ly.store" \
  --port 8420
```

The proxy stores its identity under `~/.dcp/proxy/<service-id>.json` and exposes a local DCP-compatible endpoint for the agent. For published/npm VPS installs, prefer `@dcprotocol/proxy` and `dcp-proxy` instead of the heavier human CLI path.

## Useful Flags

### `dcp trust`

- `--key <ed25519:...>`: required for custom services
- `--scopes <a,b,c>`: explicit allowed scopes
- `--budget <10usdc/day>`: daily budget
- `--auto-approve-under <1usdc>`: auto-approval threshold
- `--list`: list trusted services
- `--revoke`: revoke trust
- `--yes`: skip confirmation prompts

### `dcp connect`

- `--url <https://...>`: custom connect endpoint
- `--auth-url <https://...>`: custom auth page
- `--relay-url <wss://...>`: override relay URL
- `--no-browser`: print the auth URL instead of opening it

### `dcp pairing start`

- `--scopes <a,b,c>`: required
- `--budget <10usdc/day>`: daily budget
- `--auto-approve-under <1usdc>`: auto-approval threshold
- `--ttl <seconds>`: token lifetime, default `600`

### `dcp proxy`

- `--vault <vault-id>`: target vault
- `--hpke-key <base64>`: vault HPKE relay public key
- `--relay <wss://...>`: relay endpoint
- `--service-id <id>`: service/proxy identity
- `--service-key <base64>`: service private key for direct relay mode
- `--pair <token>`: pair and generate identity automatically
- `--port <port>`: local port, default `8420`
- `--agent-name <name>`: agent name used by proxied requests

## Session Cache

After a successful CLI unlock, DCP caches local unlock state for 30 minutes by default.

Environment variables:

- `DCP_CLI_SESSION_MINUTES`
- `DCP_CLI_INSECURE_SESSION=1` for file-based fallback when keychain is unavailable

## Notes

- Use the CLI when you want full control and reproducible setup.
- Use the desktop app when the operator wants a GUI.
- Use `@dcprotocol/client` when you are embedding DCP in code.

## Troubleshooting

### Native module problems after switching Node versions

```bash
npm rebuild better-sqlite3
```

### Want to run from source instead of the published package

```bash
npm -w @dcprotocol/cli run build
node packages/dcp-cli/dist/cli.js --help
```

## Related Docs

- Root: `README.md`
- SDK: `packages/dcp-client/README.md`
- Desktop: `packages/dcp-desktop/README.md`
