# DCP Vault Desktop

Desktop app for operating a DCP vault without living in the CLI.

This package is the source for the desktop app. It is not published to npm as an installable library.

## What The Desktop App Does

- Onboarding for a new vault and recovery phrase
- Wallet creation and basic vault management
- Local consent and session approval UI
- Trusted service management (1ly, Virtuals, custom)
- Relay setup for the default public relay or your own relay
- VPS agent pairing with verification phrase flow
- Telegram notification setup
- Activity log and budget configuration
- Bundled local DCP vault runtime for production builds

## Normal User Flow

### 1. Create or unlock the vault

Open DCP Vault and finish onboarding.

### 2. Connect the vault to a relay

In **Connect**:
- click **Use relay.dcp.1ly.store**
- click **Save Relay**

That hosted relay is the default public relay run by the DCP maintainers. It is optional; advanced users can replace it with their own relay URL.

### 3. Trust a service or create a VPS pairing token

In **Settings**:
- Add a verified service or a custom trusted service
- Choose permissions and budgets
- Configure Telegram notifications

In **Agents**:
- View connected agents
- Generate pairing tokens for new VPS agents
- Approve pending pairing claims with verification phrase
- Manage agent permissions and budgets

### 4. Approve requests

Use the built-in consent screens or Telegram notifications when a request exceeds the current auto-approved session or threshold.

## Desktop UI Pages

### Home

- Dashboard with vault status
- Quick actions

### Agents

- List all connected agents (local and VPS)
- Pairing token generation
- Pending pairing claim approval (with 3-word verification phrase)
- Edit agent permissions and budgets
- Revoke agent access

### Connect

- Relay URL configuration
- Default public relay shortcut: `wss://relay.dcp.1ly.store`
- Quick links for known services
- Advanced connection bundle copy

### Data

- View and edit stored credentials
- Manage identity, addresses, preferences

### Activity

- Audit log of all vault operations

### Settings

- Trusted services list and editor
- Known-service presets (1ly, Virtuals)
- Scope presets for signing, reads, writes
- Per-service budgets and auto-approve thresholds
- Budget configuration for the vault
- Telegram notification setup
- Recovery phrase management

## Development

### Prerequisites

- Node.js `>=22 <23`
- Run `nvm use` from the repo root before installing or building
- pnpm (`npm install -g pnpm` or use corepack)
- Rust stable
- Platform build tools required by Tauri

### Run from source

From the repo root:

```bash
pnpm install
pnpm run build
cd packages/dcp-desktop
pnpm run tauri:dev
```

### Build production bundles

```bash
cd packages/dcp-desktop
pnpm run bundle
pnpm run tauri:build
```

Build artifacts are created under:

- `src-tauri/target/release/bundle/macos/DCP Vault.app`
- `src-tauri/target/release/bundle/dmg/DCP Vault_0.2.0_aarch64.dmg`

## Packaging Notes

Production builds bundle:
- a Node runtime
- the DCP helper bundle
- a packaged DCP vault runtime at `src-tauri/resources/dcp-vault-runtime`

End users do **not** need Node installed to run the packaged app.

## Runtime Behavior

- the local server listens on `http://127.0.0.1:8421`
- the server binds to localhost only
- closing the main window hides the app to tray
- quitting the app stops the bundled server and exits fully

This matches the standard desktop-app pattern: close hides, quit exits.

## Troubleshooting

### App opens but shows stale behavior

Open the freshly built app bundle directly before replacing an older installed copy:

```bash
open "src-tauri/target/release/bundle/macos/DCP Vault.app"
```

### Ports are already in use

Check the local vault and relay ports:

```bash
lsof -nP -iTCP:8421 -sTCP:LISTEN  # Desktop app / vault server
```

### Native dependency mismatch during builds

```bash
pnpm rebuild better-sqlite3
```

## Security Notes

- Passphrases are not written to disk
- Recovery phrase is shown once during onboarding
- Private keys stay in the vault
- Production bundles ship with the local runtime they need
- Relay access still respects trust, budgets, sessions, and consent

## Related Docs

- Root: `README.md`
- Vault CLI/Server: `packages/dcp-vault/README.md`
- Agent: `packages/dcp-agent/README.md`
- Telegram: `packages/dcp-telegram/README.md`
