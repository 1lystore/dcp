# DCP Vault Desktop

Desktop app for operating a DCP vault without living in the CLI.

This package is the source for the desktop app. It is not published to npm as an installable library.

## What The Desktop App Does

- onboarding for a new vault and recovery phrase
- wallet creation and basic vault management
- local consent and session approval UI
- trusted service management
- relay setup for the default public relay or your own relay
- one-command VPS pairing flow for remote agents
- activity log and budget configuration
- bundled local DCP server runtime for production builds

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
- add a verified service or a custom trusted service
- choose permissions and budgets

In **Connect**:
- set permissions for a VPS agent
- click **Generate Pairing Token**
- copy the generated one-command VPS setup command

### 4. Approve requests

Use the built-in consent screens when a request exceeds the current auto-approved session or threshold.

## What The Desktop UI Exposes

### Connect page

- relay URL configuration
- default public relay shortcut: `wss://relay.dcp.1ly.store`
- quick links for known services
- pairing token generation for VPS agents
- one-command `npx -y -p @dcprotocol/proxy dcp-proxy --pair ...` output
- advanced connection bundle copy

### Settings page

- trusted services list and editor
- known-service presets
- scope presets for signing, reads, writes, and budget checks
- per-service budgets and auto-approve thresholds
- budget configuration for the vault
- active session management

## Development

### Prerequisites

- Node.js `>=18 <23`
- Node 20 LTS is the safest default
- Rust stable
- platform build tools required by Tauri

### Run from source

From the repo root:

```bash
npm install
npm -w @dcprotocol/server run build
cd packages/dcp-desktop
npm run tauri:dev
```

### Build production bundles

```bash
cd packages/dcp-desktop
npm run tauri:build
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
lsof -nP -iTCP:8420 -sTCP:LISTEN  # CLI server
lsof -nP -iTCP:8421 -sTCP:LISTEN  # Desktop app server
```

### Native dependency mismatch during builds

```bash
npm rebuild better-sqlite3
```

## Security Notes

- passphrases are not written to disk
- recovery phrase is shown once during onboarding
- private keys stay in the vault
- production bundles ship with the local runtime they need
- relay access still respects trust, budgets, sessions, and consent

## Related Docs

- Root: `README.md`
- CLI flows: `packages/dcp-cli/README.md`
- SDK flows: `packages/dcp-client/README.md`
