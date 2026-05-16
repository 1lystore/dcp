# @dcprotocol/desktop

DCP Desktop is the user app for the vault.

Use it to create and unlock the vault, approve agent requests, manage agents, pair Telegram, create remote-agent invites, and review audit history.

## What Users Do Here

- create or unlock a vault
- add identity data and wallets
- connect local MCP agents such as Claude Desktop, Cursor, and Hermes
- create remote-agent invites for VPS OpenClaw and Hermes installs
- approve or deny requests
- connect Telegram approvals
- revoke agents
- view audit events

## Connect Agents

Use the **Connect** screen for local agents. Desktop writes the right MCP config for supported clients, including Hermes at `~/.hermes/config.yaml`.

Use the remote invite flow for agents running on a VPS. The generated curl command installs the DCP service, pairs it with this Desktop vault, starts HTTP MCP on the VPS, and configures OpenClaw or Hermes when detected.

## Source Build

Desktop uses Tauri, so local builds need Node, Rust, and the Tauri system prerequisites.

```bash
pnpm install
pnpm --filter @dcprotocol/desktop run build
pnpm --filter @dcprotocol/desktop run tauri:dev
```

Create a desktop app bundle:

```bash
pnpm --filter @dcprotocol/desktop run tauri:build
```

The desktop app packages a local vault runtime. After changing vault/runtime code, rebuild the app bundle from source before testing Desktop again.
