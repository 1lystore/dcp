# DCP

DCP is a personal vault for AI agents.

It lets agents use identity, credentials, wallets, and approvals without taking possession of raw secrets. The vault stays with the user. Agents get scoped access and the user can approve, deny, budget, or revoke.

## Try It

Install the vault CLI:

```bash
npm install -g @dcprotocol/vault
```

Create a vault and add a little data:

```bash
dcp init
dcp create-wallet --chain solana
dcp add identity.email
dcp list
```

Install the agent runtime:

```bash
npm install -g @dcprotocol/agent
```

Run it as a local MCP server:

```bash
dcp-agent run --mode mcp --agent claude_desktop
```

MCP config:

```json
{
  "command": "dcp-agent",
  "args": ["run", "--mode", "mcp", "--agent", "claude_desktop"]
}
```

For HTTP MCP clients:

```bash
dcp-agent run --mode http-mcp --agent openclaw_local --port 8420
```

Endpoint:

```text
http://127.0.0.1:8420/mcp
```

## What Is Inside

| Package | Purpose |
|---|---|
| `@dcprotocol/vault` | Vault CLI and local vault server |
| `@dcprotocol/agent` | MCP, HTTP MCP, and remote sidecar runtime |
| `@dcprotocol/core` | Crypto, storage, wallet, policy, and shared types |
| `@dcprotocol/relay` | Encrypted relay for remote agents |
| `@dcprotocol/telegram` | Telegram approval service |
| `@dcprotocol/desktop` | Desktop vault app |

## Telegram Approvals

Telegram gives users a second approval surface:

```text
🔐 Approval Needed

Claude Desktop wants to send 0.02 ETH on Base.

⏱️ Reply within 4m 58s
```

Run the Telegram service with a real bot token:

```bash
DCP_TELEGRAM_BOT_TOKEN="123456:..." dcp-telegram --host 127.0.0.1 --port 8423
```

## Remote Agents

For a VPS or remote agent, create an invite in DCP Desktop and run the generated command:

```bash
npx -y @dcprotocol/agent install-service 'dcp_vps_v1_...'
```

The remote agent talks to a local sidecar. The sidecar talks to the user's vault through the encrypted relay.

## Developer Checks

For contributors working from this repo:

```bash
pnpm install
pnpm -r run typecheck
pnpm -r run test
pnpm -r run build
node scripts/publish-guard.mjs
./scripts/test-security.sh
```
