# @dcprotocol/mcp

MCP server for DCP Vault. Use this to connect AI agents (Claude, Cursor, OpenClaw, etc.) to a local DCP vault without exposing private keys.

## Install

```bash
npm install @dcprotocol/mcp
```

## Run

```bash
npx @dcprotocol/mcp
```

## Tools

Available tools:

- `vault_list_scopes`
- `vault_get_address`
- `vault_budget_check`
- `vault_read`
- `vault_sign_tx`
- `vault_unlock`
- `vault_lock`

### Input/Output Highlights

**vault_read**
- Input: `{ scope, fields? }`
- `fields` (optional) lets the agent request a subset of keys.

**vault_sign_tx**
- Input: `{ chain, unsigned_tx, description?, amount?, currency?, destination?, idempotency_key? }`
- Budget enforcement uses `amount` + `currency` if provided.

**vault_budget_check**
- Input: `{ amount, currency, chain? }`  
  (chain is required for USDC/USDT)
- Output: `{ allowed, remaining, limits, requires_approval }`

## Unlock Flow

MCP is a separate process and must be unlocked before reads/signing:

```json
vault_unlock({ "passphrase": "..." })
```

To avoid typing your passphrase in chat, use the local UI:

1) Start REST server: `npx @dcprotocol/server`  
2) Open `http://127.0.0.1:8420`  
3) Click **Unlock MCP** (uses OS keychain; no passphrase is written to disk)

## Consent Flow

First access requires approval. You can approve via:

- CLI: `dcp approve <consent_id> --session`
- UI: `http://127.0.0.1:8420`

By default MCP runs in **non‑TTY mode**: it creates a pending consent and waits until you approve via UI/CLI.
To enable interactive terminal prompts, set `DCP_MCP_ALLOW_TTY=1`.

For stable sessions across restarts, set a fixed agent name:

```bash
MCP_AGENT_NAME=claude-desktop
```

## Sessions and Limits

- Session timeout: **30 min idle**, **4 hours max**
- Rate limit: **5 operations/minute** per session

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VAULT_DIR` | Vault storage directory | `~/.dcp` |
| `DCP_MCP_ALLOW_TTY` | Enable terminal consent prompts | `0` |
| `MCP_AGENT_NAME` | Stable agent name for session reuse | `MCP Agent` |
| `DCP_MCP_SESSION_MINUTES` | Auto‑unlock window after UI unlock | `30` |

## Claude Desktop Example

```json
{
  "mcpServers": {
    "dcp": {
      "command": "npx",
      "args": ["@dcprotocol/mcp"]
    }
  }
}
```

Docs: see the root README for full usage and architecture.
