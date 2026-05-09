# @dcprotocol/agent

The agent runtime for DCP.

Use it when Claude Desktop, Cursor, OpenClaw, Hermes, or another agent needs to reach a DCP vault without seeing the vault's raw secrets.

## Install

```bash
npm install -g @dcprotocol/agent
```

Or run it directly:

```bash
npx -y @dcprotocol/agent --help
```

## Run As MCP

For stdio MCP clients:

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

## Run As HTTP MCP

For agents that connect to a local HTTP MCP endpoint:

```bash
dcp-agent run --mode http-mcp --agent openclaw_local --port 8420
```

Endpoint:

```text
http://127.0.0.1:8420/mcp
```

## Pair A Remote Agent

Create a remote invite in DCP Desktop, copy the command, and run it on the remote machine:

```bash
npx -y @dcprotocol/agent install-service 'dcp_vps_v1_...'
```

The sidecar listens on localhost and routes encrypted requests back to the user's vault through the relay.

## Useful Commands

```bash
dcp-agent status
dcp-agent list
dcp-agent remove <agent_id>
dcp-agent stop
```

## Safety

The agent runtime is a bridge. It does not store the vault, and it should never receive private keys. The vault decides what each agent can do.
