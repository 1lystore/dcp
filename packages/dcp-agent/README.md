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
curl -fsSL https://dcpagent.com/install.sh | sudo bash -s -- 'dcp_vps_v1_...'
```

That command installs and pairs the DCP service, starts HTTP MCP, and tries to configure OpenClaw. It uses the system Node.js when it is compatible; otherwise it installs a private DCP runtime without changing OpenClaw.

If you prefer npm and the VPS already has a working Node/npm install:

```bash
sudo npx --yes @dcprotocol/agent@latest install-service 'dcp_vps_v1_...'
```

If OpenClaw is not verified and the gateway runs as the `openclaw` Linux user:

```bash
sudo npx --yes @dcprotocol/agent@latest configure-openclaw --user openclaw
```

For custom OpenClaw installs, print the manual MCP config:

```bash
sudo npx --yes @dcprotocol/agent@latest configure-openclaw --manual
```

Use the DCP MCP URL printed by `install-service`. Do not hardcode `172.17.0.1`; native, Docker, and custom networks can use different URLs.

After changing OpenClaw MCP config, start a fresh OpenClaw chat/session so the new tools are loaded.

## Useful Commands

```bash
dcp-agent status
dcp-agent list
dcp-agent remove <agent_id>
dcp-agent stop
```

## Safety

The agent runtime is a bridge. It does not store the vault, and it should never receive private keys. The vault decides what each agent can do.
