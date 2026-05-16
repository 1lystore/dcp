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

Hermes reads MCP servers from `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  dcp:
    command: "dcp-agent"
    args:
      - "run"
      - "--mode"
      - "mcp"
      - "--agent"
      - "agent_hermes_local"
    tools:
      prompts: false
      resources: false
```

After editing Hermes config, run `/reload-mcp` or restart Hermes.

## Run As HTTP MCP

For agents that connect to a local HTTP MCP endpoint:

```bash
dcp-agent run --mode http-mcp --agent openclaw_local --port 8420
```

Endpoint:

```text
http://127.0.0.1:8420/mcp
```

Hermes can also connect to the HTTP MCP endpoint:

```yaml
mcp_servers:
  dcp:
    url: "http://127.0.0.1:8420/mcp"
    tools:
      prompts: false
      resources: false
```

## Pair A Remote Agent

Create a remote invite in DCP Desktop, copy the command, and run it on the remote machine:

```bash
curl -fsSL https://dcpagent.com/install.sh | sudo bash -s -- 'dcp_vps_v1_...'
```

That command installs and pairs the DCP service, installs the service runtime under `/var/lib/dcp-agent`, starts HTTP MCP, and tries to configure OpenClaw and Hermes when either is detected. It uses the system Node.js when it is compatible; otherwise it installs a private DCP runtime without changing OpenClaw or Hermes.

Hermes is handled in two supported layouts:

- host-native Hermes: DCP writes `mcp_servers.dcp` with `hermes config set` as the Hermes user
- Docker Hermes: DCP detects the running Hermes container, binds MCP to a Docker-reachable host address, and writes config inside the container's `/opt/data/config.yaml`

Do not reuse old remote invite tokens. If an invite expired, pairing was revoked, or you cleaned/reinstalled the service, create a new invite in Desktop.

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

If host-native Hermes is not verified, run these as the Linux user that runs Hermes:

```bash
hermes config set mcp_servers.dcp.url http://127.0.0.1:8420/mcp
hermes config set mcp_servers.dcp.enabled true
hermes config set mcp_servers.dcp.tools.prompts false
hermes config set mcp_servers.dcp.tools.resources false
```

After changing Hermes MCP config, run `/reload-mcp` in Hermes or restart Hermes.

If Docker Hermes is not verified, use the MCP URL printed by the installer:

```bash
docker exec hermes /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.url http://172.17.0.1:8420/mcp
docker exec hermes /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.enabled true
docker exec hermes /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.tools.prompts false
docker exec hermes /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.tools.resources false
```

Then run `/reload-mcp` in Hermes or restart the Hermes container.

## Remote VPS Debug Path

### Known good path

1. Install and unlock DCP Desktop.
2. Create a remote invite in Desktop.
3. Run the generated command on the VPS.
4. Confirm the verification phrase in Desktop.
5. Approve pairing.
6. Start a fresh OpenClaw chat/session or run `/reload-mcp` in Hermes.
7. Ask the agent:

```text
What is my email from DCP?
```

Good install output includes:

```text
DCP service health: ok
OpenClaw detected: yes
OpenClaw can reach DCP: yes
OpenClaw config written: yes
OpenClaw config verified: yes
Hermes detected: yes
Hermes can reach DCP: yes
Hermes config written: yes
Hermes config verified: yes
```

The normal path is one command from Desktop:

```bash
curl -fsSL https://dcpagent.com/install.sh | sudo bash -s -- 'dcp_vps_v1_...'
```

The installer prints an `Install checks` block. Use that block first.

### 1. DCP service must be running

```bash
sudo systemctl status dcp-agent --no-pager -l
sudo journalctl -u dcp-agent -n 120 --no-pager -l
```

Good state:

```text
Active: active (running)
[DCP HTTP-MCP] Started on http://...:8420
```

If the service is restarting, check the log. Common causes are old global npm packages, bad Node versions, or npm cache permissions. The curl installer avoids most of this by using a private DCP Node runtime.

### 2. DCP health must answer

Use the exact URL printed by the installer:

```bash
curl -s http://127.0.0.1:8420/health
```

or, for Docker/OpenClaw bridge installs:

```bash
curl -s http://172.17.0.1:8420/health
```

Good response:

```json
{"status":"ok","agent":"your-vps-name"}
```

Do not copy `172.17.0.1` from another server. Use the MCP endpoint printed by your installer.

### 3. If OpenClaw cannot see DCP

First check what OpenClaw has saved:

```bash
sudo -u openclaw openclaw mcp show dcp --json
```

Expected shape:

```json
{
  "url": "http://127.0.0.1:8420/mcp",
  "transport": "streamable-http",
  "connectionTimeoutMs": 300000
}
```

The `url` may be a Docker bridge URL such as `http://172.17.0.1:8420/mcp`. That is fine if health works from the OpenClaw side.

If the gateway runs as the `openclaw` Linux user, write config as that user:

```bash
sudo npx --yes @dcprotocol/agent@latest configure-openclaw --user openclaw
```

Then start a fresh OpenClaw chat/session. Existing sessions can keep an old MCP runtime.

**Start a fresh OpenClaw session after MCP changes.** Seeing `dcp` in config does not guarantee the current chat already loaded the tools.

### 4. Docker/OpenClaw bridge check

If OpenClaw runs in Docker, the host may be healthy while the container cannot reach it.

Find the container:

```bash
docker ps --format 'table {{.Names}}\t{{.Networks}}'
```

Test from inside the OpenClaw container:

```bash
docker exec <openclaw-container> sh -lc 'curl -s --max-time 5 http://172.17.0.1:8420/health'
```

Good response:

```json
{"status":"ok","agent":"your-vps-name"}
```

If the host uses UFW and the container times out, allow only Docker bridge traffic to DCP:

```bash
sudo ufw allow in on docker0 from 172.17.0.0/16 to 172.17.0.1 port 8420 proto tcp
sudo ufw reload
```

Then test from the container again.

### 5. Manual OpenClaw config

If automatic config does not match your OpenClaw install, print the manual config:

```bash
sudo npx --yes @dcprotocol/agent@latest configure-openclaw --manual
```

Add the printed server under OpenClaw's MCP config:

```json
{
  "mcp": {
    "servers": {
      "dcp": {
        "url": "http://127.0.0.1:8420/mcp",
        "transport": "streamable-http",
        "connectionTimeoutMs": 300000
      }
    }
  }
}
```

Use your printed URL, not this sample URL.

### 6. If Hermes cannot see DCP

First check what Hermes has saved:

```bash
hermes config show | grep -A 8 mcp_servers
```

Expected shape:

```yaml
mcp_servers:
  dcp:
    url: http://127.0.0.1:8420/mcp
    enabled: true
    tools:
      prompts: false
      resources: false
```

The `url` may be a Docker bridge URL such as `http://172.17.0.1:8420/mcp` when DCP had to bind to a Docker-reachable host address. That is expected for Hermes running inside Docker because `127.0.0.1` would refer to the Hermes container itself.

If the installer could not configure Hermes automatically, run:

```bash
hermes config set mcp_servers.dcp.url http://127.0.0.1:8420/mcp
hermes config set mcp_servers.dcp.enabled true
hermes config set mcp_servers.dcp.tools.prompts false
hermes config set mcp_servers.dcp.tools.resources false
```

Then run `/reload-mcp` in Hermes or restart Hermes.

For Docker Hermes, check and repair from the host:

```bash
docker exec hermes cat /opt/data/config.yaml | grep -A 8 mcp_servers
docker exec hermes curl -s http://172.17.0.1:8420/health
docker exec hermes /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.url http://172.17.0.1:8420/mcp
docker exec hermes /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.enabled true
```

Use the exact MCP URL printed by the installer.

### 7. Verify DCP MCP directly

This checks DCP itself, independent of OpenClaw:

```bash
curl -i -sS \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -X POST http://127.0.0.1:8420/mcp \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl-test","version":"1.0.0"}}}'
```

Good response includes:

```text
mcp-session-id: ...
"serverInfo":{"name":"dcp-agent"
```

Use that `mcp-session-id` to list tools:

```bash
curl -i -sS \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'mcp-session-id: PASTE_SESSION_ID_HERE' \
  -X POST http://127.0.0.1:8420/mcp \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized"}'

curl -i -sS \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'mcp-session-id: PASTE_SESSION_ID_HERE' \
  -X POST http://127.0.0.1:8420/mcp \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

Good tool list includes:

```text
vault_read
vault_write
vault_get_address
vault_budget_check
vault_sign_tx
vault_sign_message
vault_sign_x402
vault_scope_guide
```

### Test prompts

After pairing and starting a fresh OpenClaw or Hermes session, use simple prompts first:

```text
What is my email from DCP?
What is my Solana wallet address?
Send 0.00001 SOL to <address>
Send 1000 1LY to <address>
Sign this x402 Solana payment payload: <base64_payload>
```

For write/sign prompts, DCP should ask for approval in Desktop or Telegram unless the action is under the user's configured auto-approval threshold.

### 7. When to reinstall

If you revoked the old agent in Desktop, create a new invite and run the new Desktop command. The installer stops the old service and writes the new paired config.

For a clean uninstall:

```bash
sudo npx --yes @dcprotocol/agent@latest uninstall-service
```

Then create a fresh invite in Desktop and run the generated command again.

### Support paste

When asking for help, paste this output:

```bash
sudo systemctl status dcp-agent --no-pager -l
curl -s <printed-health-url>
sudo journalctl -u dcp-agent -n 80 --no-pager -l
sudo -u openclaw openclaw mcp show dcp --json
```

## Useful Commands

```bash
dcp-agent status
dcp-agent list
dcp-agent remove <agent_id>
dcp-agent stop
```

## Safety

The agent runtime is a bridge. It does not store the vault, and it should never receive private keys. The vault decides what each agent can do.
