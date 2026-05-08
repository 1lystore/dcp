# @dcprotocol/agent

Lightweight binary for connecting AI agents to DCP vaults via pairing grants.

## Installation

### One-liner (recommended for VPS)

```bash
curl -fsSL https://dcp.1ly.store/install | sh
```

With automatic pairing:
```bash
curl -fsSL https://dcp.1ly.store/install | sh -s -- --pair dcp_pair_v1_...
```

### npm

```bash
npm install -g @dcprotocol/agent
```

### Docker

```bash
docker pull dcprotocol/agent
```

## Quick Start

### 1. Get a Pairing Grant

From the DCP Desktop app or CLI:
- Open **Connect** page
- Configure permissions and budget
- Click **Generate Pairing Token**
- Copy the `dcp_pair_v1_...` token

### 2. Pair Your Agent

```bash
dcp-agent pair dcp_pair_v1_eyJ...
```

This automatically:
- Verifies the grant signature and expiration
- Creates config at `~/.dcp/agents/{agent_id}.json` with `0600` permissions
- Stores vault connection details (HPKE keys, relay URL, scopes)

### 3. Run the Agent

```bash
dcp-agent run
```

The agent starts a local proxy server at `http://127.0.0.1:8420` that forwards requests to your vault via the relay.

## Commands

| Command | Description |
|---------|-------------|
| `dcp-agent pair <grant>` | Pair with a vault using a pairing grant token |
| `dcp-agent run` | Start the agent (--mode proxy/mcp/http-mcp) |
| `dcp-agent run --daemon` | Run in background (survives SSH disconnect) |
| `dcp-agent status` | Show agent configuration and status |
| `dcp-agent list` | List all configured agents |
| `dcp-agent remove <agent_id>` | Remove an agent configuration |
| `dcp-agent stop` | Stop daemon agent |
| `dcp-agent secrets` | OpenClaw secrets provider (stdin/stdout) |
| `dcp-agent get-secret <scope>` | Get a single secret from the vault |
| `dcp-agent install-service` | Install as systemd service (VPS) |
| `dcp-agent uninstall-service` | Uninstall systemd service |

## OpenClaw Integration

DCP Agent implements the [OpenClaw exec provider protocol](https://docs.openclaw.ai/gateway/secrets), allowing OpenClaw workflows to fetch secrets directly from your DCP vault.

### Configuration

Add DCP as a secrets provider in your OpenClaw config:

```json5
// openclaw.json5
{
  secrets: {
    providers: {
      dcp: {
        source: "exec",
        command: "dcp-agent",
        args: ["secrets"]
      }
    }
  }
}
```

### Using Secrets

Reference DCP secrets in your OpenClaw configuration:

```json5
{
  providers: {
    openai: {
      apiKey: { "$ref": "dcp:credentials.api.openai" }
    },
    anthropic: {
      apiKey: { "$ref": "dcp:credentials.api.anthropic" }
    }
  }
}
```

### Secret ID Formats

The provider supports multiple ID formats:

| Format | Example | Maps To |
|--------|---------|---------|
| DCP scope | `credentials.api.openai` | `credentials.api.openai` |
| OpenClaw providers | `providers/openai/apiKey` | `credentials.api.openai` |
| Identity | `identity.email` | `identity.email` |
| Address | `address.home` | `address.home` |

### Protocol

The provider speaks JSON over stdin/stdout:

**Request (stdin):**
```json
{
  "protocolVersion": 1,
  "provider": "dcp",
  "ids": ["credentials.api.openai", "credentials.api.stripe"]
}
```

**Response (stdout):**
```json
{
  "protocolVersion": 1,
  "values": {
    "credentials.api.openai": "sk-...",
    "credentials.api.stripe": "sk_live_..."
  }
}
```

**Error Response:**
```json
{
  "protocolVersion": 1,
  "values": {},
  "errors": {
    "credentials.api.missing": {
      "message": "Scope not in agent permissions"
    }
  }
}
```

## VPS / Cloud Deployment

### Quick Start (3 commands)

```bash
# 1. Install
curl -fsSL https://dcp.1ly.store/install | sh

# 2. Pair (one-time)
dcp-agent pair dcp_pair_v1_...

# 3. Done! OpenClaw will auto-fetch secrets
```

### Docker

Run with pairing grant:
```bash
docker run -e DCP_PAIR_GRANT=dcp_pair_v1_... dcprotocol/agent
```

With persistent config:
```bash
docker run -v dcp-config:/root/.dcp dcprotocol/agent
```

### Docker Compose with OpenClaw

```yaml
version: '3.8'
services:
  openclaw:
    image: openclaw/gateway
    volumes:
      - dcp-config:/root/.dcp
    environment:
      - OPENCLAW_SECRETS_PROVIDER=exec
      - OPENCLAW_SECRETS_EXEC_COMMAND=dcp-agent
      - OPENCLAW_SECRETS_EXEC_ARGS=secrets

  dcp-init:
    image: dcprotocol/agent
    command: ["pair", "${DCP_PAIR_GRANT}"]
    volumes:
      - dcp-config:/root/.dcp
    deploy:
      restart_policy:
        condition: on-failure
        max_attempts: 1

volumes:
  dcp-config:
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dcp-pairing-grant
type: Opaque
stringData:
  grant: "dcp_pair_v1_..."
---
apiVersion: batch/v1
kind: Job
metadata:
  name: dcp-agent-pair
spec:
  template:
    spec:
      containers:
      - name: dcp-agent
        image: dcprotocol/agent
        command: ["dcp-agent", "pair"]
        args: ["$(DCP_PAIR_GRANT)"]
        env:
        - name: DCP_PAIR_GRANT
          valueFrom:
            secretKeyRef:
              name: dcp-pairing-grant
              key: grant
        volumeMounts:
        - name: dcp-config
          mountPath: /root/.dcp
      volumes:
      - name: dcp-config
        persistentVolumeClaim:
          claimName: dcp-config
      restartPolicy: Never
```

## Programmatic Usage

```typescript
import { fetchSecret, fetchSecrets } from '@dcprotocol/agent/secrets';

// Single secret
const apiKey = await fetchSecret('credentials.api.openai');

// Multiple secrets
const secrets = await fetchSecrets([
  'credentials.api.openai',
  'credentials.api.stripe',
]);
```

## Agent Modes

| Mode | Command | Description |
|------|---------|-------------|
| `proxy` | `dcp-agent run --mode proxy` | Local HTTP proxy at 127.0.0.1:8420 |
| `mcp` | `dcp-agent run --mode mcp` | stdio MCP server for Claude Desktop, Cursor |
| `http-mcp` | `dcp-agent run --mode http-mcp` | Streamable HTTP MCP for VPS agents |

### MCP Server Configuration

Add to your MCP client config (Claude Desktop, Cursor, VS Code):

```json
{
  "mcpServers": {
    "dcp": {
      "command": "dcp-agent",
      "args": ["run", "--mode", "mcp"]
    }
  }
}
```

### MCP Tools Available

| Tool | Purpose |
|------|---------|
| `vault_get_address` | Get public wallet address |
| `vault_budget_check` | Check budget limits |
| `vault_read` | Read data or credentials |
| `vault_sign_tx` | Sign a transaction |
| `vault_sign_message` | Sign a message |
| `vault_sign_typed_data` | Sign EIP-712 typed data |
| `vault_write` | Write data to vault |

### Daemon Mode

Run in background (survives SSH disconnect):

```bash
dcp-agent run --mode proxy --daemon
```

- PID file: `~/.dcp/agents/{agent_id}.pid`
- Log file: `~/.dcp/agents/{agent_id}.log` (mode 0600)

### Systemd Service

Install as a systemd service for production VPS:

```bash
dcp-agent install-service
systemctl start dcp-agent
systemctl enable dcp-agent
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DCP_AGENT_PORT` | Proxy server port | `8420` |
| `DCP_AGENT_DEBUG` | Enable debug logging | `false` |

## Configuration Storage

Agent configurations are stored at:
- **Directory**: `~/.dcp/agents/`
- **Permissions**: `0700` (directory), `0600` (files)
- **Format**: JSON with vault connection details

Example config:
```json
{
  "agent_id": "agent_abc123",
  "agent_name": "my-trading-bot",
  "vault_id": "vault_xyz789",
  "mode": "gateway",
  "vault_hpke_public_key": "...",
  "vault_signing_public_key": "...",
  "permission_scopes": ["sign:solana", "read:credentials.api.*"],
  "budget": {
    "daily": 10,
    "currency": "USDC",
    "auto_approve_under": 1
  },
  "tier": "pro",
  "relay_url": "wss://relay.dcp.1ly.store",
  "gateway_url": "https://gateway.dcp.1ly.store",
  "paired_at": "2025-01-15T10:30:00Z",
  "grant_expires_at": "2025-02-15T10:30:00Z"
}
```

## Security

- Pairing grants are Ed25519-signed and time-limited
- Config files are created with restrictive permissions (`0600`)
- Secrets are fetched over encrypted relay connections (HPKE)
- Agent can only access scopes granted during pairing

## License

Apache-2.0
