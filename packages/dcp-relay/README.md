# @dcprotocol/relay

Encrypted message relay for DCP - enables cloud MCP clients to securely communicate with local vaults.

This is the same relay software used for the default public relay at `wss://relay.dcp.1ly.store`. Running your own relay is fully supported.

## Overview

The DCP Relay is a message bus that routes encrypted requests between cloud MCP clients (like Claude.ai, ChatGPT) and local DCP vaults. The relay never sees plaintext data - it only handles routing of opaque encrypted payloads.

## Features

- **WebSocket Primary**: Real-time bidirectional communication
- **HTTP Long-Poll Fallback**: For environments where WebSocket isn't available
- **Heartbeat**: 30-second keep-alive interval
- **Message TTL**: Messages expire after 5 minutes
- **Idempotency**: Duplicate requests handled via `request_id`
- **Zero Knowledge**: Relay sees only routing metadata, never plaintext
- **Rate Limiting**: Configurable per-vault rate limits (default: 60 req/min)
- **Prometheus Metrics**: `/metrics` endpoint for monitoring

## Installation

```bash
npm install @dcprotocol/relay
```

## Quick Start

### As a Server

```bash
# Start relay on default port (8421)
npx -y @dcprotocol/relay

# With options
npx -y @dcprotocol/relay --port 9000 --debug
```

If you self-host, point Desktop, `@dcprotocol/client`, `dcp connect`, or `@dcprotocol/proxy` at your own relay URL instead of the public one.

### As a Library

```typescript
import { RelayServer } from '@dcprotocol/relay';

const relay = new RelayServer({
  port: 8421,
  host: '0.0.0.0',
  debug: true,
  enableLongPoll: true,
});

await relay.start();
console.log('Relay running on port 8421');

// Graceful shutdown
process.on('SIGINT', () => relay.stop());
```

## Protocol

### Relay Envelope

All messages follow this envelope format:

```json
{
  "version": "1",
  "vault_id": "vault_abc123",
  "request_id": "req_xyz789",
  "action_type": "sign",
  "encrypted_payload": "<base64-encoded-hpke-ciphertext>",
  "expires_at": "2026-03-05T12:00:00Z"
}
```

### Action Types

- `sign` - Signing operations (tx, message, x402, typed data)
- `read` - Read operations
- `write` - Write operations
- `budget` - Budget checks

### WebSocket Messages

```typescript
// Register vault (authenticated)
{
  type: 'register',
  payload: {
    vault_id: string,
    public_key: string,
    signing_public_key: string,
    timestamp: string,
    nonce: string,
    signature: string,
    pairing_token?: string,
  }
}

// Heartbeat
{ type: 'heartbeat', payload: { vault_id: string } }

// Request (relay -> vault)
{ type: 'request', payload: RelayEnvelope }

// Response (vault -> relay)
{ type: 'response', payload: RelayResponseEnvelope }
```

### HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/stats` | GET | Relay statistics |
| `/metrics` | GET | Detailed metrics (JSON or Prometheus format) |
| `/relay/request` | POST | Submit request to vault (requires pairing token when enabled) |
| `/relay/response/:requestId` | GET | Poll for response |
| `/relay/poll` | POST | Long-poll for vault (fallback) |
| `/relay/respond` | POST | Submit response (fallback) |

### WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/ws` | Vault connections (authenticated) |
| `/ws-client` | Client/agent connections |

## Security

- **End-to-End Encryption**: All payloads are HPKE-encrypted (X25519 + ChaCha20-Poly1305)
- **No Plaintext**: Relay never sees method names, amounts, or business logic
- **Relay Authentication**: Vault registration is signed (Ed25519) and pairing tokens are validated when required
- **Transport-Level Errors Only**: `RELAY_UNAVAILABLE`, `RELAY_TIMEOUT`, `RELAY_UNAUTHORIZED`

### Request Authentication
When pairing tokens are enabled, clients must include one of:
- `Authorization: Bearer <pairing_token>`
- `X-DCP-PAIRING-TOKEN: <pairing_token>`

## Configuration

```typescript
interface RelayConfig {
  port: number;              // Default: 8421
  host: string;              // Default: '0.0.0.0'
  enableLongPoll: boolean;   // Default: true
  heartbeatIntervalMs: number; // Default: 30000
  messageTtlMs: number;      // Default: 300000 (5 minutes)
  maxPendingMessages: number; // Default: 100 per vault
  debug: boolean;            // Default: false
  rateLimitPerMinute: number; // Default: 60 requests per vault per minute
  rateLimitWindowMs: number;  // Default: 60000 (1 minute)
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DCP_RELAY_PORT` | Port to listen on | 8421 |
| `DCP_RELAY_HOST` | Host to bind to | 0.0.0.0 |
| `DCP_RELAY_DEBUG` | Enable debug logging | false |
| `DCP_RELAY_RATE_LIMIT` | Max requests per vault per minute | 60 |

## Error Codes

| Code | Description |
|------|-------------|
| `RELAY_UNAVAILABLE` | Relay server not available |
| `RELAY_TIMEOUT` | Request timed out |
| `RELAY_UNAUTHORIZED` | Not authorized |
| `RELAY_INVALID_ENVELOPE` | Invalid message format |
| `RELAY_VAULT_NOT_CONNECTED` | Target vault not connected |
| `RELAY_DUPLICATE_REQUEST` | Duplicate request_id |
| `RELAY_MESSAGE_EXPIRED` | Message TTL exceeded |
| `RELAY_RATE_LIMITED` | Too many requests (429) |

## Rate Limiting

The relay enforces per-vault rate limits to prevent abuse. When a vault exceeds its limit, subsequent requests receive a 429 response with:

```json
{
  "error": {
    "code": "RELAY_RATE_LIMITED",
    "message": "Rate limit exceeded for vault vault_abc123. Try again in 45 seconds.",
    "details": {
      "vault_id": "vault_abc123",
      "limit": 60,
      "window_ms": 60000,
      "retry_after_ms": 45000
    }
  }
}
```

Rate limit headers are included in all responses:
- `X-RateLimit-Limit`: Max requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Seconds until reset (on 429)
- `Retry-After`: Seconds to wait before retry (on 429)

## Monitoring

### Metrics Endpoint

The `/metrics` endpoint provides detailed relay statistics:

```bash
# JSON format (default)
curl http://localhost:8421/metrics

# Prometheus format
curl http://localhost:8421/metrics?format=prometheus
```

### Prometheus Metrics

```
dcp_relay_messages_total
dcp_relay_messages_pending
dcp_relay_messages_delivered
dcp_relay_vaults_connected
dcp_relay_vaults_tracked
dcp_relay_rate_limit_max
dcp_relay_ws_clients
```

## Deployment

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
RUN npm install -g @dcprotocol/relay
EXPOSE 8421
CMD ["dcp-relay", "--host", "0.0.0.0"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  relay:
    image: node:20-alpine
    working_dir: /app
    command: npx -y @dcprotocol/relay
    ports:
      - "8421:8421"
    environment:
      - DCP_RELAY_PORT=8421
      - DCP_RELAY_RATE_LIMIT=60
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8421/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### Systemd Service

```ini
[Unit]
Description=DCP Relay Server
After=network.target

[Service]
Type=simple
User=dcp
ExecStart=/usr/bin/npx -y @dcprotocol/relay --port 8421
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=DCP_RELAY_RATE_LIMIT=60

[Install]
WantedBy=multi-user.target
```

### Production Checklist

1. **TLS/SSL**: Run behind a reverse proxy (nginx, Caddy) with TLS termination
2. **Rate Limiting**: Adjust `DCP_RELAY_RATE_LIMIT` based on expected traffic
3. **Monitoring**: Scrape `/metrics?format=prometheus` with Prometheus
4. **Health Checks**: Use `/health` endpoint for load balancer health checks
5. **Logging**: Enable `--debug` for troubleshooting, disable in production

### Nginx Configuration

```nginx
upstream dcp_relay {
    server 127.0.0.1:8421;
}

server {
    listen 443 ssl http2;
    server_name relay.dcp.1ly.store;

    ssl_certificate /etc/letsencrypt/live/relay.dcp.1ly.store/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.dcp.1ly.store/privkey.pem;

    location / {
        proxy_pass http://dcp_relay;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

## License

Apache-2.0
