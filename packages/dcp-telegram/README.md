# @dcprotocol/telegram

Telegram notification service for DCP Vault. Enables users to receive consent notifications and approve requests directly via Telegram.

## Architecture

This service implements a **shared bot model** - one Telegram bot serves all DCP users. Users pair their vault with the bot using a 6-digit code.

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│ DCP Vault   │────▶│ @dcprotocol/     │────▶│ Telegram     │
│ (Desktop)   │     │ telegram         │     │ Bot API      │
└─────────────┘     └──────────────────┘     └──────────────┘
       │                    │                       │
       │  Webhook POST      │    Send message       │
       └────────────────────▼───────────────────────▼
                    User's Telegram chat
```

## Installation

```bash
npm install @dcprotocol/telegram
```

## Quick Start

### 1. Create a Telegram Bot

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token

### 2. Configure Environment

```bash
# Required
export TELEGRAM_BOT_TOKEN="your-bot-token"

# Optional
export DCP_TELEGRAM_PORT=8422
export DCP_TELEGRAM_SECRET="your-webhook-secret"
```

### 3. Run the Service

```bash
# Start the service
npx -y @dcprotocol/telegram

# Or with Docker
docker run -e TELEGRAM_BOT_TOKEN=... dcprotocol/telegram
```

## Bot Commands

Users interact with the bot using these commands:

| Command | Description |
|---------|-------------|
| `/start` | Welcome message and instructions |
| `/pair` | Initiate pairing with a vault |
| `/status` | Check connection status |
| `/help` | Show available commands |
| `/mute` | Mute notifications |
| `/unmute` | Unmute notifications |
| `/unlink` | Unlink from vault |

## Pairing Flow

1. User opens DCP Desktop and navigates to Settings > Telegram
2. Desktop requests a pairing code from the Telegram service
3. User sends `/pair` to the bot
4. Bot asks for the 6-digit code
5. User enters the code
6. Vault and Telegram chat are linked

## Webhook API

The service exposes HTTP endpoints for vault integration.

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/stats` | GET | Service statistics |
| `/api/pair/start` | POST | Request pairing code |
| `/api/pair/status/:vaultId` | GET | Check pairing status |
| `/webhook/consent` | POST | Send consent notification |

### Request Pairing Code

```bash
curl -X POST http://localhost:8422/api/pair/start \
  -H "Content-Type: application/json" \
  -d '{"vault_id":"vault_abc123"}'
```

Response:
```json
{
  "pairing_code": "123456",
  "expires_at": "2025-03-05T12:05:00Z"
}
```

### Send Consent Notification

```bash
curl -X POST http://localhost:8422/webhook/consent \
  -H "Content-Type: application/json" \
  -H "X-DCP-Signature: <ed25519-signature>" \
  -d '{
    "vault_id": "vault_abc123",
    "event": "consent_created",
    "data": {
      "consent_id": "consent_xyz",
      "agent_name": "my-bot",
      "action": "sign_message",
      "scope": "sign:solana"
    },
    "timestamp": "2025-03-05T12:00:00Z",
    "nonce": "unique-nonce"
  }'
```

## Notification Types

### Consent Request

Sent when an agent requests user approval:

```
🔔 Consent Request

Agent: my-trading-bot
Action: Transaction Signing

[Approve] [Deny]
```

### Budget Alert

Sent when spending approaches limits:

```
⚠️ Budget Alert

Agent: my-trading-bot
Daily spent: 8.5 SOL of 10 SOL limit
```

### Pairing Success

Sent when pairing completes:

```
✅ Vault Connected

Your DCP Vault is now linked to this Telegram chat.
You'll receive consent notifications here.
```

## Privacy & Security

- **Privacy-Safe Categories**: Notifications show high-level categories only, not specific amounts or recipients
- **Signed Webhooks**: All webhook requests are signed with Ed25519
- **Nonce Replay Protection**: Prevents duplicate notifications
- **Rate Limiting**: 30 notifications per chat per hour by default

### Notification Categories

| Internal Action | Display Category |
|-----------------|------------------|
| `sign`, `sign_tx` | Transaction Signing |
| `sign_message` | Message Signing |
| `read` | Data Read |
| `write` | Data Write |
| `credentials` | Credential Access |
| Other | Other |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | Required |
| `DCP_TELEGRAM_PORT` | Webhook server port | `8422` |
| `DCP_TELEGRAM_SECRET` | Webhook verification secret | Auto-generated |
| `DCP_TELEGRAM_RATE_LIMIT` | Max notifications per hour | `30` |

### Database

The service uses SQLite for persistence:

- **Location**: `./data/telegram.db`
- **Tables**: pairings, approvals, rate_limits, nonces

## Docker Deployment

### Docker Run

```bash
docker run -d \
  --name dcp-telegram \
  -e TELEGRAM_BOT_TOKEN=your-token \
  -p 8422:8422 \
  -v telegram-data:/app/data \
  dcprotocol/telegram
```

### Docker Compose

```yaml
version: '3.8'
services:
  telegram:
    image: dcprotocol/telegram
    ports:
      - "8422:8422"
    environment:
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
      - DCP_TELEGRAM_SECRET=${DCP_TELEGRAM_SECRET}
    volumes:
      - telegram-data:/app/data
    restart: unless-stopped

volumes:
  telegram-data:
```

## Programmatic Usage

```typescript
import { DcpTelegramBot } from '@dcprotocol/telegram';

const bot = new DcpTelegramBot({
  token: process.env.TELEGRAM_BOT_TOKEN!,
  webhookPort: 8422,
});

await bot.start();
```

## Desktop Integration

The DCP Desktop app integrates with the Telegram service:

1. Navigate to Settings > Telegram
2. Click "Connect Telegram"
3. A pairing code is displayed
4. Open the DCP bot in Telegram
5. Send `/pair` and enter the code
6. Connection is established

Once connected, consent requests will be sent to Telegram with Approve/Deny buttons.

## Related Packages

- `@dcprotocol/vault` - Vault server that sends notifications
- `@dcprotocol/core` - Shared types and crypto
- `@dcprotocol/desktop` - Desktop app with Telegram settings

## License

MIT
