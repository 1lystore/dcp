# @dcprotocol/telegram

Telegram approvals for DCP.

Use this service when a vault owner wants approval requests delivered to Telegram with approve and deny buttons.

## Install

```bash
npm install -g @dcprotocol/telegram
```

## Run

Create a bot with BotFather, then start the service with the bot token:

```bash
DCP_TELEGRAM_BOT_TOKEN="123456:..." dcp-telegram --host 127.0.0.1 --port 8423
```

Health check:

```bash
curl -sS http://127.0.0.1:8423/health
```

## Pair Telegram

1. Open Telegram settings in DCP Desktop.
2. Start pairing.
3. Send the pairing code to the bot:

```text
/pair 123456
```

4. Send a test notification from Desktop.

## Approval Message

Keep approval messages short:

```text
🔐 Approval Needed

Claude Desktop wants to send 0.02 SOL on Solana.

⏱️ Reply within 4m 58s
```

Telegram is an approval surface. The vault still owns policy, signing, and audit history.

## Useful Endpoints

```text
GET  /health
GET  /stats
POST /api/pair/start
GET  /api/pair/status/:vaultId
POST /webhook/consent
```
