/**
 * DCP Telegram Cloud Service (Option B from PRD Section 15)
 *
 * Cloud service that handles Telegram notifications for ALL users:
 * - ONE shared bot token (from environment)
 * - Stores vault_id ↔ chat_id pairings in SQLite
 * - Receives webhooks from desktop apps
 * - Sends notifications to users
 *
 * Usage:
 *   DCP_TELEGRAM_BOT_TOKEN=xxx dcp-telegram [options]
 *
 * Options:
 *   --port          Webhook server port (default: 8422)
 *   --host          Webhook server host (default: 0.0.0.0 for cloud)
 *   --data-dir      Data directory for SQLite (default: ./data)
 *   --debug         Enable debug logging
 *   --help          Show this help message
 */

// Re-export types and classes
export * from './types.js';
export { DcpTelegramBot } from './bot.js';
export { WebhookServer, validateTelegramUpdate } from './webhook.js';
export { TelegramStore, PairingStore, ApprovalCommandStore, RateLimiter, DeduplicationStore, NonceStore } from './store.js';
export {
  formatConsentNotification,
  formatTestNotification,
  formatPairingSuccess,
  formatHelpMessage,
  formatStatusMessage,
  categorizeRequest,
  sanitizeAgentName,
  escapeMarkdown,
} from './notification.js';

// Load .env file if present
import dotenv from 'dotenv';
dotenv.config();

import { DcpTelegramBot } from './bot.js';
import { WebhookServer } from './webhook.js';
import { TelegramStore } from './store.js';

/**
 * Parse command line arguments
 */
function parseArgs(args: string[]): {
  botToken?: string;
  port: number;
  host: string;
  dataDir: string;
  debug: boolean;
  help: boolean;
} {
  const config = {
    botToken: undefined as string | undefined,
    port: 8422,
    host: '0.0.0.0', // Cloud default: listen on all interfaces
    dataDir: './data',
    debug: false,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    switch (arg) {
      case '--bot-token':
        config.botToken = nextArg;
        i++;
        break;
      case '--port':
        config.port = parseInt(nextArg, 10) || 8422;
        i++;
        break;
      case '--host':
        config.host = nextArg || '0.0.0.0';
        i++;
        break;
      case '--data-dir':
        config.dataDir = nextArg || './data';
        i++;
        break;
      case '--debug':
        config.debug = true;
        break;
      case '--help':
      case '-h':
        config.help = true;
        break;
    }
  }

  // Environment variables (preferred for cloud deployment)
  config.botToken = config.botToken || process.env.DCP_TELEGRAM_BOT_TOKEN;
  config.port = parseInt(process.env.DCP_TELEGRAM_PORT || '', 10) || config.port;
  config.host = process.env.DCP_TELEGRAM_HOST || config.host;
  config.dataDir = process.env.DCP_TELEGRAM_DATA_DIR || config.dataDir;
  config.debug = config.debug || process.env.DCP_TELEGRAM_DEBUG === 'true';

  return config;
}

/**
 * Show help message
 */
function showHelp(): void {
  console.log(`
DCP Telegram Cloud Service v0.2.0

Cloud notification service for DCP Vault - serves ALL users with ONE shared bot.

USAGE:
  DCP_TELEGRAM_BOT_TOKEN=xxx dcp-telegram [options]

OPTIONS:
  --port <port>          Webhook server port (default: 8422)
  --host <host>          Webhook server host (default: 0.0.0.0)
  --data-dir <dir>       Data directory for SQLite (default: ./data)
  --debug                Enable debug logging
  --help, -h             Show this help message

ENVIRONMENT VARIABLES:
  DCP_TELEGRAM_BOT_TOKEN    Bot token from BotFather (REQUIRED)
  DCP_TELEGRAM_PORT         Server port
  DCP_TELEGRAM_HOST         Server host
  DCP_TELEGRAM_DATA_DIR     Data directory
  DCP_TELEGRAM_DEBUG        Enable debug (true/false)

API ENDPOINTS:
  POST /api/pair/start           Desktop calls to get pairing code
  GET  /api/pair/status/:vaultId Desktop polls to check if paired
  POST /webhook/consent          Desktop sends consent notifications
  GET  /health                   Health check
  GET  /stats                    Service statistics

EXAMPLE:
  # Cloud deployment
  DCP_TELEGRAM_BOT_TOKEN="123456:ABC-DEF..." dcp-telegram --port 8422

  # Local testing
  dcp-telegram --bot-token "123456:ABC-DEF..." --debug

For more information, visit: https://dcp.1ly.store
`);
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = parseArgs(args);

  if (config.help) {
    showHelp();
    process.exit(0);
  }

  if (!config.botToken) {
    console.error('Error: Bot token is required');
    console.error('Set DCP_TELEGRAM_BOT_TOKEN environment variable');
    console.error('Run with --help for more information');
    process.exit(1);
  }

  console.log('[INIT] Starting DCP Telegram Cloud Service...');
  console.log(`[INIT] Data directory: ${config.dataDir}`);

  // Initialize shared store (SQLite for pairings)
  const store = new TelegramStore(config.dataDir);
  console.log('[INIT] Store initialized');

  // Initialize bot with shared store
  const bot = new DcpTelegramBot(
    {
      botToken: config.botToken,
      debug: config.debug,
    },
    store
  );

  // Initialize webhook server with shared store
  const webhookServer = new WebhookServer(bot, store, {
    port: config.port,
    host: config.host,
    serverUrl: '', // Not needed for cloud service
    debug: config.debug,
  });

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`\n[SHUTDOWN] Received ${signal}, shutting down...`);
    await webhookServer.stop();
    await bot.stop();
    store.close();
    console.log('[SHUTDOWN] Cleanup complete');
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Start services
  try {
    await bot.start();
    await webhookServer.start();

    const stats = store.getStats();
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║         DCP Telegram Cloud Service - RUNNING                 ║
╠══════════════════════════════════════════════════════════════╣
║  Bot:     Polling for messages                               ║
║  Server:  http://${config.host}:${config.port.toString().padEnd(33)}║
║  Data:    ${config.dataDir.padEnd(48)}║
║  Paired:  ${stats.pairings.totalPairings.toString().padEnd(48)}║
╠══════════════════════════════════════════════════════════════╣
║  Endpoints:                                                  ║
║    POST /api/pair/start         - Get pairing code           ║
║    GET  /api/pair/status/:id    - Check pairing status       ║
║    POST /webhook/consent        - Send notification          ║
║    GET  /health                 - Health check               ║
║    GET  /stats                  - Service stats              ║
╠══════════════════════════════════════════════════════════════╣
║  Press Ctrl+C to stop                                        ║
╚══════════════════════════════════════════════════════════════╝
`);
  } catch (err) {
    console.error('[ERROR] Failed to start service:', err);
    process.exit(1);
  }
}

// Run if this is the main module
const isMainModule =
  process.argv[1]?.endsWith('index.js') ||
  process.argv[1]?.endsWith('index.mjs') ||
  process.argv[1]?.endsWith('index.ts');

if (isMainModule) {
  main().catch((err) => {
    console.error('[FATAL]', err);
    process.exit(1);
  });
}
