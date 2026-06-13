#!/usr/bin/env node
/**
 * DCP Relay - Entry Point
 *
 * Encrypted message bus between cloud MCP clients and local vaults.
 * Can be run as a standalone server or imported as a library.
 *
 * Usage:
 *   npx @dcprotocol/relay          # Start relay server on default port
 *   npx @dcprotocol/relay --port 8422 --debug
 *
 * From protocol spec:
 * - WebSocket primary, HTTP long-poll fallback
 * - Message TTL: 5 minutes
 * - Heartbeat: 30 seconds
 * - Idempotency by request_id
 */

// ============================================================================
// Exports
// ============================================================================

export { RelayServer } from './relay.js';
export { MessageStore, ConnectionStore, RateLimiter, MobilePairingStore, PushTokenStore } from './store.js';
export {
  authenticateRegistration,
  verifyRegistrationSignature,
  tokenStore,
  closeAuth,
  type AuthConfig,
} from './auth.js';
export {
  // Types
  type RelayEnvelope,
  type RelayResponseEnvelope,
  type RelayConfig,
  type ActionType,
  type WsMessage,
  type WsMessageType,
  type RegisterPayload,
  type HeartbeatPayload,
  type LongPollRequest,
  type LongPollResponse,
  type StoredMessage,
  type VaultConnection,
  type PushTokenRegistration,
  type RelayErrorCode,
  type PairingClaim,
  type StoredPairingClaim,
  type PairingClaimResponse,
  type PairingApprovalStatus,
  type MobileAgentClient,
  type MobileAgentEnvironment,
  type MobileDcpScope,
  type MobilePairingBudget,
  type MobilePairingInvite,
  type MobilePairingApprovalRequest,
  type MobilePairingRecord,
  type MobilePairingStatus,

  // Constants
  RELAY_VERSION,
  HEARTBEAT_INTERVAL_MS,
  MESSAGE_TTL_MS,
  RECONNECT_MIN_MS,
  RECONNECT_MAX_MS,
  DEFAULT_RELAY_CONFIG,
  MAX_CLOCK_SKEW_MS,
  MIN_NONCE_SIZE,

  // Error class
  RelayError,
} from './types.js';

// ============================================================================
// CLI Entry Point
// ============================================================================

import { RelayServer } from './relay.js';
import { DEFAULT_RELAY_CONFIG } from './types.js';
import path from 'node:path';

interface RelayCliOptions {
  port: number;
  host: string;
  debug: boolean;
  rateLimitPerMinute: number;
  expoPushUrl: string;
  publicUrl: string;
}

function parseArgs(): RelayCliOptions {
  const args = process.argv.slice(2);

  // Defaults from config or env
  let port = parseInt(process.env.DCP_RELAY_PORT || '', 10) || DEFAULT_RELAY_CONFIG.port;
  let host = process.env.DCP_RELAY_HOST || DEFAULT_RELAY_CONFIG.host;
  let debug = process.env.DCP_RELAY_DEBUG === 'true' || false;
  let rateLimitPerMinute = parseInt(process.env.DCP_RELAY_RATE_LIMIT || '', 10) || DEFAULT_RELAY_CONFIG.rateLimitPerMinute;
  let expoPushUrl = process.env.DCP_EXPO_PUSH_URL ?? DEFAULT_RELAY_CONFIG.expoPushUrl;
  // Public base URL (OAuth issuer / MCP resource origin) — set behind a tunnel/proxy
  // so discovery metadata + token audience use the public https host, not localhost.
  const publicUrl = process.env.DCP_RELAY_PUBLIC_URL ?? DEFAULT_RELAY_CONFIG.publicUrl;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--port' || arg === '-p') {
      port = parseInt(args[++i], 10) || port;
    } else if (arg === '--host' || arg === '-h') {
      host = args[++i] || host;
    } else if (arg === '--debug' || arg === '-d') {
      debug = true;
    } else if (arg === '--rate-limit' || arg === '-r') {
      rateLimitPerMinute = parseInt(args[++i], 10) || rateLimitPerMinute;
    } else if (arg === '--no-push') {
      expoPushUrl = '';
    } else if (arg === '--help') {
      console.log(`
DCP Relay - Encrypted message bus for cloud MCP clients

Usage:
  dcp-relay [options]

Options:
  -p, --port <port>         Port to listen on (default: 8422)
  -h, --host <host>         Host to bind to (default: 0.0.0.0)
  -r, --rate-limit <n>      Max requests per vault per minute (default: 60)
  -d, --debug               Enable debug logging
      --help                Show this help message

Environment Variables:
  DCP_RELAY_PORT            Port to listen on
  DCP_RELAY_HOST            Host to bind to
  DCP_RELAY_DEBUG           Enable debug logging (true/false)
  DCP_RELAY_RATE_LIMIT      Max requests per vault per minute
  DCP_EXPO_PUSH_URL         Expo push API endpoint; set empty with --no-push to disable

Examples:
  dcp-relay                         # Start on default port
  dcp-relay --port 9000             # Start on port 9000
  dcp-relay --rate-limit 120        # 120 requests/min per vault
  dcp-relay --debug                 # Start with debug logging
`);
      process.exit(0);
    }
  }

  return { port, host, debug, rateLimitPerMinute, expoPushUrl, publicUrl };
}

async function main(): Promise<void> {
  const { port, host, debug, rateLimitPerMinute, expoPushUrl, publicUrl } = parseArgs();

  const relay = new RelayServer({
    port,
    host,
    debug,
    enableLongPoll: true,
    rateLimitPerMinute,
    expoPushUrl,
    publicUrl,
  });

  // Handle shutdown
  const shutdown = async () => {
    console.log('\nShutting down relay...');
    await relay.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  try {
    await relay.start();
    console.log(`DCP Relay running on ${host}:${port}`);
    console.log('Press Ctrl+C to stop');
  } catch (err) {
    console.error('Failed to start relay:', err);
    process.exit(1);
  }
}

// Run only when this file is the process entry point — NEVER when imported or
// bundled into another package (e.g. the desktop's vault bundle). We deliberately
// do NOT use `require.main === module`: esbuild evaluates that to `true` inside a
// bundle, which would make the relay server autostart and fight for port 8422.
// Instead, key off the actual entry path: a relay binary name, or a path that runs
// the relay's own dist/src directly.
const argv1 = process.argv[1] || '';
const argvEntry = argv1 ? path.basename(argv1) : '';
const isDirectCliInvocation =
  argvEntry === 'dcp-relay' ||
  argvEntry === 'dcp-relay.js' ||
  argvEntry === 'dcp-relay.mjs' ||
  /[\\/]dcp-relay[\\/](dist|src)[\\/]index\.(js|mjs|ts)$/.test(argv1) ||
  /[\\/]@dcprotocol[\\/]relay[\\/]/.test(argv1);

if (isDirectCliInvocation) {
  main().catch(console.error);
}
