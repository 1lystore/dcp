/**
 * DCP Telegram Service Types
 *
 * Type definitions for the Telegram notification service.
 * Re-exports core types and defines service-specific types.
 */

// Re-export core Telegram types
export type {
  TelegramConfig,
  CreateTelegramConfigInput,
  TelegramPairingCode,
  TelegramNotificationLog,
  TelegramConsentPayload,
  TelegramWebhookPayload,
  TelegramRequestCategory,
} from '@dcprotocol/core';

/**
 * Telegram bot configuration
 */
export interface TelegramBotConfig {
  /** Bot token from BotFather */
  botToken: string;

  /** Webhook URL for receiving Telegram updates (optional, uses polling if not set) */
  webhookUrl?: string;

  /** Port for webhook server (default: 8422) */
  webhookPort?: number;

  /** Host for webhook server (default: 127.0.0.1) */
  webhookHost?: string;

  /** Enable debug logging */
  debug?: boolean;
}

/**
 * Telegram service configuration
 */
export interface TelegramServiceConfig {
  /** Port for the webhook server */
  port: number;

  /** Host to bind to */
  host: string;

  /** URL of the dcp-server for vault operations */
  serverUrl: string;

  /** Vault signing public key for webhook verification */
  vaultSigningPublicKey?: string;

  /** Enable debug logging */
  debug: boolean;
}

/**
 * Bot command handler result
 */
export interface CommandResult {
  /** Whether the command was handled successfully */
  success: boolean;

  /** Response message to send to user */
  message: string;

  /** Optional parse mode for response */
  parseMode?: 'Markdown' | 'HTML';
}

/**
 * Notification send result
 */
export interface NotificationResult {
  /** Whether the notification was sent successfully */
  success: boolean;

  /** Telegram message ID if sent */
  messageId?: number;

  /** Error message if failed */
  error?: string;
}

export type ApprovalAction = 'approve' | 'deny';

export interface ApprovalCommand {
  id: string;
  vault_id: string;
  chat_id: string;
  consent_id: string;
  action: ApprovalAction;
  created_at: string;
  /** When command expires (vault must reject after this) */
  expires_at: string;
  /** Service signature proving this came from Telegram service */
  service_signature: string;
  /** Pairing ID linking to vault-chat relationship */
  pairing_id: string;
  processed_at: string | null;
  result: string | null;
}

/**
 * Rate limiter state for a chat
 */
export interface RateLimitState {
  /** Chat ID being tracked */
  chatId: string;

  /** Number of notifications in current window */
  count: number;

  /** Window start timestamp */
  windowStart: number;

  /** Whether currently rate limited */
  isLimited: boolean;
}

/**
 * Telegram error codes
 */
export type TelegramErrorCode =
  | 'BOT_NOT_INITIALIZED'
  | 'INVALID_CHAT_ID'
  | 'RATE_LIMITED'
  | 'SEND_FAILED'
  | 'WEBHOOK_VERIFICATION_FAILED'
  | 'INVALID_PAIRING_CODE'
  | 'PAIRING_EXPIRED'
  | 'ALREADY_PAIRED'
  | 'NOT_PAIRED'
  | 'INTERNAL_ERROR'
  | 'MISSING_SIGNATURE'
  | 'INVALID_SIGNATURE'
  | 'UNKNOWN_VAULT_KEY'
  | 'STALE_TIMESTAMP'
  | 'REPLAY_DETECTED'
  | 'MISSING_NONCE';

/**
 * Telegram service error
 */
export class TelegramError extends Error {
  constructor(
    public code: TelegramErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'TelegramError';
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
      },
    };
  }
}

/**
 * Supported bot commands
 */
export const BOT_COMMANDS = [
  { command: 'start', description: 'Begin pairing with DCP Vault' },
  { command: 'pair', description: 'Complete pairing with 6-digit code' },
  { command: 'approve', description: 'Approve a vault request' },
  { command: 'deny', description: 'Deny a vault request' },
  { command: 'status', description: 'Check connection status' },
  { command: 'mute', description: 'Mute notifications (1h, 6h, 24h)' },
  { command: 'unmute', description: 'Resume notifications' },
  { command: 'unlink', description: 'Disconnect from vault' },
  { command: 'help', description: 'Show available commands' },
] as const;

/**
 * Mute duration options
 */
export const MUTE_DURATIONS: Record<string, number> = {
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
};

/**
 * Default service configuration
 */
export const DEFAULT_SERVICE_CONFIG: TelegramServiceConfig = {
  port: 8423, // Note: 8421=vault, 8422=relay, 8423=telegram
  host: '127.0.0.1',
  serverUrl: 'http://127.0.0.1:8421',
  debug: false,
};

/**
 * Vault-to-Telegram pairing (stored in cloud service)
 * This is the core of Option B from PRD Section 15
 */
export interface VaultPairing {
  /** Vault ID (from desktop) */
  vault_id: string;

  /** Telegram chat ID */
  chat_id: string;

  /** When pairing was completed */
  paired_at: string;

  /** Whether notifications are enabled */
  enabled: boolean;

  /** Muted until timestamp (null if not muted) */
  muted_until: string | null;

  /** Notifications sent count (for stats) */
  notification_count: number;

  /** Last notification timestamp */
  last_notification_at: string | null;
}

/**
 * Pending pairing code (waiting for user to send to bot)
 */
export interface PendingPairing {
  /** 6-digit pairing code */
  code: string;

  /** Vault ID this code is for */
  vault_id: string;

  /** When the code expires */
  expires_at: string;

  /** When the code was created */
  created_at: string;
}
