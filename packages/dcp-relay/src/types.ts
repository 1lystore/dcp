/**
 * Types for DCP Relay
 * Encrypted message bus between cloud MCP clients and local vaults
 *
 * From PRD Phase 1 Section 4.1:
 * - Relay sees only encrypted payloads and minimal routing metadata
 * - No method names, amounts, recipients, or business logic visible to relay
 */

// ============================================================================
// Constants (from PRD Section 4.1, 7.1)
// ============================================================================

export const RELAY_VERSION = '1';
export const HEARTBEAT_INTERVAL_MS = 30_000; // 30 seconds
export const MESSAGE_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const RECONNECT_MIN_MS = 1_000; // 1 second
export const RECONNECT_MAX_MS = 60_000; // 60 seconds

// ============================================================================
// Action Types (from PRD Section 7)
// ============================================================================

/**
 * Generic action types - relay does not interpret method names
 * All specific methods (vault_sign_x402, etc.) live inside encrypted_payload
 */
export type ActionType = 'sign' | 'read' | 'write' | 'budget';

// ============================================================================
// Relay Envelope (from PRD Section 7.1)
// ============================================================================

/**
 * Relay envelope - the only structure visible to relay
 * All sensitive data is inside encrypted_payload (opaque to relay)
 */
export interface RelayEnvelope {
  /** Protocol version for forward compatibility */
  version: string;
  /** Vault identifier for routing */
  vault_id: string;
  /** Unique request identifier for idempotency */
  request_id: string;
  /** Generic action type (sign, read, write, budget) */
  action_type: ActionType;
  /** Encrypted payload - opaque to relay, contains full DCP request/response */
  encrypted_payload: string;
  /** ISO timestamp when message expires */
  expires_at: string;
}

/**
 * Relay response envelope
 */
export interface RelayResponseEnvelope {
  /** Protocol version */
  version: string;
  /** Original request ID for correlation */
  request_id: string;
  /** Encrypted response payload - opaque to relay */
  encrypted_payload: string;
  /** Response timestamp */
  timestamp: string;
}

// ============================================================================
// WebSocket Message Types
// ============================================================================

export type WsMessageType =
  | 'register'     // Vault registers with relay
  | 'unregister'   // Vault disconnects
  | 'request'      // Client sends request to vault
  | 'response'     // Vault sends response to client
  | 'heartbeat'    // Keep-alive ping
  | 'ack'          // Acknowledgement
  | 'error';       // Error response

export interface WsMessage {
  type: WsMessageType;
  payload: unknown;
  timestamp: string;
}

/**
 * Registration payload with authentication
 *
 * Defense in depth:
 * 1. Signature: Proves possession of private key (Ed25519)
 * 2. Pairing token: Ties to OAuth pairing flow (Sprint 3)
 *
 * The signature covers: vault_id + timestamp + nonce
 * This prevents replay attacks and proves key ownership.
 */
export interface RegisterPayload {
  /** Vault identifier */
  vault_id: string;
  /** HPKE receiver public key (base64) */
  public_key: string;
  /** Ed25519 signing public key (base64) - used for signature verification */
  signing_public_key: string;
  /** ISO timestamp (must be within 5 minutes of server time) */
  timestamp: string;
  /** Random nonce to prevent replay (base64, 32 bytes) */
  nonce: string;
  /** Ed25519 signature of: vault_id || timestamp || nonce (base64) */
  signature: string;
  /** Pairing token from 'dcp connect' flow (optional until Sprint 3) */
  pairing_token?: string;
}

/** Maximum allowed clock skew for registration timestamps */
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000; // 5 minutes

/** Minimum nonce size */
export const MIN_NONCE_SIZE = 32;

export interface HeartbeatPayload {
  vault_id: string;
  timestamp: string;
}

// ============================================================================
// HTTP Long-Poll Types (Fallback)
// ============================================================================

export interface LongPollRequest {
  vault_id: string;
  timeout_ms?: number;
  last_message_id?: string;
}

export interface LongPollResponse {
  messages: RelayEnvelope[];
  last_message_id: string;
}

// ============================================================================
// Internal Store Types
// ============================================================================

export interface StoredMessage {
  envelope: RelayEnvelope;
  received_at: number;
  delivered: boolean;
  response?: RelayResponseEnvelope;
}

export interface VaultConnection {
  vault_id: string;
  public_key: string;
  connected_at: number;
  last_heartbeat: number;
  ws?: unknown; // WebSocket reference
}

// ============================================================================
// Error Types (from PRD Section 7.3)
// ============================================================================

/**
 * Relay error codes - transport-level only
 * Business logic errors are inside encrypted_payload (invisible to relay)
 */
export type RelayErrorCode =
  | 'RELAY_UNAVAILABLE'
  | 'RELAY_TIMEOUT'
  | 'RELAY_UNAUTHORIZED'
  | 'RELAY_INVALID_ENVELOPE'
  | 'RELAY_VAULT_NOT_CONNECTED'
  | 'RELAY_DUPLICATE_REQUEST'
  | 'RELAY_MESSAGE_EXPIRED'
  | 'RELAY_RATE_LIMITED';

export class RelayError extends Error {
  constructor(
    public code: RelayErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'RelayError';
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

// ============================================================================
// Configuration Types
// ============================================================================

export interface RelayConfig {
  /** Port to listen on */
  port: number;
  /** Host to bind to */
  host: string;
  /** Enable HTTP long-poll fallback */
  enableLongPoll: boolean;
  /** Heartbeat interval in ms (default: 30000) */
  heartbeatIntervalMs: number;
  /** Message TTL in ms (default: 300000 = 5 minutes) */
  messageTtlMs: number;
  /** Max pending messages per vault */
  maxPendingMessages: number;
  /** Enable debug logging */
  debug: boolean;
  /** Rate limit: max requests per vault per minute (default: 60) */
  rateLimitPerMinute: number;
  /** Rate limit window in ms (default: 60000 = 1 minute) */
  rateLimitWindowMs: number;
}

export const DEFAULT_RELAY_CONFIG: RelayConfig = {
  port: 8421,
  host: '0.0.0.0', // Relay is meant to be publicly accessible
  enableLongPoll: true,
  heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS,
  messageTtlMs: MESSAGE_TTL_MS,
  maxPendingMessages: 100,
  debug: false,
  rateLimitPerMinute: 60,
  rateLimitWindowMs: 60_000,
};
