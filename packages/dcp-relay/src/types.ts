/**
 * Types for DCP Relay
 * Encrypted message bus between cloud MCP clients and local vaults
 *
 * From protocol spec Section 4.1:
 * - Relay sees only encrypted payloads and minimal routing metadata
 * - No method names, amounts, recipients, or business logic visible to relay
 */

// ============================================================================
// Constants (from protocol spec section 4.1, 7.1)
// ============================================================================

export const RELAY_VERSION = '1';
export const HEARTBEAT_INTERVAL_MS = 30_000; // 30 seconds
export const MESSAGE_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const RECONNECT_MIN_MS = 1_000; // 1 second
export const RECONNECT_MAX_MS = 60_000; // 60 seconds

// ============================================================================
// Action Types (from protocol spec section 7)
// ============================================================================

/**
 * Generic action types - relay does not interpret method names
 * All specific methods (vault_sign_x402, etc.) live inside encrypted_payload
 */
export type ActionType = 'sign' | 'read' | 'write' | 'budget';

// ============================================================================
// Relay Envelope (from protocol spec section 7.1)
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
  | 'register'        // Vault registers with relay
  | 'unregister'      // Vault disconnects
  | 'request'         // Client sends request to vault
  | 'response'        // Vault sends response to client
  | 'heartbeat'       // Keep-alive ping
  | 'ack'             // Acknowledgement
  | 'error'           // Error response
  | 'pairing_claim'   // New pairing claim from agent (relay → vault)
  | 'pairing_result'; // Pairing approval result from vault (vault → relay)

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

export interface PushTokenRegistration {
  vault_id: string;
  token: string;
  platform?: 'ios' | 'android' | 'web' | 'unknown';
  device_id?: string;
  updated_at: number;
}

// ============================================================================
// Error Types (from protocol spec section 7.3)
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
  /** Expo push API endpoint. Empty disables outbound push delivery. */
  expoPushUrl: string;
}

export const DEFAULT_RELAY_CONFIG: RelayConfig = {
  port: 8422, // Note: 8421 is used by vault, relay uses 8422
  host: '0.0.0.0', // Relay is meant to be publicly accessible
  enableLongPoll: true,
  heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS,
  messageTtlMs: MESSAGE_TTL_MS,
  maxPendingMessages: 100,
  debug: false,
  rateLimitPerMinute: 60,
  rateLimitWindowMs: 60_000,
  expoPushUrl: 'https://exp.host/--/api/v2/push/send',
};

// ============================================================================
// Pairing Claim Types (VPS → Relay → Vault flow)
// ============================================================================

/**
 * Pairing claim submitted by VPS agent during install-service
 *
 * Flow (per the protocol spec):
 * 1. VPS parses pairing invite (request-only, no authority)
 * 2. VPS generates Ed25519 keypair
 * 3. VPS signs claim with private key
 * 4. Relay routes claim to vault via invite_id
 * 5. Desktop shows pending pairing with verification phrase
 * 6. User approves and assigns permissions in vault policy DB
 */
export interface PairingClaim {
  /** Invite ID from the pairing invite (routes to vault) */
  invite_id: string;
  /** Vault ID from the invite (self-routing, survives relay restarts) */
  vault_id?: string;
  /** Agent's Ed25519 public key (base64) */
  agent_public_key: string;
  /** Agent's hostname for display */
  agent_hostname: string;
  /** Agent version */
  agent_version: string;
  /** Timestamp for freshness check */
  timestamp: number;
  /** Nonce for uniqueness */
  nonce: string;
  /** Ed25519 signature of canonical JSON payload (base64) */
  signature: string;
}

/**
 * Stored pairing claim with metadata
 */
export interface StoredPairingClaim {
  claim_id: string;
  claim: PairingClaim;
  verification_phrase: string;
  received_at: number;
  /** Pending = waiting for user approval, approved/denied/expired are terminal */
  status: 'pending' | 'approved' | 'denied' | 'expired';
  /** Assigned agent_id after approval */
  agent_id?: string;
  /** Vault ID that will process this claim */
  vault_id?: string;
  /** When status changed to terminal */
  resolved_at?: number;
}

/**
 * Response to pairing claim submission
 */
export interface PairingClaimResponse {
  success: boolean;
  claim_id?: string;
  verification_phrase?: string;
  error?: string;
}

/**
 * Pairing claim approval status (for polling)
 */
export interface PairingApprovalStatus {
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'not_found';
  agent_id?: string;
  vault_id?: string;
  error?: string;
}

// ============================================================================
// DCP Mobile Pairing Types (Agent QR → Mobile approval → Agent polling)
// ============================================================================

export type MobileAgentClient =
  | 'claude-desktop'
  | 'cursor'
  | 'vscode'
  | 'hermes'
  | 'openclaw'
  | 'mcp'
  | 'custom'
  | 'hosted';

export type MobileAgentEnvironment = 'local' | 'vps' | 'hosted' | 'dev';

export type MobileDcpScope =
  | 'read:wallet.address'
  | 'sign:solana'
  | 'vault_get_address'
  | 'vault_budget_check'
  | 'vault_sign_tx'
  | 'vault_sign_message';

export interface MobilePairingBudget {
  daily: number;
  currency: 'SOL' | 'USDC';
  approval_threshold: number;
}

export interface MobilePairingInvite {
  type: 'dcp_agent_pairing';
  version: '1.0';
  relay_url: string;
  invite_id: string;
  requested_agent_id: string;
  agent_public_key: string;
  agent_name: string;
  agent_client: MobileAgentClient;
  environment: MobileAgentEnvironment;
  requested_scopes: MobileDcpScope[];
  requested_budget: MobilePairingBudget;
  created_at: string;
  expires_at: string;
  nonce: string;
  signature?: string;
}

export interface MobilePairingApprovalRequest {
  invite: MobilePairingInvite;
  vault_id: string;
  agent_id: string;
  vault_hpke_public_key: string;
  vault_signing_public_key: string;
  approved_scopes: MobileDcpScope[];
  approved_budget: MobilePairingBudget;
}

export interface MobilePairingRecord {
  invite_id: string;
  invite: MobilePairingInvite;
  received_at: number;
  status: 'approved' | 'denied' | 'expired';
  vault_id?: string;
  vault_hpke_public_key?: string;
  vault_signing_public_key?: string;
  agent_id?: string;
  approved_scopes?: MobileDcpScope[];
  approved_budget?: MobilePairingBudget;
  resolved_at?: number;
  denied_reason?: string;
}

export interface MobilePairingStatus {
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'not_found';
  invite_id?: string;
  agent_id?: string;
  vault_id?: string;
  vault_hpke_public_key?: string;
  vault_signing_public_key?: string;
  approved_scopes?: MobileDcpScope[];
  approved_budget?: MobilePairingBudget;
  error?: string;
}
