/**
 * Types for DCP Relay Client
 * Local vault connector to relay with HPKE encryption
 *
 * From protocol spec Section 4.2, 6:
 * - WebSocket connection management
 * - Reconnect + heartbeat
 * - Encrypt/decrypt payloads using HPKE (X25519 + ChaCha20-Poly1305)
 */

// Re-export relay types
export {
  type RelayEnvelope,
  type RelayResponseEnvelope,
  type ActionType,
  type WsMessage,
  type WsMessageType,
  type RegisterPayload,
  type HeartbeatPayload,
  type RelayErrorCode,
  type PairingClaim,
  type StoredPairingClaim,
  RelayError,
  RELAY_VERSION,
  HEARTBEAT_INTERVAL_MS,
  MESSAGE_TTL_MS,
  RECONNECT_MIN_MS,
  RECONNECT_MAX_MS,
} from '@dcprotocol/relay';

// ============================================================================
// Constants
// ============================================================================

export const HPKE_KEY_SIZE = 32; // X25519 key size
export const HPKE_NONCE_SIZE = 0; // HPKE handles nonces internally
export const HPKE_TAG_SIZE = 16; // Poly1305 tag size

// ============================================================================
// HPKE Key Types
// ============================================================================

export interface HpkeKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

export interface EncryptedMessage {
  /** Encapsulated key / Ephemeral public key (32 bytes) */
  ephemeralPublicKey: Buffer;
  /** Nonce (empty for HPKE - handled internally) */
  nonce: Buffer;
  /** Ciphertext (variable length, includes Poly1305 tag) */
  ciphertext: Buffer;
}

/**
 * Envelope metadata for AAD binding
 * AAD prevents ciphertext substitution between envelopes
 */
export interface EnvelopeAad {
  version: string;
  vault_id: string;
  request_id: string;
  action_type: string;
}

// ============================================================================
// Client Configuration
// ============================================================================

/**
 * Signing keypair for relay authentication (Ed25519)
 */
export interface SigningKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

export interface RelayClientConfig {
  /** Relay server URL (e.g., ws://relay.example.com or wss://relay.example.com) */
  relayUrl: string;
  /** Vault ID for routing */
  vaultId: string;
  /** HPKE keypair for encryption/decryption */
  keyPair: HpkeKeyPair;
  /** Ed25519 signing keypair for relay authentication */
  signingKeyPair: SigningKeyPair;
  /** Pairing token from 'dcp connect' flow (optional) */
  pairingToken?: string;
  /** Enable automatic reconnection */
  autoReconnect: boolean;
  /** Initial reconnect delay in ms (default: 1000) */
  reconnectMinMs: number;
  /** Maximum reconnect delay in ms (default: 60000) */
  reconnectMaxMs: number;
  /** Heartbeat interval in ms (default: 30000) */
  heartbeatIntervalMs: number;
  /** Enable debug logging */
  debug: boolean;
}

export const DEFAULT_CLIENT_CONFIG: Omit<RelayClientConfig, 'relayUrl' | 'vaultId' | 'keyPair' | 'signingKeyPair' | 'pairingToken'> = {
  autoReconnect: true,
  reconnectMinMs: 1000,
  reconnectMaxMs: 60000,
  heartbeatIntervalMs: 30000,
  debug: false,
};

// ============================================================================
// Client State
// ============================================================================

export type ClientState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting';

// ============================================================================
// Event Types
// ============================================================================

export interface RelayClientEvents {
  connected: () => void;
  disconnected: (reason: string) => void;
  reconnecting: (attempt: number, delayMs: number) => void;
  error: (error: Error) => void;
  request: (envelope: import('@dcprotocol/relay').RelayEnvelope) => void;
  /** Emitted when a VPS agent submits a pairing claim via the relay */
  pairingClaim: (claim: import('@dcprotocol/relay').StoredPairingClaim) => void;
}

// ============================================================================
// Request Handler Type
// ============================================================================

/**
 * Handler function for incoming relay requests
 * Returns the response payload to send back
 */
export interface RelayResponseData {
  /** Response payload to encrypt and send back */
  payload: Buffer;
  /** Recipient public key for response encryption (requester key) */
  recipientPublicKey: Buffer;
}

export type RequestHandler = (
  action: import('@dcprotocol/relay').ActionType,
  decryptedPayload: Buffer
) => Promise<RelayResponseData>;

// ============================================================================
// Client Error Types
// ============================================================================

export type ClientErrorCode =
  | 'CLIENT_NOT_CONNECTED'
  | 'CLIENT_ALREADY_CONNECTED'
  | 'CLIENT_CONNECTION_FAILED'
  | 'CLIENT_ENCRYPTION_FAILED'
  | 'CLIENT_DECRYPTION_FAILED'
  | 'CLIENT_INVALID_KEY';

export class ClientError extends Error {
  constructor(
    public code: ClientErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ClientError';
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
