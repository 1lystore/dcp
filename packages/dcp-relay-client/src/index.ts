/**
 * DCP Relay Client - Entry Point
 *
 * Provides encrypted connection between local vaults and DCP relay.
 *
 * From protocol spec:
 * - RFC 9180 HPKE (X25519 + ChaCha20-Poly1305)
 * - AAD binding to envelope metadata
 * - Ed25519 signed registration
 * - WebSocket connection with auto-reconnect
 * - Exponential backoff with jitter (1s → 60s)
 * - Heartbeat (30 seconds)
 */

// ============================================================================
// Client Exports
// ============================================================================

export { RelayClient, createRelayClient } from './client.js';

// ============================================================================
// Crypto Exports
// ============================================================================

export {
  // Key generation
  generateKeyPair,
  generateKeyPairSync,
  generateSigningKeyPair,

  // HPKE encryption/decryption
  encrypt,
  decrypt,
  constructAad,

  // Serialization
  serializeEncrypted,
  deserializeEncrypted,
  encodeToBase64,
  decodeFromBase64,

  // Key utilities
  encodePublicKey,
  decodePublicKey,
  zeroize,

  // Signing (for authentication)
  sign,
  generateNonce,
} from './crypto.js';

// ============================================================================
// Type Exports
// ============================================================================

export {
  // Types from this package
  type HpkeKeyPair,
  type SigningKeyPair,
  type EncryptedMessage,
  type EnvelopeAad,
  type RelayClientConfig,
  type RelayClientEvents,
  type RequestHandler,
  type ClientState,
  type ClientErrorCode,
  ClientError,
  DEFAULT_CLIENT_CONFIG,
  HPKE_KEY_SIZE,
  HPKE_NONCE_SIZE,
  HPKE_TAG_SIZE,

  // Re-exported from @dcprotocol/relay
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
} from './types.js';
