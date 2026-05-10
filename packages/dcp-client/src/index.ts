/**
 * @dcprotocol/client
 *
 * Universal agent SDK for DCP - connect any agent to DCP Vault.
 *
 * Features:
 * - Auto-detect local vs relay transport
 * - HPKE encryption for relay mode (X25519 + ChaCha20-Poly1305)
 * - Session caching for approved operations
 * - Service signature support for trusted services
 * - TypeScript types included
 *
 * @example
 * ```typescript
 * import { DcpClient } from '@dcprotocol/client';
 *
 * const dcp = new DcpClient({ mode: 'auto' });
 *
 * // Get wallet address
 * const { address } = await dcp.getAddress('solana');
 *
 * // Sign a transaction (will prompt for consent if first time)
 * const result = await dcp.signTx({
 *   chain: 'solana',
 *   unsignedTx: '...',
 *   amount: 0.5,
 *   currency: 'USDC',
 *   description: 'Buy API access',
 * });
 *
 * // Read credentials
 * const { data } = await dcp.readCredential('credentials.api.openai');
 *
 * // Always close when done
 * await dcp.close();
 * ```
 *
 * @packageDocumentation
 */

// Main client
export { DcpClient, createDcpClient } from './client.js';

// Errors
export {
  DcpError,
  vaultOffline,
  vaultLocked,
  consentRequired,
  relayUnavailable,
  relayTimeout,
  invalidConfig,
  parseErrorResponse,
} from './errors.js';

export type { DcpErrorCode, DcpErrorAction, DcpErrorDetails } from './errors.js';

// Types
export type {
  // Config
  DcpClientConfig,
  DcpMode,
  ResolvedConfig,

  // Chains
  Chain,
  Network,

  // Input types
  SignTxInput,
  SignMessageInput,
  SignX402Input,
  ReadCredentialInput,
  WriteCredentialInput,
  BudgetCheckInput,
  PairServiceInput,

  // Output types
  GetAddressResult,
  SignTxResult,
  SignMessageResult,
  SignX402Result,
  ReadCredentialResult,
  WriteCredentialResult,
  BudgetCheckResult,
  PairServiceResult,
  ConsentStatusResult,
  HealthCheckResult,

  // Session
  SessionInfo,

  // Transport (internal, but exposed for advanced use)
  Transport,

  // Relay types
  RelayEnvelope,
  RelayResponseEnvelope,
  DecryptedRelayPayload,
  EnvelopeAad,
  HpkeKeyPair,
  EncryptedMessage,
} from './types.js';

// Constants
export {
  DEFAULT_LOCAL_URL,
  DEFAULT_RELAY_URL,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_LOCAL_CHECK_TIMEOUT_MS,
  RELAY_VERSION,
  CHAIN_CURRENCY_MAP,
} from './types.js';

// Crypto utilities (for advanced use)
export {
  generateKeyPair,
  generateKeyPairSync,
  encrypt,
  decrypt,
  encodeToBase64,
  decodeFromBase64,
  encodePublicKey,
  decodePublicKey,
  zeroize,
  sign,
  verify,
  generateSigningKeyPair,
  generateNonce,
  generateRequestId,
  constructAad,
  HPKE_KEY_SIZE,
} from './crypto.js';

// Transports (for advanced use)
export { LocalTransport } from './local-transport.js';
export { RelayTransport } from './relay-transport.js';
