/**
 * DCP Vault Core
 *
 * Core encryption, wallet, storage, and policy engine for DCP Vault.
 * Private keys never leave this module - agents call vault operations,
 * never touch the keys.
 */

// Types
export * from './types.js';

// Crypto Engine
export {
  // Key generation
  generateKey,
  generateNonce,
  generateSalt,

  // Argon2id key derivation
  deriveKeyFromPassphrase,

  // XChaCha20-Poly1305 encryption
  encrypt,
  decrypt,

  // Envelope encryption (two-layer)
  envelopeEncrypt,
  envelopeDecrypt,

  // Memory safety
  zeroize,
  secureAlloc,

  // BIP-39 Recovery
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  validateMnemonic,
  generateRecoveryPhrase, // deprecated

  // Ed25519 Signing
  generateSigningKeyPair,
  signMessage,
  verifySignature,

  // Utilities
  verifyCryptoReady,
  canonicalJson,

  // Constants
  KEY_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from './crypto.js';

// Wallet Manager
export {
  // Wallet creation
  generateWalletKeypair,
  encryptWalletKey,
  createWallet,

  // Transaction signing
  signTransaction,
  signSolanaTransaction,
  signEvmTransaction,

  // Message signing
  signSolanaMessage,
  signEvmMessage,
  signEvmTypedData,

  // Wallet import
  importWallet,

  // Utilities
  getPublicAddress,
  getSupportedOperations,
  isChainSupported,
} from './wallet.js';

// Storage Layer
export { VaultStorage, getStorage, resetStorage } from './storage.js';

// Budget & Policy Engine
export {
  // Budget Engine class
  BudgetEngine,
  getBudgetEngine,
  resetBudgetEngine,

  // Configuration
  VaultConfig,
  DesktopOwner,
  DEFAULT_BUDGET_CONFIG,
  DEFAULT_VAULT_CONFIG,
  RATE_LIMIT_PER_MINUTE,
} from './budget.js';

// Known Services Registry
export {
  KNOWN_SERVICES,
  getKnownService,
  listKnownServices,
  isKnownService,
  parsePublicKey,
  isValidPublicKey,
  DEFAULT_RELAY_URL,
  RELAY_URLS,
} from './services.js';

// Signed Pairing Grants (PRD Section 7.1)
export {
  createSignedPairingGrant,
  decodePairingGrant,
  verifyPairingGrant,
  verifyPairingGrantWithKey,
  isPairingGrant,
  PAIRING_GRANT_PREFIX,
  DEFAULT_PAIRING_TTL_MS,
  type CreatePairingGrantInput,
  // VPS Pairing Invites (for remote agent pairing via relay)
  createVpsPairingInvite,
  parseVpsPairingInvite,
  isVpsInviteExpired,
  isVpsPairingInvite,
  VPS_INVITE_PREFIX,
  type VpsPairingInvite,
  // Session Tokens (for Gateway Authentication)
  createSessionToken,
  decodeSessionToken,
  verifySessionToken,
  isSessionToken,
  SESSION_TOKEN_PREFIX,
  DEFAULT_SESSION_TOKEN_TTL_MS,
  type CreateSessionTokenInput,
} from './pairing.js';

// Re-export Telegram types explicitly for convenience
export type {
  TelegramConfig,
  CreateTelegramConfigInput,
  TelegramPairingCode,
  TelegramNotificationLog,
  TelegramConsentPayload,
  TelegramWebhookPayload,
  TelegramRequestCategory,
} from './types.js';
