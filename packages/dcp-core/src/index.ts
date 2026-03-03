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

  // Utilities
  verifyCryptoReady,
  // Constants
  KEY_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
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
  DEFAULT_BUDGET_CONFIG,
  DEFAULT_VAULT_CONFIG,
  RATE_LIMIT_PER_MINUTE,
} from './budget.js';
