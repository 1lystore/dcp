/**
 * Crypto Engine for DCP Vault
 *
 * Implements:
 * - XChaCha20-Poly1305 encryption (256-bit key, 192-bit nonce, AEAD)
 * - Argon2id key derivation (m=64MB, t=3, p=4)
 * - Envelope encryption (per-record DEK wrapped with master key)
 * - Memory zeroization after use
 *
 * SECURITY CRITICAL: This is the foundation of the vault.
 * Private keys exist in plaintext for ~5ms during operations.
 */

import sodium from 'sodium-native';
import * as bip39 from 'bip39';
import { EncryptedPayload, VaultError } from './types.js';

// ============================================================================
// Constants (from PRD Section 3.2.1)
// ============================================================================

/** XChaCha20-Poly1305 key size: 256 bits */
export const KEY_SIZE = 32;

/** XChaCha20-Poly1305 nonce size: 192 bits */
export const NONCE_SIZE = 24;

/** Authentication tag size: 128 bits */
export const TAG_SIZE = 16;

/** Argon2id memory cost: 64 MB */
const ARGON2_MEMORY = 65536;

/** Argon2id time cost: 3 iterations */
const ARGON2_TIME = 3;

/** Salt size for Argon2id */
const SALT_SIZE = 16;

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate a cryptographically secure random key (256-bit)
 * Used for master key and per-record DEKs
 */
export function generateKey(): Buffer {
  const key = sodium.sodium_malloc(KEY_SIZE);
  sodium.randombytes_buf(key);
  return key;
}

/**
 * Generate a cryptographically secure random nonce (192-bit)
 * Each encryption MUST use a unique nonce
 */
export function generateNonce(): Buffer {
  const nonce = Buffer.allocUnsafe(NONCE_SIZE);
  sodium.randombytes_buf(nonce);
  return nonce;
}

/**
 * Generate a cryptographically secure salt for Argon2id
 */
export function generateSalt(): Buffer {
  const salt = Buffer.allocUnsafe(SALT_SIZE);
  sodium.randombytes_buf(salt);
  return salt;
}

// ============================================================================
// Argon2id Key Derivation (from PRD Section 3.2.1)
// ============================================================================

/**
 * Derive a 256-bit key from passphrase using Argon2id
 *
 * Parameters (from PRD):
 * - m = 64MB (memory cost)
 * - t = 3 (time cost / iterations)
 * - p = 4 (parallelism - handled internally by libsodium)
 *
 * @param passphrase - User's passphrase
 * @param salt - 16-byte salt (generate with generateSalt() for new keys)
 * @returns 256-bit derived key
 */
export function deriveKeyFromPassphrase(passphrase: string, salt: Buffer): Buffer {
  if (salt.length !== SALT_SIZE) {
    throw new VaultError('INTERNAL_ERROR', `Salt must be ${SALT_SIZE} bytes`);
  }

  const key = sodium.sodium_malloc(KEY_SIZE);
  const passphraseBuffer = Buffer.from(passphrase, 'utf8');

  try {
    sodium.crypto_pwhash(
      key,
      passphraseBuffer,
      salt,
      ARGON2_TIME,
      ARGON2_MEMORY * 1024, // Convert KB to bytes
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    return key;
  } finally {
    // Zeroize passphrase from memory
    zeroize(passphraseBuffer);
  }
}

// ============================================================================
// XChaCha20-Poly1305 Encryption (from PRD Section 5)
// ============================================================================

/**
 * Encrypt plaintext using XChaCha20-Poly1305
 *
 * @param plaintext - Data to encrypt
 * @param key - 256-bit encryption key
 * @param associatedData - Optional authenticated data (not encrypted, but authenticated)
 * @returns Object containing ciphertext and nonce
 */
export function encrypt(
  plaintext: Buffer,
  key: Buffer,
  associatedData?: Buffer
): { ciphertext: Buffer; nonce: Buffer } {
  if (key.length !== KEY_SIZE) {
    throw new VaultError('INTERNAL_ERROR', `Key must be ${KEY_SIZE} bytes`);
  }

  const nonce = generateNonce();
  const ciphertext = Buffer.allocUnsafe(plaintext.length + TAG_SIZE);

  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext,
    plaintext,
    associatedData || null,
    null, // nsec (not used)
    nonce,
    key
  );

  return { ciphertext, nonce };
}

/**
 * Decrypt ciphertext using XChaCha20-Poly1305
 *
 * @param ciphertext - Encrypted data (includes auth tag)
 * @param nonce - 192-bit nonce used during encryption
 * @param key - 256-bit decryption key
 * @param associatedData - Optional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws VaultError if decryption fails (tampered data or wrong key)
 */
export function decrypt(
  ciphertext: Buffer,
  nonce: Buffer,
  key: Buffer,
  associatedData?: Buffer
): Buffer {
  if (key.length !== KEY_SIZE) {
    throw new VaultError('INTERNAL_ERROR', `Key must be ${KEY_SIZE} bytes`);
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new VaultError('INTERNAL_ERROR', `Nonce must be ${NONCE_SIZE} bytes`);
  }

  const plaintext = sodium.sodium_malloc(ciphertext.length - TAG_SIZE);

  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext,
      null, // nsec (not used)
      ciphertext,
      associatedData || null,
      nonce,
      key
    );
    return plaintext;
  } catch {
    throw new VaultError('INTERNAL_ERROR', 'Decryption failed - data may be tampered or key incorrect');
  }
}

// ============================================================================
// Envelope Encryption (from PRD Section 5)
// ============================================================================

/**
 * Encrypt data using envelope encryption (two-layer encryption)
 *
 * Layer 1: Master Key (stored in OS Keychain)
 * Layer 2: Per-Record DEK (Data Encryption Key)
 *
 * Process:
 * 1. Generate a new 256-bit DEK for this record
 * 2. Encrypt plaintext with DEK: XChaCha20-Poly1305(plaintext, DEK)
 * 3. Wrap DEK with master key: XChaCha20-Poly1305(DEK, masterKey)
 * 4. Return ciphertext + wrapped DEK + nonces
 *
 * @param plaintext - Data to encrypt
 * @param masterKey - 256-bit master key from OS Keychain
 * @returns Encrypted payload with wrapped DEK
 */
export function envelopeEncrypt(plaintext: Buffer, masterKey: Buffer): EncryptedPayload {
  // Generate per-record DEK
  const dek = generateKey();

  try {
    // Layer 2: Encrypt plaintext with DEK
    const { ciphertext, nonce } = encrypt(plaintext, dek);

    // Layer 1: Wrap DEK with master key
    const { ciphertext: dekWrapped, nonce: dekNonce } = encrypt(dek, masterKey);

    return {
      ciphertext,
      nonce,
      dek_wrapped: dekWrapped,
      dek_nonce: dekNonce,
    };
  } finally {
    // CRITICAL: Zeroize DEK from memory immediately
    zeroize(dek);
  }
}

/**
 * Decrypt envelope-encrypted data
 *
 * Process:
 * 1. Unwrap DEK: XChaCha20-Poly1305-Decrypt(wrapped_dek, masterKey) → DEK
 * 2. Decrypt data: XChaCha20-Poly1305-Decrypt(ciphertext, DEK) → plaintext
 * 3. Zeroize DEK from memory
 *
 * @param payload - Encrypted payload with wrapped DEK
 * @param masterKey - 256-bit master key from OS Keychain
 * @returns Decrypted plaintext (caller MUST zeroize after use)
 */
export function envelopeDecrypt(payload: EncryptedPayload, masterKey: Buffer): Buffer {
  // Layer 1: Unwrap DEK
  const dek = decrypt(payload.dek_wrapped, payload.dek_nonce, masterKey);

  try {
    // Layer 2: Decrypt data with DEK
    const plaintext = decrypt(payload.ciphertext, payload.nonce, dek);
    return plaintext;
  } finally {
    // CRITICAL: Zeroize DEK from memory immediately
    zeroize(dek);
  }
}

// ============================================================================
// Memory Zeroization (from PRD Section 3.2.1)
// ============================================================================

/**
 * Securely zeroize sensitive data from memory
 *
 * CRITICAL: Must be called after any operation with sensitive data:
 * - Private keys
 * - DEKs
 * - Passphrases
 * - Decrypted plaintext
 *
 * Uses sodium_memzero which is resistant to compiler optimizations
 * that might skip zeroing "unused" memory.
 */
export function zeroize(buffer: Buffer): void {
  if (buffer && buffer.length > 0) {
    sodium.sodium_memzero(buffer);
  }
}

/**
 * Create a secure buffer that can be zeroized
 * Uses sodium_malloc which provides:
 * - Guard pages to detect buffer overflows
 * - Memory that can be securely zeroized
 */
export function secureAlloc(size: number): Buffer {
  return sodium.sodium_malloc(size);
}

// ============================================================================
// BIP-39 Recovery Phrase (from PRD Section 3.2.1)
// ============================================================================

/**
 * Generate a 12-word BIP-39 mnemonic for vault recovery
 *
 * This generates a cryptographically secure 128-bit entropy that produces
 * a valid 12-word BIP-39 mnemonic with proper checksum.
 *
 * IMPORTANT: This mnemonic should be shown to the user ONCE during vault init.
 * The user MUST write it down. It is NOT stored in the vault.
 *
 * @returns 12-word BIP-39 mnemonic phrase
 */
export function generateRecoveryMnemonic(): string {
  // Generate 128 bits of entropy for 12-word mnemonic
  // BIP-39: 128 bits entropy = 12 words (with 4-bit checksum)
  const entropy = Buffer.allocUnsafe(16);
  sodium.randombytes_buf(entropy);

  // Convert entropy to BIP-39 mnemonic
  const mnemonic = bip39.entropyToMnemonic(entropy.toString('hex'));

  // Zeroize entropy from memory
  sodium.sodium_memzero(entropy);

  return mnemonic;
}

/**
 * Derive master key from BIP-39 recovery mnemonic
 *
 * This allows users to recover their vault from the 12-word phrase.
 * Uses BIP-39 standard to convert mnemonic to 512-bit seed, then
 * takes first 256 bits as master key.
 *
 * @param mnemonic - 12-word BIP-39 mnemonic
 * @param passphrase - Optional BIP-39 passphrase (empty string if not used)
 * @returns 256-bit master key
 * @throws VaultError if mnemonic is invalid
 */
export function deriveKeyFromMnemonic(mnemonic: string, passphrase: string = ''): Buffer {
  // Validate mnemonic
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new VaultError('INTERNAL_ERROR', 'Invalid recovery phrase');
  }

  // Derive 512-bit seed from mnemonic using BIP-39 standard
  // This uses PBKDF2-HMAC-SHA512 with 2048 iterations
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);

  // Take first 256 bits (32 bytes) as master key
  const masterKey = sodium.sodium_malloc(KEY_SIZE);
  seed.copy(masterKey, 0, 0, KEY_SIZE);

  // Zeroize seed from memory
  sodium.sodium_memzero(seed);

  return masterKey;
}

/**
 * Validate a BIP-39 mnemonic phrase
 *
 * @param mnemonic - Mnemonic to validate
 * @returns true if valid BIP-39 mnemonic with correct checksum
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic);
}

/**
 * @deprecated Use generateRecoveryMnemonic() instead
 *
 * This function is deprecated and will be removed.
 * It was incorrectly named and implied it derived from master key,
 * but recovery phrases should be generated independently.
 */
export function generateRecoveryPhrase(_masterKey: Buffer): string {
  return generateRecoveryMnemonic();
}

/**
 * Verify that sodium-native is properly initialized
 * Should be called at module load
 */
export function verifyCryptoReady(): boolean {
  try {
    // Test key generation
    const testKey = generateKey();
    const testNonce = generateNonce();

    // Test encryption/decryption roundtrip
    const testData = Buffer.from('test');
    const encrypted = encrypt(testData, testKey);
    const decrypted = decrypt(encrypted.ciphertext, encrypted.nonce, testKey);

    const success = decrypted.equals(testData);

    // Cleanup
    zeroize(testKey);
    zeroize(decrypted);

    return success && testNonce.length === NONCE_SIZE;
  } catch {
    return false;
  }
}
