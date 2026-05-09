/**
 * HPKE Cryptography for DCP Client SDK
 *
 * Implements RFC 9180 HPKE for relay encryption:
 * - KEM: DHKEM(X25519, HKDF-SHA256)
 * - KDF: HKDF-SHA256
 * - AEAD: ChaCha20-Poly1305
 *
 * See protocol spec section A4.2 and A8 for relay encryption specification.
 *
 * SECURITY NOTES:
 * - Uses ephemeral sender keys for each encryption (forward secrecy)
 * - All key material is zeroized after use via close()
 * - AAD binds ciphertext to envelope metadata (prevents substitution)
 */

import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import sodium from 'sodium-native';
import type { HpkeKeyPair, EncryptedMessage, EnvelopeAad } from './types.js';
import { DcpError } from './errors.js';

// ============================================================================
// Constants
// ============================================================================

export const HPKE_KEY_SIZE = 32; // X25519 key size
const ENCAP_SIZE = 32; // Encapsulated key size for X25519
const MIN_CIPHERTEXT_SIZE = 16; // Poly1305 tag size

// ============================================================================
// HPKE Suite Configuration (RFC 9180)
// ============================================================================

/**
 * HPKE Cipher Suite:
 * - KEM: DHKEM(X25519, HKDF-SHA256) - Mode 0x0020
 * - KDF: HKDF-SHA256 - Mode 0x0001
 * - AEAD: ChaCha20-Poly1305 - Mode 0x0003
 */
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate an HPKE keypair (X25519)
 * Used for ephemeral reply keys in relay requests
 */
export async function generateKeyPair(): Promise<HpkeKeyPair> {
  const keyPair = await suite.kem.generateKeyPair();

  // Export keys to raw bytes
  const publicKeyArray = await suite.kem.serializePublicKey(keyPair.publicKey);
  const privateKeyArray = await suite.kem.serializePrivateKey(keyPair.privateKey);

  return {
    publicKey: Buffer.from(publicKeyArray),
    privateKey: Buffer.from(privateKeyArray),
  };
}

/**
 * Synchronous key generation using sodium-native
 * For cases where async is not possible
 */
export function generateKeyPairSync(): HpkeKeyPair {
  const publicKey = sodium.sodium_malloc(HPKE_KEY_SIZE);
  const privateKey = sodium.sodium_malloc(HPKE_KEY_SIZE);

  sodium.crypto_box_keypair(publicKey, privateKey);

  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(privateKey),
  };
}

// ============================================================================
// AAD Construction (protocol spec A4.2)
// ============================================================================

/**
 * Construct AAD (Additional Authenticated Data) from envelope metadata
 *
 * AAD Format: version|vault_id|request_id|action_type (pipe-delimited)
 *
 * This binds the ciphertext to the envelope, preventing:
 * - Ciphertext substitution between envelopes
 * - Replay of ciphertext in different contexts
 */
export function constructAad(envelope: EnvelopeAad): Uint8Array {
  const parts = [
    envelope.version,
    envelope.vault_id,
    envelope.request_id,
    envelope.action_type,
  ];
  return new TextEncoder().encode(parts.join('|'));
}

// ============================================================================
// HPKE Encryption (RFC 9180)
// ============================================================================

/**
 * Encrypt a message using HPKE (RFC 9180)
 *
 * Mode: Base (0x00) - single-shot encryption
 *
 * @param plaintext - Message to encrypt
 * @param recipientPublicKey - Recipient's public key (32 bytes)
 * @param aad - Additional authenticated data (envelope metadata)
 * @returns Encrypted message with encapsulated key
 */
export async function encrypt(
  plaintext: Buffer,
  recipientPublicKey: Buffer,
  aad?: EnvelopeAad
): Promise<EncryptedMessage> {
  if (recipientPublicKey.length !== HPKE_KEY_SIZE) {
    throw new DcpError(
      'ENCRYPTION_FAILED',
      `Recipient public key must be ${HPKE_KEY_SIZE} bytes, got ${recipientPublicKey.length}`
    );
  }

  try {
    // Convert Buffer to ArrayBuffer for HPKE library
    const pubKeyArrayBuffer = new Uint8Array(recipientPublicKey).buffer as ArrayBuffer;

    // Deserialize recipient's public key
    const publicKey = await suite.kem.deserializePublicKey(pubKeyArrayBuffer);

    // Create sender context (generates ephemeral keypair internally)
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey });

    // Construct AAD if envelope metadata provided
    const aadBytes = aad ? constructAad(aad) : new Uint8Array(0);
    const aadArrayBuffer = aadBytes.buffer.slice(
      aadBytes.byteOffset,
      aadBytes.byteOffset + aadBytes.byteLength
    ) as ArrayBuffer;

    // Convert plaintext to ArrayBuffer
    const plaintextArrayBuffer = new Uint8Array(plaintext).buffer as ArrayBuffer;

    // Encrypt with AEAD
    const ciphertext = await sender.seal(plaintextArrayBuffer, aadArrayBuffer);

    return {
      ephemeralPublicKey: Buffer.from(sender.enc),
      nonce: Buffer.alloc(0), // HPKE handles nonce internally
      ciphertext: Buffer.from(ciphertext),
    };
  } catch (err) {
    throw new DcpError('ENCRYPTION_FAILED', 'HPKE encryption failed', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * Decrypt an HPKE-encrypted message (RFC 9180)
 *
 * @param encrypted - Encrypted message with encapsulated key
 * @param privateKey - Recipient's private key (32 bytes)
 * @param aad - Additional authenticated data (must match encryption AAD)
 * @returns Decrypted plaintext
 */
export async function decrypt(
  encrypted: EncryptedMessage,
  privateKey: Buffer,
  aad?: EnvelopeAad
): Promise<Buffer> {
  if (privateKey.length !== HPKE_KEY_SIZE) {
    throw new DcpError(
      'DECRYPTION_FAILED',
      `Private key must be ${HPKE_KEY_SIZE} bytes, got ${privateKey.length}`
    );
  }

  if (encrypted.ephemeralPublicKey.length !== ENCAP_SIZE) {
    throw new DcpError(
      'DECRYPTION_FAILED',
      `Encapsulated key must be ${ENCAP_SIZE} bytes, got ${encrypted.ephemeralPublicKey.length}`
    );
  }

  try {
    // Convert Buffer to ArrayBuffer for HPKE library
    const privKeyArrayBuffer = new Uint8Array(privateKey).buffer as ArrayBuffer;

    // Deserialize private key
    const recipientPrivateKey = await suite.kem.deserializePrivateKey(privKeyArrayBuffer);

    // Convert encapsulated key to ArrayBuffer
    const encArrayBuffer = new Uint8Array(encrypted.ephemeralPublicKey).buffer as ArrayBuffer;

    // Create recipient context
    const recipient = await suite.createRecipientContext({
      recipientKey: recipientPrivateKey,
      enc: encArrayBuffer,
    });

    // Construct AAD if envelope metadata provided
    const aadBytes = aad ? constructAad(aad) : new Uint8Array(0);
    const aadArrayBuffer = aadBytes.buffer.slice(
      aadBytes.byteOffset,
      aadBytes.byteOffset + aadBytes.byteLength
    ) as ArrayBuffer;

    // Convert ciphertext to ArrayBuffer
    const ciphertextArrayBuffer = new Uint8Array(encrypted.ciphertext).buffer as ArrayBuffer;

    // Decrypt
    const plaintext = await recipient.open(ciphertextArrayBuffer, aadArrayBuffer);

    return Buffer.from(plaintext);
  } catch (err) {
    throw new DcpError(
      'DECRYPTION_FAILED',
      'HPKE decryption failed - invalid ciphertext, key, or AAD mismatch',
      { error: err instanceof Error ? err.message : String(err) }
    );
  }
}

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize encrypted message to a single buffer
 * Format: encapsulatedKey (32) || ciphertext (variable)
 */
export function serializeEncrypted(encrypted: EncryptedMessage): Buffer {
  return Buffer.concat([encrypted.ephemeralPublicKey, encrypted.ciphertext]);
}

/**
 * Deserialize encrypted message from buffer
 */
export function deserializeEncrypted(data: Buffer): EncryptedMessage {
  if (data.length < ENCAP_SIZE + MIN_CIPHERTEXT_SIZE) {
    throw new DcpError('DECRYPTION_FAILED', 'Encrypted data too short');
  }

  const ephemeralPublicKey = data.subarray(0, ENCAP_SIZE);
  const ciphertext = data.subarray(ENCAP_SIZE);

  return {
    ephemeralPublicKey: Buffer.from(ephemeralPublicKey),
    nonce: Buffer.alloc(0),
    ciphertext: Buffer.from(ciphertext),
  };
}

/**
 * Encode encrypted message to base64 for transport in JSON
 */
export function encodeToBase64(encrypted: EncryptedMessage): string {
  return serializeEncrypted(encrypted).toString('base64');
}

/**
 * Decode encrypted message from base64
 */
export function decodeFromBase64(base64: string): EncryptedMessage {
  const buffer = Buffer.from(base64, 'base64');
  return deserializeEncrypted(buffer);
}

// ============================================================================
// Key Utilities
// ============================================================================

/**
 * Encode public key to base64 for sharing
 */
export function encodePublicKey(publicKey: Buffer): string {
  return publicKey.toString('base64');
}

/**
 * Decode public key from base64
 */
export function decodePublicKey(base64: string): Buffer {
  const key = Buffer.from(base64, 'base64');
  if (key.length !== HPKE_KEY_SIZE) {
    throw new DcpError(
      'INVALID_CONFIG',
      `Invalid public key length: ${key.length}, expected ${HPKE_KEY_SIZE}`
    );
  }
  return key;
}

/**
 * Zeroize a buffer containing sensitive key material
 */
export function zeroize(buffer: Buffer): void {
  sodium.sodium_memzero(buffer);
}

// ============================================================================
// Ed25519 Signing (for service authentication)
// ============================================================================

/**
 * Generate Ed25519 signing keypair
 * Used for service authentication in relay mode
 */
export function generateSigningKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const publicKey = sodium.sodium_malloc(32);
  const privateKey = sodium.sodium_malloc(64);

  sodium.crypto_sign_keypair(publicKey, privateKey);

  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(privateKey),
  };
}

/**
 * Sign a message with Ed25519
 */
export function sign(message: Buffer, privateKey: Buffer): Buffer {
  if (privateKey.length !== 64) {
    throw new DcpError('ENCRYPTION_FAILED', 'Ed25519 private key must be 64 bytes');
  }

  const signature = sodium.sodium_malloc(64);
  sodium.crypto_sign_detached(signature, message, privateKey);

  return Buffer.from(signature);
}

/**
 * Verify an Ed25519 signature
 */
export function verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  if (publicKey.length !== 32) {
    return false;
  }
  if (signature.length !== 64) {
    return false;
  }

  try {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate random nonce
 */
export function generateNonce(size = 32): Buffer {
  const nonce = sodium.sodium_malloc(size);
  sodium.randombytes_buf(nonce);
  return Buffer.from(nonce);
}

/**
 * Generate a random request ID
 */
export function generateRequestId(): string {
  const bytes = generateNonce(16);
  return `req_${bytes.toString('hex')}`;
}
