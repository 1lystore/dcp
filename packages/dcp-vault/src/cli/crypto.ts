/**
 * CLI Crypto Utilities
 *
 * HPKE key generation and Ed25519 signature verification
 * for the DCP CLI.
 */

import * as crypto from 'crypto';

// ============================================================================
// HPKE Key Generation (X25519)
// ============================================================================

/**
 * Generate an HPKE X25519 keypair for relay encryption
 *
 * @returns { publicKey, privateKey } as Buffers
 */
export function generateHpkeKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  // Generate X25519 keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  // Extract raw keys from DER encoding
  // X25519 public key in SPKI: last 32 bytes
  // X25519 private key in PKCS8: last 32 bytes
  const rawPublicKey = publicKey.slice(-32);
  const rawPrivateKey = privateKey.slice(-32);

  return {
    publicKey: rawPublicKey,
    privateKey: rawPrivateKey,
  };
}

// ============================================================================
// Ed25519 Signature Verification
// ============================================================================

/**
 * Verify an Ed25519 signature
 *
 * @param message - Message that was signed
 * @param signature - Signature to verify (base64)
 * @param publicKey - Ed25519 public key (base64 or ed25519:base64)
 * @returns true if signature is valid
 */
export function verifyEd25519Signature(
  message: Buffer,
  signature: Buffer,
  publicKey: string
): boolean {
  // Parse public key
  let keyData: Buffer;
  if (publicKey.startsWith('ed25519:')) {
    keyData = Buffer.from(publicKey.slice(8), 'base64');
  } else {
    keyData = Buffer.from(publicKey, 'base64');
  }

  // Create key object
  const key = crypto.createPublicKey({
    key: Buffer.concat([
      // Ed25519 public key SPKI header
      Buffer.from('302a300506032b6570032100', 'hex'),
      keyData,
    ]),
    format: 'der',
    type: 'spki',
  });

  // Verify signature
  return crypto.verify(null, message, key, signature);
}

/**
 * Sign a message with Ed25519
 *
 * @param message - Message to sign
 * @param privateKey - Ed25519 private key (base64)
 * @returns Signature as Buffer
 */
export function signEd25519(message: Buffer, privateKey: Buffer): Buffer {
  // Create key object
  const key = crypto.createPrivateKey({
    key: Buffer.concat([
      // Ed25519 private key PKCS8 header
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      privateKey,
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  return crypto.sign(null, message, key);
}

/**
 * Generate an Ed25519 keypair
 *
 * @returns { publicKey, privateKey } as Buffers
 */
export function generateEd25519KeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  // Extract raw keys
  const rawPublicKey = publicKey.slice(-32);
  const rawPrivateKey = privateKey.slice(-32);

  return {
    publicKey: rawPublicKey,
    privateKey: rawPrivateKey,
  };
}
