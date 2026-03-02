/**
 * Tests for Crypto Engine
 *
 * These tests verify:
 * - Key generation produces correct sizes
 * - Encryption/decryption roundtrip works
 * - Envelope encryption works
 * - Argon2id key derivation is deterministic
 * - Memory zeroization works
 * - Tampered data is rejected
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKey,
  generateNonce,
  generateSalt,
  deriveKeyFromPassphrase,
  encrypt,
  decrypt,
  envelopeEncrypt,
  envelopeDecrypt,
  zeroize,
  verifyCryptoReady,
  KEY_SIZE,
  NONCE_SIZE,
} from '../src/crypto.js';
import { VaultError } from '../src/types.js';

describe('Crypto Engine', () => {
  beforeAll(() => {
    // Verify sodium-native is ready
    expect(verifyCryptoReady()).toBe(true);
  });

  describe('Key Generation', () => {
    it('should generate 256-bit (32 byte) keys', () => {
      const key = generateKey();
      expect(key.length).toBe(KEY_SIZE);
      expect(key.length).toBe(32);
      zeroize(key);
    });

    it('should generate 192-bit (24 byte) nonces', () => {
      const nonce = generateNonce();
      expect(nonce.length).toBe(NONCE_SIZE);
      expect(nonce.length).toBe(24);
    });

    it('should generate 16-byte salts', () => {
      const salt = generateSalt();
      expect(salt.length).toBe(16);
    });

    it('should generate unique keys each time', () => {
      const key1 = generateKey();
      const key2 = generateKey();
      expect(key1.equals(key2)).toBe(false);
      zeroize(key1);
      zeroize(key2);
    });

    it('should generate unique nonces each time', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1.equals(nonce2)).toBe(false);
    });
  });

  describe('Argon2id Key Derivation', () => {
    it('should derive consistent key from same passphrase and salt', () => {
      const passphrase = 'test-passphrase-123';
      const salt = generateSalt();

      const key1 = deriveKeyFromPassphrase(passphrase, salt);
      const key2 = deriveKeyFromPassphrase(passphrase, salt);

      expect(key1.equals(key2)).toBe(true);
      expect(key1.length).toBe(KEY_SIZE);

      zeroize(key1);
      zeroize(key2);
    });

    it('should derive different keys for different salts', () => {
      const passphrase = 'test-passphrase-123';
      const salt1 = generateSalt();
      const salt2 = generateSalt();

      const key1 = deriveKeyFromPassphrase(passphrase, salt1);
      const key2 = deriveKeyFromPassphrase(passphrase, salt2);

      expect(key1.equals(key2)).toBe(false);

      zeroize(key1);
      zeroize(key2);
    });

    it('should derive different keys for different passphrases', () => {
      const salt = generateSalt();

      const key1 = deriveKeyFromPassphrase('passphrase-1', salt);
      const key2 = deriveKeyFromPassphrase('passphrase-2', salt);

      expect(key1.equals(key2)).toBe(false);

      zeroize(key1);
      zeroize(key2);
    });

    it('should reject invalid salt size', () => {
      const invalidSalt = Buffer.from('too-short');
      expect(() => deriveKeyFromPassphrase('test', invalidSalt)).toThrow(VaultError);
    });
  });

  describe('XChaCha20-Poly1305 Encryption', () => {
    it('should encrypt and decrypt successfully', () => {
      const key = generateKey();
      const plaintext = Buffer.from('Hello, DCP Vault!');

      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);

      expect(decrypted.equals(plaintext)).toBe(true);

      zeroize(key);
      zeroize(decrypted);
    });

    it('should produce ciphertext longer than plaintext (includes auth tag)', () => {
      const key = generateKey();
      const plaintext = Buffer.from('test data');

      const { ciphertext } = encrypt(plaintext, key);

      // Ciphertext should be plaintext + 16 byte auth tag
      expect(ciphertext.length).toBe(plaintext.length + 16);

      zeroize(key);
    });

    it('should encrypt empty buffer', () => {
      const key = generateKey();
      const plaintext = Buffer.alloc(0);

      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);

      expect(decrypted.length).toBe(0);

      zeroize(key);
    });

    it('should encrypt large data', () => {
      const key = generateKey();
      const plaintext = Buffer.alloc(1024 * 1024, 0xab); // 1MB

      const { ciphertext, nonce } = encrypt(plaintext, key);
      const decrypted = decrypt(ciphertext, nonce, key);

      expect(decrypted.equals(plaintext)).toBe(true);

      zeroize(key);
      zeroize(decrypted);
    });

    it('should reject tampered ciphertext', () => {
      const key = generateKey();
      const plaintext = Buffer.from('sensitive data');

      const { ciphertext, nonce } = encrypt(plaintext, key);

      // Tamper with ciphertext
      ciphertext[0] ^= 0xff;

      expect(() => decrypt(ciphertext, nonce, key)).toThrow(VaultError);

      zeroize(key);
    });

    it('should reject wrong key', () => {
      const key1 = generateKey();
      const key2 = generateKey();
      const plaintext = Buffer.from('secret');

      const { ciphertext, nonce } = encrypt(plaintext, key1);

      expect(() => decrypt(ciphertext, nonce, key2)).toThrow(VaultError);

      zeroize(key1);
      zeroize(key2);
    });

    it('should reject wrong nonce', () => {
      const key = generateKey();
      const plaintext = Buffer.from('secret');

      const { ciphertext } = encrypt(plaintext, key);
      const wrongNonce = generateNonce();

      expect(() => decrypt(ciphertext, wrongNonce, key)).toThrow(VaultError);

      zeroize(key);
    });

    it('should support associated data', () => {
      const key = generateKey();
      const plaintext = Buffer.from('secret message');
      const associatedData = Buffer.from('metadata');

      const { ciphertext, nonce } = encrypt(plaintext, key, associatedData);
      const decrypted = decrypt(ciphertext, nonce, key, associatedData);

      expect(decrypted.equals(plaintext)).toBe(true);

      zeroize(key);
      zeroize(decrypted);
    });

    it('should reject if associated data is wrong', () => {
      const key = generateKey();
      const plaintext = Buffer.from('secret');
      const ad1 = Buffer.from('correct');
      const ad2 = Buffer.from('wrong');

      const { ciphertext, nonce } = encrypt(plaintext, key, ad1);

      expect(() => decrypt(ciphertext, nonce, key, ad2)).toThrow(VaultError);

      zeroize(key);
    });
  });

  describe('Envelope Encryption', () => {
    it('should encrypt and decrypt with envelope encryption', () => {
      const masterKey = generateKey();
      const plaintext = Buffer.from('private key data');

      const payload = envelopeEncrypt(plaintext, masterKey);
      const decrypted = envelopeDecrypt(payload, masterKey);

      expect(decrypted.equals(plaintext)).toBe(true);

      zeroize(masterKey);
      zeroize(decrypted);
    });

    it('should produce different ciphertext for same plaintext (unique DEK)', () => {
      const masterKey = generateKey();
      const plaintext = Buffer.from('same data');

      const payload1 = envelopeEncrypt(plaintext, masterKey);
      const payload2 = envelopeEncrypt(plaintext, masterKey);

      // DEK is different, so wrapped DEK and ciphertext should differ
      expect(payload1.ciphertext.equals(payload2.ciphertext)).toBe(false);
      expect(payload1.dek_wrapped.equals(payload2.dek_wrapped)).toBe(false);

      zeroize(masterKey);
    });

    it('should fail with wrong master key', () => {
      const masterKey1 = generateKey();
      const masterKey2 = generateKey();
      const plaintext = Buffer.from('secret');

      const payload = envelopeEncrypt(plaintext, masterKey1);

      expect(() => envelopeDecrypt(payload, masterKey2)).toThrow(VaultError);

      zeroize(masterKey1);
      zeroize(masterKey2);
    });

    it('should fail if payload is tampered', () => {
      const masterKey = generateKey();
      const plaintext = Buffer.from('secret');

      const payload = envelopeEncrypt(plaintext, masterKey);

      // Tamper with ciphertext
      payload.ciphertext[0] ^= 0xff;

      expect(() => envelopeDecrypt(payload, masterKey)).toThrow(VaultError);

      zeroize(masterKey);
    });

    it('should handle private key sized data (32 bytes)', () => {
      const masterKey = generateKey();
      const privateKey = generateKey(); // 32 bytes, same as a real private key

      const payload = envelopeEncrypt(privateKey, masterKey);
      const decrypted = envelopeDecrypt(payload, masterKey);

      expect(decrypted.equals(privateKey)).toBe(true);

      zeroize(masterKey);
      zeroize(privateKey);
      zeroize(decrypted);
    });
  });

  describe('Memory Zeroization', () => {
    it('should zeroize buffer contents', () => {
      const buffer = Buffer.from('sensitive data');
      const originalContent = Buffer.from(buffer);

      zeroize(buffer);

      // Buffer should now be all zeros
      expect(buffer.every((byte) => byte === 0)).toBe(true);
      expect(buffer.equals(originalContent)).toBe(false);
    });

    it('should handle empty buffer', () => {
      const buffer = Buffer.alloc(0);
      expect(() => zeroize(buffer)).not.toThrow();
    });

    it('should handle null/undefined gracefully', () => {
      expect(() => zeroize(null as unknown as Buffer)).not.toThrow();
      expect(() => zeroize(undefined as unknown as Buffer)).not.toThrow();
    });
  });

  describe('verifyCryptoReady', () => {
    it('should return true when crypto is ready', () => {
      expect(verifyCryptoReady()).toBe(true);
    });
  });
});
