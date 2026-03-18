/**
 * Tests for DCP Relay Client
 *
 * Tests RFC 9180 HPKE encryption, AAD binding, signed auth, and client connection
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  generateKeyPair,
  generateKeyPairSync,
  generateSigningKeyPair,
  encrypt,
  decrypt,
  constructAad,
  serializeEncrypted,
  deserializeEncrypted,
  encodeToBase64,
  decodeFromBase64,
  encodePublicKey,
  decodePublicKey,
  zeroize,
  sign,
  generateNonce,
  HPKE_KEY_SIZE,
  ClientError,
} from '../src/index.js';
import { RelayClient, createRelayClient } from '../src/client.js';
import { RelayServer } from '@dcprotocol/relay';
import type { EnvelopeAad } from '../src/types.js';

// Minimum ciphertext size (encap key + tag)
const MIN_CIPHERTEXT_SIZE = 32 + 16;

// ============================================================================
// HPKE Crypto Tests (RFC 9180)
// ============================================================================

describe('HPKE Cryptography (RFC 9180)', () => {
  describe('generateKeyPair', () => {
    it('should generate valid keypair (async)', async () => {
      const keyPair = await generateKeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Buffer);
      expect(keyPair.privateKey).toBeInstanceOf(Buffer);
      expect(keyPair.publicKey.length).toBe(HPKE_KEY_SIZE);
      expect(keyPair.privateKey.length).toBe(HPKE_KEY_SIZE);
    });

    it('should generate valid keypair (sync)', () => {
      const keyPair = generateKeyPairSync();

      expect(keyPair.publicKey).toBeInstanceOf(Buffer);
      expect(keyPair.privateKey).toBeInstanceOf(Buffer);
      expect(keyPair.publicKey.length).toBe(HPKE_KEY_SIZE);
      expect(keyPair.privateKey.length).toBe(HPKE_KEY_SIZE);
    });

    it('should generate unique keypairs', async () => {
      const keyPair1 = await generateKeyPair();
      const keyPair2 = await generateKeyPair();

      expect(keyPair1.publicKey.equals(keyPair2.publicKey)).toBe(false);
      expect(keyPair1.privateKey.equals(keyPair2.privateKey)).toBe(false);
    });
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt a message', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = await encrypt(plaintext, keyPair.publicKey);
      const decrypted = await decrypt(encrypted, keyPair.privateKey);

      expect(decrypted.toString()).toBe('Hello, World!');
    });

    it('should produce unique ciphertext each time (ephemeral keys)', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('Same message');

      const encrypted1 = await encrypt(plaintext, keyPair.publicKey);
      const encrypted2 = await encrypt(plaintext, keyPair.publicKey);

      // Different ephemeral keys means different ciphertext
      expect(encrypted1.ephemeralPublicKey.equals(encrypted2.ephemeralPublicKey)).toBe(false);
      expect(encrypted1.ciphertext.equals(encrypted2.ciphertext)).toBe(false);
    });

    it('should fail to decrypt with wrong key', async () => {
      const keyPair1 = await generateKeyPair();
      const keyPair2 = await generateKeyPair();
      const plaintext = Buffer.from('Secret message');

      const encrypted = await encrypt(plaintext, keyPair1.publicKey);

      await expect(decrypt(encrypted, keyPair2.privateKey)).rejects.toThrow(ClientError);
    });

    it('should fail with invalid public key size', async () => {
      const plaintext = Buffer.from('Test');
      const invalidKey = Buffer.alloc(16); // Wrong size

      await expect(encrypt(plaintext, invalidKey)).rejects.toThrow(ClientError);
    });

    it('should fail with invalid private key size', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('Test');
      const encrypted = await encrypt(plaintext, keyPair.publicKey);

      const invalidKey = Buffer.alloc(16); // Wrong size
      await expect(decrypt(encrypted, invalidKey)).rejects.toThrow(ClientError);
    });

    it('should handle empty plaintext', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.alloc(0);

      const encrypted = await encrypt(plaintext, keyPair.publicKey);
      const decrypted = await decrypt(encrypted, keyPair.privateKey);

      expect(decrypted.length).toBe(0);
    });

    it('should handle large plaintext', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.alloc(1024 * 100, 'x'); // 100KB

      const encrypted = await encrypt(plaintext, keyPair.publicKey);
      const decrypted = await decrypt(encrypted, keyPair.privateKey);

      expect(decrypted.equals(plaintext)).toBe(true);
    });
  });

  describe('AAD binding', () => {
    it('should encrypt and decrypt with matching AAD', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('AAD test');
      const aad: EnvelopeAad = {
        version: '1',
        vault_id: 'vault_123',
        request_id: 'req_456',
        action_type: 'sign',
      };

      const encrypted = await encrypt(plaintext, keyPair.publicKey, aad);
      const decrypted = await decrypt(encrypted, keyPair.privateKey, aad);

      expect(decrypted.toString()).toBe('AAD test');
    });

    it('should fail to decrypt with mismatched AAD', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('AAD test');
      const aad1: EnvelopeAad = {
        version: '1',
        vault_id: 'vault_123',
        request_id: 'req_456',
        action_type: 'sign',
      };
      const aad2: EnvelopeAad = {
        version: '1',
        vault_id: 'vault_different', // Different vault_id
        request_id: 'req_456',
        action_type: 'sign',
      };

      const encrypted = await encrypt(plaintext, keyPair.publicKey, aad1);
      await expect(decrypt(encrypted, keyPair.privateKey, aad2)).rejects.toThrow(ClientError);
    });

    it('should fail to decrypt with AAD when encrypted without AAD', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('No AAD');
      const aad: EnvelopeAad = {
        version: '1',
        vault_id: 'vault_123',
        request_id: 'req_456',
        action_type: 'sign',
      };

      const encrypted = await encrypt(plaintext, keyPair.publicKey); // No AAD
      await expect(decrypt(encrypted, keyPair.privateKey, aad)).rejects.toThrow(ClientError);
    });

    it('should construct AAD correctly', () => {
      const aad: EnvelopeAad = {
        version: '1',
        vault_id: 'vault_abc',
        request_id: 'req_xyz',
        action_type: 'read',
      };

      const constructed = constructAad(aad);
      const expected = new TextEncoder().encode('1|vault_abc|req_xyz|read');

      expect(Buffer.from(constructed).equals(Buffer.from(expected))).toBe(true);
    });
  });

  describe('serialization', () => {
    it('should serialize and deserialize encrypted message', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('Test message');

      const encrypted = await encrypt(plaintext, keyPair.publicKey);
      const serialized = serializeEncrypted(encrypted);
      const deserialized = deserializeEncrypted(serialized);

      expect(deserialized.ephemeralPublicKey.equals(encrypted.ephemeralPublicKey)).toBe(true);
      expect(deserialized.ciphertext.equals(encrypted.ciphertext)).toBe(true);
    });

    it('should encode and decode as base64', async () => {
      const keyPair = await generateKeyPair();
      const plaintext = Buffer.from('Base64 test');

      const encrypted = await encrypt(plaintext, keyPair.publicKey);
      const base64 = encodeToBase64(encrypted);
      const decoded = decodeFromBase64(base64);

      expect(decoded.ephemeralPublicKey.equals(encrypted.ephemeralPublicKey)).toBe(true);
      expect(decoded.ciphertext.equals(encrypted.ciphertext)).toBe(true);

      // Can still decrypt
      const decrypted = await decrypt(decoded, keyPair.privateKey);
      expect(decrypted.toString()).toBe('Base64 test');
    });

    it('should reject too-short serialized data', () => {
      const tooShort = Buffer.alloc(MIN_CIPHERTEXT_SIZE - 1);
      expect(() => deserializeEncrypted(tooShort)).toThrow(ClientError);
    });
  });

  describe('key utilities', () => {
    it('should encode and decode public key', async () => {
      const keyPair = await generateKeyPair();
      const encoded = encodePublicKey(keyPair.publicKey);
      const decoded = decodePublicKey(encoded);

      expect(decoded.equals(keyPair.publicKey)).toBe(true);
    });

    it('should reject invalid public key length', () => {
      const invalidBase64 = Buffer.alloc(16).toString('base64');
      expect(() => decodePublicKey(invalidBase64)).toThrow(ClientError);
    });
  });

  describe('zeroize', () => {
    it('should zero out buffer contents', () => {
      const buffer = Buffer.from('sensitive data');
      const originalContent = Buffer.from(buffer);

      zeroize(buffer);

      expect(buffer.every((b) => b === 0)).toBe(true);
      expect(buffer.equals(originalContent)).toBe(false);
    });
  });
});

// ============================================================================
// Signing Tests
// ============================================================================

describe('Ed25519 Signing', () => {
  it('should generate signing keypair', () => {
    const keyPair = generateSigningKeyPair();

    expect(keyPair.publicKey).toBeInstanceOf(Buffer);
    expect(keyPair.privateKey).toBeInstanceOf(Buffer);
    expect(keyPair.publicKey.length).toBe(32);
    expect(keyPair.privateKey.length).toBe(64);
  });

  it('should sign messages', () => {
    const keyPair = generateSigningKeyPair();
    const message = Buffer.from('Test message to sign');

    const signature = sign(message, keyPair.privateKey);

    expect(signature).toBeInstanceOf(Buffer);
    expect(signature.length).toBe(64);
  });

  it('should generate unique nonces', () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    expect(nonce1.length).toBe(32);
    expect(nonce2.length).toBe(32);
    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it('should fail to sign with invalid key size', () => {
    const invalidKey = Buffer.alloc(32); // Wrong size for Ed25519 private key
    const message = Buffer.from('Test');

    expect(() => sign(message, invalidKey)).toThrow(ClientError);
  });
});

// ============================================================================
// RelayClient Tests
// ============================================================================

describe('RelayClient', () => {
  let server: RelayServer;
  let testPort: number;

  beforeAll(async () => {
    testPort = 19421 + Math.floor(Math.random() * 10000);
    server = new RelayServer({
      port: testPort,
      host: '127.0.0.1',
      debug: false,
      enableLongPoll: true,
      authConfig: { requirePairingToken: false }, // Don't require token for tests
    });
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  describe('createRelayClient', () => {
    it('should create client with factory function', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = createRelayClient(
        `ws://127.0.0.1:${testPort}`,
        'vault_factory_test',
        keyPair,
        signingKeyPair
      );

      expect(client).toBeInstanceOf(RelayClient);
      expect(client.getState()).toBe('disconnected');

      client.destroy();
    });
  });

  describe('connection', () => {
    it('should connect to relay server with signed auth', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_connect_test',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      let connected = false;
      client.on('connected', () => {
        connected = true;
      });

      await client.connect();

      expect(client.getState()).toBe('connected');
      expect(client.isConnected()).toBe(true);
      expect(connected).toBe(true);

      client.disconnect();
      expect(client.getState()).toBe('disconnected');
    });

    it('should throw when connecting twice', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_double_connect',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      await client.connect();

      await expect(client.connect()).rejects.toThrow(ClientError);

      client.disconnect();
    });

    it('should handle connection failure gracefully', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: 'ws://127.0.0.1:59999', // Invalid port
        vaultId: 'vault_fail',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      await expect(client.connect()).rejects.toThrow(ClientError);
    });
  });

  describe('public key', () => {
    it('should return encoded public key', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_pubkey',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      const publicKey = client.getPublicKey();
      expect(typeof publicKey).toBe('string');
      expect(publicKey.length).toBeGreaterThan(0);

      // Should be valid base64
      const decoded = decodePublicKey(publicKey);
      expect(decoded.equals(keyPair.publicKey)).toBe(true);
    });

    it('should return encoded signing public key', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_signing_pubkey',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      const signingPubKey = client.getSigningPublicKey();
      expect(typeof signingPubKey).toBe('string');
      expect(signingPubKey.length).toBeGreaterThan(0);

      const decoded = Buffer.from(signingPubKey, 'base64');
      expect(decoded.equals(signingKeyPair.publicKey)).toBe(true);
    });
  });

  describe('encryption/decryption', () => {
    it('should encrypt and decrypt payloads', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_crypto',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      const payload = Buffer.from(JSON.stringify({ action: 'test', data: 'secret' }));
      const encrypted = await client.encryptPayload(payload, keyPair.publicKey);
      const decrypted = await client.decryptPayload(encrypted);

      expect(decrypted.toString()).toBe(payload.toString());
    });

    it('should encrypt and decrypt payloads with AAD', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_crypto_aad',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      const payload = Buffer.from('Secure payload');
      const aad: EnvelopeAad = {
        version: '1',
        vault_id: 'vault_crypto_aad',
        request_id: 'req_test',
        action_type: 'sign',
      };

      const encrypted = await client.encryptPayload(payload, keyPair.publicKey, aad);
      const decrypted = await client.decryptPayload(encrypted, aad);

      expect(decrypted.toString()).toBe('Secure payload');
    });
  });

  describe('destroy', () => {
    it('should cleanup resources on destroy', async () => {
      const keyPair = await generateKeyPair();
      const signingKeyPair = generateSigningKeyPair();
      const client = new RelayClient({
        relayUrl: `ws://127.0.0.1:${testPort}`,
        vaultId: 'vault_destroy',
        keyPair,
        signingKeyPair,
        autoReconnect: false,
      });

      await client.connect();
      client.destroy();

      expect(client.getState()).toBe('disconnected');
    });
  });
});

// ============================================================================
// ClientError Tests
// ============================================================================

describe('ClientError', () => {
  it('should create error with correct properties', () => {
    const error = new ClientError('CLIENT_CONNECTION_FAILED', 'Connection failed', { host: 'localhost' });

    expect(error.code).toBe('CLIENT_CONNECTION_FAILED');
    expect(error.message).toBe('Connection failed');
    expect(error.details?.host).toBe('localhost');
    expect(error.name).toBe('ClientError');
  });

  it('should serialize to JSON correctly', () => {
    const error = new ClientError('CLIENT_NOT_CONNECTED', 'Not connected');
    const json = error.toJSON();

    expect(json.error.code).toBe('CLIENT_NOT_CONNECTED');
    expect(json.error.message).toBe('Not connected');
  });
});
