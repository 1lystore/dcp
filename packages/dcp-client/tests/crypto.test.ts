/**
 * HPKE Crypto Tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  generateKeyPairSync,
  encrypt,
  decrypt,
  encodeToBase64,
  decodeFromBase64,
  encodePublicKey,
  decodePublicKey,
  constructAad,
  sign,
  verify,
  generateSigningKeyPair,
  generateNonce,
  generateRequestId,
  zeroize,
  HPKE_KEY_SIZE,
} from '../src/crypto.js';
import type { EnvelopeAad } from '../src/types.js';
import { DcpError } from '../src/errors.js';

describe('HPKE Key Generation', () => {
  it('should generate valid async keypair', async () => {
    const keyPair = await generateKeyPair();

    expect(keyPair.publicKey).toBeInstanceOf(Buffer);
    expect(keyPair.privateKey).toBeInstanceOf(Buffer);
    expect(keyPair.publicKey.length).toBe(HPKE_KEY_SIZE);
    expect(keyPair.privateKey.length).toBe(HPKE_KEY_SIZE);
  });

  it('should generate valid sync keypair', () => {
    const keyPair = generateKeyPairSync();

    expect(keyPair.publicKey).toBeInstanceOf(Buffer);
    expect(keyPair.privateKey).toBeInstanceOf(Buffer);
    expect(keyPair.publicKey.length).toBe(HPKE_KEY_SIZE);
    expect(keyPair.privateKey.length).toBe(HPKE_KEY_SIZE);
  });

  it('should generate unique keypairs', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    expect(kp1.publicKey.equals(kp2.publicKey)).toBe(false);
    expect(kp1.privateKey.equals(kp2.privateKey)).toBe(false);
  });
});

describe('HPKE Encryption/Decryption', () => {
  it('should encrypt and decrypt a message', async () => {
    const keyPair = await generateKeyPair();
    const plaintext = Buffer.from('Hello, DCP!');

    const encrypted = await encrypt(plaintext, keyPair.publicKey);
    const decrypted = await decrypt(encrypted, keyPair.privateKey);

    expect(decrypted.toString()).toBe('Hello, DCP!');
  });

  it('should encrypt and decrypt with AAD', async () => {
    const keyPair = await generateKeyPair();
    const plaintext = Buffer.from('Sensitive data');
    const aad: EnvelopeAad = {
      version: '1',
      vault_id: 'vault_123',
      request_id: 'req_456',
      action_type: 'sign',
    };

    const encrypted = await encrypt(plaintext, keyPair.publicKey, aad);
    const decrypted = await decrypt(encrypted, keyPair.privateKey, aad);

    expect(decrypted.toString()).toBe('Sensitive data');
  });

  it('should fail to decrypt with wrong AAD', async () => {
    const keyPair = await generateKeyPair();
    const plaintext = Buffer.from('Sensitive data');
    const aad1: EnvelopeAad = {
      version: '1',
      vault_id: 'vault_123',
      request_id: 'req_456',
      action_type: 'sign',
    };
    const aad2: EnvelopeAad = {
      version: '1',
      vault_id: 'vault_123',
      request_id: 'req_789', // Different request_id
      action_type: 'sign',
    };

    const encrypted = await encrypt(plaintext, keyPair.publicKey, aad1);

    await expect(decrypt(encrypted, keyPair.privateKey, aad2)).rejects.toThrow(DcpError);
  });

  it('should fail to decrypt with wrong private key', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();
    const plaintext = Buffer.from('Secret');

    const encrypted = await encrypt(plaintext, keyPair1.publicKey);

    await expect(decrypt(encrypted, keyPair2.privateKey)).rejects.toThrow(DcpError);
  });

  it('should handle large messages', async () => {
    const keyPair = await generateKeyPair();
    const plaintext = Buffer.alloc(1024 * 100, 'a'); // 100KB

    const encrypted = await encrypt(plaintext, keyPair.publicKey);
    const decrypted = await decrypt(encrypted, keyPair.privateKey);

    expect(decrypted.length).toBe(plaintext.length);
    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('should reject invalid public key size', async () => {
    const plaintext = Buffer.from('Test');
    const invalidKey = Buffer.alloc(16); // Wrong size

    await expect(encrypt(plaintext, invalidKey)).rejects.toThrow(DcpError);
  });

  it('should reject invalid private key size', async () => {
    const keyPair = await generateKeyPair();
    const plaintext = Buffer.from('Test');
    const encrypted = await encrypt(plaintext, keyPair.publicKey);

    const invalidKey = Buffer.alloc(16); // Wrong size

    await expect(decrypt(encrypted, invalidKey)).rejects.toThrow(DcpError);
  });
});

describe('Serialization', () => {
  it('should serialize and deserialize encrypted message', async () => {
    const keyPair = await generateKeyPair();
    const plaintext = Buffer.from('Test message');

    const encrypted = await encrypt(plaintext, keyPair.publicKey);
    const base64 = encodeToBase64(encrypted);
    const decoded = decodeFromBase64(base64);

    expect(decoded.ephemeralPublicKey.equals(encrypted.ephemeralPublicKey)).toBe(true);
    expect(decoded.ciphertext.equals(encrypted.ciphertext)).toBe(true);

    // Should still decrypt correctly
    const decrypted = await decrypt(decoded, keyPair.privateKey);
    expect(decrypted.toString()).toBe('Test message');
  });

  it('should encode and decode public key', () => {
    const keyPair = generateKeyPairSync();
    const encoded = encodePublicKey(keyPair.publicKey);
    const decoded = decodePublicKey(encoded);

    expect(decoded.equals(keyPair.publicKey)).toBe(true);
  });

  it('should reject invalid public key length on decode', () => {
    const invalidBase64 = Buffer.alloc(16).toString('base64');

    expect(() => decodePublicKey(invalidBase64)).toThrow(DcpError);
  });
});

describe('AAD Construction', () => {
  it('should construct AAD from envelope metadata', () => {
    const aad: EnvelopeAad = {
      version: '1',
      vault_id: 'vault_abc123',
      request_id: 'req_xyz789',
      action_type: 'sign',
    };

    const result = constructAad(aad);

    // AAD format: version|vault_id|request_id|action_type
    const expected = '1|vault_abc123|req_xyz789|sign';
    expect(new TextDecoder().decode(result)).toBe(expected);
  });
});

describe('Ed25519 Signing', () => {
  it('should generate valid signing keypair', () => {
    const keyPair = generateSigningKeyPair();

    expect(keyPair.publicKey.length).toBe(32);
    expect(keyPair.privateKey.length).toBe(64);
  });

  it('should sign and verify a message', () => {
    const keyPair = generateSigningKeyPair();
    const message = Buffer.from('Sign this message');

    const signature = sign(message, keyPair.privateKey);

    expect(signature.length).toBe(64);
    expect(verify(message, signature, keyPair.publicKey)).toBe(true);
  });

  it('should fail to verify with wrong message', () => {
    const keyPair = generateSigningKeyPair();
    const message1 = Buffer.from('Original message');
    const message2 = Buffer.from('Modified message');

    const signature = sign(message1, keyPair.privateKey);

    expect(verify(message2, signature, keyPair.publicKey)).toBe(false);
  });

  it('should fail to verify with wrong public key', () => {
    const keyPair1 = generateSigningKeyPair();
    const keyPair2 = generateSigningKeyPair();
    const message = Buffer.from('Test message');

    const signature = sign(message, keyPair1.privateKey);

    expect(verify(message, signature, keyPair2.publicKey)).toBe(false);
  });

  it('should reject invalid private key size for signing', () => {
    const invalidKey = Buffer.alloc(32); // Wrong size
    const message = Buffer.from('Test');

    expect(() => sign(message, invalidKey)).toThrow(DcpError);
  });
});

describe('Utility Functions', () => {
  it('should generate random nonce of specified size', () => {
    const nonce = generateNonce(32);
    expect(nonce.length).toBe(32);

    const nonce16 = generateNonce(16);
    expect(nonce16.length).toBe(16);
  });

  it('should generate unique nonces', () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    expect(nonce1.equals(nonce2)).toBe(false);
  });

  it('should generate valid request ID', () => {
    const id = generateRequestId();

    expect(id.startsWith('req_')).toBe(true);
    expect(id.length).toBeGreaterThan(10);
  });

  it('should generate unique request IDs', () => {
    const id1 = generateRequestId();
    const id2 = generateRequestId();

    expect(id1).not.toBe(id2);
  });

  it('should zeroize buffer', () => {
    const buffer = Buffer.from('sensitive data');
    const originalLength = buffer.length;

    zeroize(buffer);

    // Buffer should still have same length but be all zeros
    expect(buffer.length).toBe(originalLength);
    expect(buffer.every((b) => b === 0)).toBe(true);
  });
});

describe('End-to-End Relay Encryption', () => {
  it('should simulate full relay encryption flow', async () => {
    // Vault's long-term keypair
    const vaultKeyPair = await generateKeyPair();

    // Client generates ephemeral reply keypair for each request
    const replyKeyPair = await generateKeyPair();

    // Request envelope metadata
    const requestAad: EnvelopeAad = {
      version: '1',
      vault_id: 'vault_test123',
      request_id: 'req_abc789',
      action_type: 'sign',
    };

    // Client creates request payload
    const requestPayload = JSON.stringify({
      method: 'vault_sign',
      params: { chain: 'solana', unsigned_tx: 'base64tx...' },
      agent_name: 'test-agent',
      reply_public_key: replyKeyPair.publicKey.toString('base64'),
    });

    // Client encrypts request to vault's public key
    const encryptedRequest = await encrypt(
      Buffer.from(requestPayload),
      vaultKeyPair.publicKey,
      requestAad
    );

    // Serialize for transport
    const transportPayload = encodeToBase64(encryptedRequest);

    // --- Relay forwards to vault ---

    // Vault decrypts request
    const receivedEncrypted = decodeFromBase64(transportPayload);
    const decryptedRequest = await decrypt(receivedEncrypted, vaultKeyPair.privateKey, requestAad);
    const parsedRequest = JSON.parse(decryptedRequest.toString());

    expect(parsedRequest.method).toBe('vault_sign');
    expect(parsedRequest.agent_name).toBe('test-agent');

    // Vault extracts reply public key
    const clientReplyKey = Buffer.from(parsedRequest.reply_public_key, 'base64');

    // Vault creates response
    const responsePayload = JSON.stringify({
      signed_tx: 'base64signedtx...',
      signature: 'sig123',
      chain: 'solana',
    });

    // Vault encrypts response to client's reply key
    const encryptedResponse = await encrypt(
      Buffer.from(responsePayload),
      clientReplyKey,
      requestAad // Same AAD binds response to request
    );

    const responseTransport = encodeToBase64(encryptedResponse);

    // --- Relay forwards to client ---

    // Client decrypts response with reply private key
    const receivedResponse = decodeFromBase64(responseTransport);
    const decryptedResponse = await decrypt(receivedResponse, replyKeyPair.privateKey, requestAad);
    const parsedResponse = JSON.parse(decryptedResponse.toString());

    expect(parsedResponse.signed_tx).toBe('base64signedtx...');
    expect(parsedResponse.signature).toBe('sig123');

    // Clean up sensitive keys
    zeroize(replyKeyPair.privateKey);
    zeroize(vaultKeyPair.privateKey);
  });
});
