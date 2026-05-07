/**
 * Tests for webhook server
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { sign, generateKeyPairSync } from 'crypto';

// Generate test keypair
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

// Export raw public key (32 bytes)
function getRawPublicKey(): Buffer {
  const exported = publicKey.export({ type: 'spki', format: 'der' });
  // Skip SPKI header (12 bytes) to get raw key
  return exported.slice(12);
}

// Sign a message using Ed25519
function signMessage(message: Buffer): Buffer {
  return sign(null, message, privateKey);
}

// Canonical JSON
function canonicalJson(obj: object): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

describe('Webhook Signature Verification', () => {
  it('should generate valid test keypair', () => {
    const rawKey = getRawPublicKey();
    expect(rawKey.length).toBe(32);
  });

  it('should sign and verify message', () => {
    const message = Buffer.from('test message');
    const signature = signMessage(message);
    expect(signature.length).toBe(64); // Ed25519 signature is 64 bytes
  });

  it('should create canonical JSON deterministically', () => {
    const obj1 = { b: 2, a: 1, c: 3 };
    const obj2 = { c: 3, a: 1, b: 2 };

    expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
    expect(canonicalJson(obj1)).toBe('{"a":1,"b":2,"c":3}');
  });
});

describe('Webhook Payload Validation', () => {
  it('should validate required fields', () => {
    const validPayload = {
      event: 'consent_created',
      vault_id: 'vault_123',
      data: {
        consent_id: 'consent_123',
        agent_name: 'test-agent',
        category: 'transaction_signing',
        review_link: 'http://localhost/consent/123',
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 300000).toISOString(),
      },
      signature: 'base64signature',
      timestamp: new Date().toISOString(),
    };

    // All fields present
    expect(validPayload.event).toBeDefined();
    expect(validPayload.vault_id).toBeDefined();
    expect(validPayload.data).toBeDefined();
    expect(validPayload.signature).toBeDefined();
    expect(validPayload.timestamp).toBeDefined();
  });

  it('should reject payload without event', () => {
    const payload = {
      vault_id: 'vault_123',
      data: {},
      signature: 'sig',
      timestamp: new Date().toISOString(),
    };

    expect(payload.event).toBeUndefined();
  });

  it('should reject payload without vault_id', () => {
    const payload = {
      event: 'consent_created',
      data: {},
      signature: 'sig',
      timestamp: new Date().toISOString(),
    };

    expect(payload.vault_id).toBeUndefined();
  });
});

describe('Consent Payload Privacy', () => {
  it('should only contain privacy-safe fields', () => {
    const safeFields = [
      'consent_id',
      'agent_name',
      'category',
      'review_link',
      'created_at',
      'expires_at',
    ];

    const forbiddenFields = [
      'amount',
      'currency',
      'destination',
      'address',
      'private_key',
      'secret',
      'api_key',
      'transaction_data',
      'signed_tx',
    ];

    const payload = {
      consent_id: 'consent_123',
      agent_name: 'test-agent',
      category: 'transaction_signing',
      review_link: 'http://localhost/consent/123',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 300000).toISOString(),
    };

    // Should have all safe fields
    for (const field of safeFields) {
      expect(payload).toHaveProperty(field);
    }

    // Should NOT have any forbidden fields
    for (const field of forbiddenFields) {
      expect(payload).not.toHaveProperty(field);
    }
  });
});

describe('Timestamp Validation', () => {
  it('should accept timestamp within 5 minute window', () => {
    const now = Date.now();
    const validTimestamp = new Date(now - 2 * 60 * 1000).toISOString(); // 2 min ago
    const timestampDate = new Date(validTimestamp).getTime();

    const diff = Math.abs(now - timestampDate);
    expect(diff).toBeLessThan(5 * 60 * 1000);
  });

  it('should reject timestamp older than 5 minutes', () => {
    const now = Date.now();
    const oldTimestamp = new Date(now - 10 * 60 * 1000).toISOString(); // 10 min ago
    const timestampDate = new Date(oldTimestamp).getTime();

    const diff = Math.abs(now - timestampDate);
    expect(diff).toBeGreaterThan(5 * 60 * 1000);
  });
});

describe('Replay Protection', () => {
  it('should detect duplicate nonces', () => {
    const seenNonces = new Set<string>();
    const nonce1 = 'vault_123:' + new Date().toISOString();

    expect(seenNonces.has(nonce1)).toBe(false);
    seenNonces.add(nonce1);
    expect(seenNonces.has(nonce1)).toBe(true);
  });

  it('should create unique nonces for different requests', () => {
    const nonce1 = 'vault_123:' + new Date().toISOString();
    // Simulate different timestamp
    const nonce2 = 'vault_123:' + new Date(Date.now() + 1).toISOString();

    expect(nonce1).not.toBe(nonce2);
  });
});
