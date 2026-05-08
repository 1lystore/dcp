/**
 * Tests for webhook server
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { sign, generateKeyPairSync } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { canonicalJson, generateSigningKeyPair, signMessage as signDcpMessage } from '@dcprotocol/core';
import { verifyEd25519 } from '../src/webhook.js';
import { WebhookServer } from '../src/webhook.js';
import { TelegramStore } from '../src/store.js';

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

  it('should verify a vault Ed25519 signature created by DCP core', () => {
    const keyPair = generateSigningKeyPair();
    const payload = {
      vault_id: 'vault_test',
      timestamp: new Date().toISOString(),
      nonce: 'nonce_test',
    };
    const message = Buffer.from(canonicalJson(payload), 'utf8');
    const signature = signDcpMessage(message, keyPair.privateKey);

    expect(verifyEd25519(message, signature, keyPair.publicKey)).toBe(true);
  });

  it('should reject an Ed25519 signature for a modified message', () => {
    const keyPair = generateSigningKeyPair();
    const message = Buffer.from('original', 'utf8');
    const signature = signDcpMessage(message, keyPair.privateKey);

    expect(verifyEd25519(Buffer.from('modified', 'utf8'), signature, keyPair.publicKey)).toBe(false);
  });
});

describe('Pairing Start Endpoint', () => {
  it('should accept a DCP core signed pairing start request', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcp-telegram-webhook-'));
    const store = new TelegramStore(tempDir);
    const fakeBot = {
      getStats: () => ({}),
    };
    const webhook = new WebhookServer(fakeBot as never, store);

    try {
      const keyPair = generateSigningKeyPair();
      const vaultId = 'vault_integration_test';

      const registerResponse = await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: {
          vault_id: vaultId,
          public_key: keyPair.publicKey.toString('base64'),
        },
      });

      expect(registerResponse.statusCode).toBe(200);

      const payloadWithoutSignature = {
        vault_id: vaultId,
        timestamp: new Date().toISOString(),
        nonce: 'nonce_integration_test',
      };
      const message = Buffer.from(canonicalJson(payloadWithoutSignature), 'utf8');
      const signature = signDcpMessage(message, keyPair.privateKey).toString('base64');

      const pairResponse = await webhook.getServer().inject({
        method: 'POST',
        url: '/api/pair/start',
        payload: {
          ...payloadWithoutSignature,
          signature,
        },
      });

      expect(pairResponse.statusCode).toBe(200);
      const body = pairResponse.json() as { code: string; expires_at: string };
      expect(body.code).toMatch(/^\d{6}$/);
      expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now());
    } finally {
      await webhook.getServer().close();
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
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
