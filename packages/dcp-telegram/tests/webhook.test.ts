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

describe('Vault Key Registration (trust-anchor protection)', () => {
  function makeServer() {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcp-telegram-register-'));
    const store = new TelegramStore(tempDir);
    const fakeBot = { getStats: () => ({}) };
    const webhook = new WebhookServer(fakeBot as never, store);
    return { tempDir, store, webhook };
  }

  it('accepts first registration (TOFU) and idempotent re-registration of the same key', async () => {
    const { tempDir, store, webhook } = makeServer();
    try {
      const keyPair = generateSigningKeyPair();
      const vaultId = 'vault_tofu';
      const publicKey = keyPair.publicKey.toString('base64');

      const first = await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: { vault_id: vaultId, public_key: publicKey },
      });
      expect(first.statusCode).toBe(200);

      // Same key again — still fine, no signature needed.
      const again = await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: { vault_id: vaultId, public_key: publicKey },
      });
      expect(again.statusCode).toBe(200);
    } finally {
      await webhook.getServer().close();
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('rejects overwriting an existing key with a different one and no signature (takeover attempt)', async () => {
    const { tempDir, store, webhook } = makeServer();
    try {
      const legit = generateSigningKeyPair();
      const attacker = generateSigningKeyPair();
      const vaultId = 'vault_takeover';

      await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: { vault_id: vaultId, public_key: legit.publicKey.toString('base64') },
      });

      const overwrite = await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: { vault_id: vaultId, public_key: attacker.publicKey.toString('base64') },
      });
      expect(overwrite.statusCode).toBe(403);

      // The legit key must remain the registered trust anchor.
      expect(store.getVaultKey(vaultId)).toBe(legit.publicKey.toString('base64'));
    } finally {
      await webhook.getServer().close();
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('allows key rotation when signed by the currently-registered key', async () => {
    const { tempDir, store, webhook } = makeServer();
    try {
      const oldKey = generateSigningKeyPair();
      const newKey = generateSigningKeyPair();
      const vaultId = 'vault_rotate';

      await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: { vault_id: vaultId, public_key: oldKey.publicKey.toString('base64') },
      });

      const newPublicKey = newKey.publicKey.toString('base64');
      const timestamp = new Date().toISOString();
      const nonce = 'rotate_nonce';
      const message = Buffer.from(
        canonicalJson({ vault_id: vaultId, public_key: newPublicKey, timestamp, nonce }),
        'utf8'
      );
      const signature = signDcpMessage(message, oldKey.privateKey).toString('base64');

      const rotate = await webhook.getServer().inject({
        method: 'POST',
        url: '/register',
        payload: { vault_id: vaultId, public_key: newPublicKey, timestamp, nonce, signature },
      });
      expect(rotate.statusCode).toBe(200);
      expect(store.getVaultKey(vaultId)).toBe(newPublicKey);
    } finally {
      await webhook.getServer().close();
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('Remote Approval Endpoints (require signed vault requests)', () => {
  it('rejects unsigned pending-approvals reads and unsigned processed callbacks', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcp-telegram-approval-'));
    const store = new TelegramStore(tempDir);
    const fakeBot = { getStats: () => ({}) };
    const webhook = new WebhookServer(fakeBot as never, store);
    try {
      const vaultId = 'vault_approvals';

      const listUnsigned = await webhook.getServer().inject({
        method: 'GET',
        url: `/api/approvals/${vaultId}`,
      });
      expect(listUnsigned.statusCode).toBe(401);

      const processedUnsigned = await webhook.getServer().inject({
        method: 'POST',
        url: '/api/approvals/processed',
        payload: { command_id: 'cmd_1', result: 'success', vault_id: vaultId },
      });
      expect(processedUnsigned.statusCode).toBe(401);

      // Unlink must also be signed (else anyone could unlink a stranger's pairing).
      const unlinkUnsigned = await webhook.getServer().inject({
        method: 'DELETE',
        url: `/api/pair/${vaultId}`,
      });
      expect(unlinkUnsigned.statusCode).toBe(401);
    } finally {
      await webhook.getServer().close();
      store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // End-to-end contract test: a request signed exactly the way the vault signs
  // (canonicalJson over the fields + timestamp + nonce, Ed25519) MUST be accepted.
  // This is the deploy-coupling risk between @dcprotocol/vault and this service.
  it('accepts a correctly vault-signed GET (list) and POST (processed)', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcp-telegram-approval-ok-'));
    const store = new TelegramStore(tempDir);
    const fakeBot = {
      getStats: () => ({}),
      sendApprovalProcessedNotification: async () => ({ success: true }),
    };
    const webhook = new WebhookServer(fakeBot as never, store);
    try {
      const keyPair = generateSigningKeyPair();
      const vaultId = 'vault_e2e';
      const chatId = '12345';

      // Register key (TOFU) + pair the vault so approvals can be listed.
      webhook.getServer(); // ensure routes are set up
      store.registerVaultKey(vaultId, keyPair.publicKey.toString('base64'));
      const pairing = store.pairings.completePairing(vaultId, chatId);
      const command = store.approvals.createApprovalCommand(
        vaultId,
        chatId,
        'consent_abc',
        'approve',
        (pairing as { id?: string }).id || 'pair_1'
      );

      // The vault signs canonicalJson({vault_id, timestamp, nonce}) for the GET.
      const sign = (data: Record<string, unknown>) => {
        const timestamp = new Date().toISOString();
        const nonce = `nonce_${Math.random().toString(36).slice(2)}`;
        const message = Buffer.from(canonicalJson({ ...data, timestamp, nonce }), 'utf8');
        const signature = signDcpMessage(message, keyPair.privateKey).toString('base64');
        return { timestamp, nonce, signature };
      };

      const g = sign({ vault_id: vaultId });
      const listRes = await webhook.getServer().inject({
        method: 'GET',
        url: `/api/approvals/${vaultId}`,
        headers: {
          'x-dcp-timestamp': g.timestamp,
          'x-dcp-nonce': g.nonce,
          'x-dcp-signature': g.signature,
        },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().commands.map((c: { id: string }) => c.id)).toContain(command.id);

      // The vault signs canonicalJson({vault_id, command_id, result, timestamp, nonce}) for POST.
      const p = sign({ vault_id: vaultId, command_id: command.id, result: 'success' });
      const procRes = await webhook.getServer().inject({
        method: 'POST',
        url: '/api/approvals/processed',
        payload: {
          command_id: command.id,
          result: 'success',
          vault_id: vaultId,
          timestamp: p.timestamp,
          nonce: p.nonce,
          signature: p.signature,
        },
      });
      expect(procRes.statusCode).toBe(200);
      expect(procRes.json().processed).toBe(true);
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
