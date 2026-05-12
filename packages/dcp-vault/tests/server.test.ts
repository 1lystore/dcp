/**
 * Vault Server Tests
 *
 * Tests for the REST API server endpoints.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer } from '../src/index.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  VaultStorage,
  resetStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  createWallet,
} from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('REST Server', () => {
  let server: FastifyInstance;
  let testVaultDir: string;
  let storage: VaultStorage;
  let x402SessionId: string;
  let x402WalletAddress: string;
  const passphrase = 'test-passphrase-123';

  beforeAll(async () => {
    // Reset any existing storage singleton
    resetStorage();

    // Create a unique temp directory for tests
    testVaultDir = path.join(os.tmpdir(), `dcp-vault-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);

    // Set environment variable for the server to use
    process.env.VAULT_DIR = testVaultDir;

    // Initialize storage and schema first
    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();
    const mnemonic = generateRecoveryMnemonic();
    const masterKey = deriveKeyFromMnemonic(mnemonic);
    try {
      await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
      const { encrypted, info } = createWallet('solana', masterKey);
      storage.createRecord({
        scope: 'crypto.wallet.solana',
        item_type: 'WALLET_KEY',
        sensitivity: 'critical',
        data: encrypted,
        chain: 'solana',
        public_address: info.public_address,
      });
      x402WalletAddress = info.public_address;
      const session = storage.createSession(
        'x402-test-agent',
        ['crypto.wallet.solana'],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      x402SessionId = session.id;
    } finally {
      zeroize(masterKey);
    }
    storage.close(); // Close so server can open its own connection

    // Build and start the server (will create its own storage connection)
    server = await buildServer();
    await server.ready();
  });

  afterAll(async () => {
    await server.close();

    // Reset and cleanup storage singleton
    resetStorage();

    // Clean up temp directory
    if (testVaultDir && fs.existsSync(testVaultDir)) {
      fs.rmSync(testVaultDir, { recursive: true, force: true });
    }

    // Clean up env
    delete process.env.VAULT_DIR;
  });

  describe('Health Check', () => {
    it('should return health status', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/health',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('ok');
      expect(typeof body.initialized).toBe('boolean');
      expect(typeof body.unlocked).toBe('boolean');
      const here = dirname(fileURLToPath(import.meta.url));
      const pkg = JSON.parse(
        readFileSync(join(here, '..', 'package.json'), 'utf8')
      ) as { version?: string };
      expect(body.version).toBe(pkg.version);
    });
  });

  describe('Vault Unlock', () => {
    it('should unlock the vault with passphrase', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/unlock',
        payload: { passphrase },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.unlocked).toBe(true);
    });
  });

  describe('x402 Signing', () => {
    it('should sign a Solana x402 payload with an active wallet session', async () => {
      await server.inject({
        method: 'POST',
        url: '/v1/vault/unlock',
        payload: { passphrase },
      });

      const payload = Buffer.from(JSON.stringify({
        x402Version: 1,
        network: 'solana',
        resource: 'https://api.example.test/paywalled',
        nonce: 'test-nonce-1',
      })).toString('base64');

      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/sign_x402',
        payload: {
          network: 'solana',
          payload,
          amount: 0.00001,
          currency: 'SOL',
          recipient: 'pay-sh-test-recipient',
          purpose: 'x402 endpoint test',
          agent_name: 'x402-test-agent',
          session_id: x402SessionId,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.signature).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
      expect(body.public_key).toBe(x402WalletAddress);
      expect(body.chain).toBe('solana');
      expect(body.session_id).toBe(x402SessionId);
    });

    it('should require currency when x402 amount is provided', async () => {
      const payload = Buffer.from('x402-test').toString('base64');

      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/sign_x402',
        payload: {
          network: 'solana',
          payload,
          amount: 0.00001,
          agent_name: 'x402-test-agent',
          session_id: x402SessionId,
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.message).toContain('currency is required');
    });
  });

  describe('MCP Unlock Bridge', () => {
    it('should write mcp.unlock file', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/unlock-mcp',
        payload: { passphrase },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.queued).toBe(true);

      const unlockPath = path.join(testVaultDir, 'mcp.unlock');
      expect(fs.existsSync(unlockPath)).toBe(true);
      fs.unlinkSync(unlockPath);
    });
  });

  describe('Vault Lock', () => {
    it('should lock the vault', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/lock',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.locked).toBe(true);
    });
  });

  // ============================================================================
  // Unlock Rate Limiting Tests (protocol spec)
  // ============================================================================

  describe('Unlock Rate Limiting', () => {
    it('should reject wrong passphrase', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/unlock',
        payload: { passphrase: 'wrong-passphrase' },
      });

      expect(response.statusCode).toBe(400); // VaultError returns 400
      const body = JSON.parse(response.body);
      expect(body.error.message).toContain('Wrong passphrase');
    });

    it('should return 429 after too many failed attempts', async () => {
      // Make 5 failed attempts (the limit per the protocol spec)
      for (let i = 0; i < 5; i++) {
        await server.inject({
          method: 'POST',
          url: '/v1/vault/unlock',
          payload: { passphrase: 'wrong-passphrase-attempt-' + i },
        });
      }

      // 6th attempt should be rate limited
      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/unlock',
        payload: { passphrase: 'another-wrong-passphrase' },
      });

      expect(response.statusCode).toBe(429);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('RATE_LIMITED');
      expect(typeof body.error.retry_after_seconds).toBe('number');
      expect(body.error.retry_after_seconds).toBeGreaterThan(0);
    });

    it('should include retry_after_seconds in rate limit response', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/vault/unlock',
        payload: { passphrase: 'any-passphrase' },
      });

      // Should still be rate limited from previous test
      expect(response.statusCode).toBe(429);
      const body = JSON.parse(response.body);
      expect(body.error.retry_after_seconds).toBeDefined();
      // Should be approximately 300 seconds (5 minutes) minus some elapsed time
      expect(body.error.retry_after_seconds).toBeLessThanOrEqual(300);
    });
  });

  describe('Scopes', () => {
    it('should list available scopes', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/scopes',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(Array.isArray(body.scopes)).toBe(true);
    });
  });

  describe('Agents', () => {
    it('should list active sessions', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/agents',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(Array.isArray(body.agents)).toBe(true);
    });
  });

  describe('Consent', () => {
    it('should list pending consents', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/consent',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(Array.isArray(body.pending)).toBe(true);
    });

    it('should require owner token for consent approval', async () => {
      // Without owner token, should get UNAUTHORIZED (security: don't reveal consent existence)
      const response = await server.inject({
        method: 'POST',
        url: '/consent/non-existent-id/approve',
        payload: {},
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should require owner token for consent denial', async () => {
      // Without owner token, should get UNAUTHORIZED (security: don't reveal consent existence)
      const response = await server.inject({
        method: 'POST',
        url: '/consent/non-existent-id/deny',
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('Revoke', () => {
    it('should handle revoking non-existent agent', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/revoke/non-existent-agent',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.revoked).toBe(0);
    });
  });
});
