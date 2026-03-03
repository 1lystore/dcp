/**
 * Vault Server Tests
 *
 * Tests for the REST API server endpoints.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer } from '../src/index.js';
import { VaultStorage, resetStorage, generateRecoveryMnemonic, deriveKeyFromMnemonic, zeroize } from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('REST Server', () => {
  let server: FastifyInstance;
  let testVaultDir: string;
  let storage: VaultStorage;
  const passphrase = 'test-passphrase-123';

  beforeAll(async () => {
    // Reset any existing storage singleton
    resetStorage();

    // Create a unique temp directory for tests
    testVaultDir = path.join(os.tmpdir(), `dcp-server-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);

    // Set environment variable for the server to use
    process.env.VAULT_DIR = testVaultDir;

    // Initialize storage and schema first
    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();
    const mnemonic = generateRecoveryMnemonic();
    const masterKey = deriveKeyFromMnemonic(mnemonic);
    try {
      await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
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
      expect(typeof body.unlocked).toBe('boolean');
      expect(body.version).toBe('0.1.0');
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

    it('should return error for non-existent consent approval', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/consent/non-existent-id/approve',
        payload: {},
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('CONSENT_NOT_FOUND');
    });

    it('should return error for non-existent consent denial', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/consent/non-existent-id/deny',
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('CONSENT_NOT_FOUND');
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
