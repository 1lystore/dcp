/**
 * Owner-token guard on GET /v1/vault/activity (audit-log disclosure fix).
 *
 * The audit trail exposes agent names, scopes, amounts, destinations, and which
 * credentials were read, so it must require the owner token like the other
 * sensitive routes. This drives the real server end-to-end: unauthenticated
 * reads are rejected; a genuine owner token is accepted.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer } from '../src/index.js';
import {
  VaultStorage,
  resetStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  generateSigningKeyPair,
  signMessage,
} from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

async function mintOwnerToken(server: FastifyInstance): Promise<string> {
  const keys = generateSigningKeyPair();
  const desktopId = 'desktop_test_' + Math.random().toString(36).slice(2);
  await server.inject({
    method: 'POST',
    url: '/v1/desktop/register',
    payload: { desktop_id: desktopId, public_key: keys.publicKey.toString('base64') },
  });
  const ch = await server.inject({ method: 'GET', url: `/v1/desktop/challenge?desktop_id=${desktopId}` });
  const { nonce } = JSON.parse(ch.body);
  const signature = signMessage(Buffer.from(nonce, 'base64'), keys.privateKey).toString('base64');
  const vr = await server.inject({
    method: 'POST',
    url: '/v1/desktop/verify',
    payload: { desktop_id: desktopId, nonce, signature },
  });
  const { token } = JSON.parse(vr.body);
  if (!token) throw new Error('Failed to mint owner token: ' + vr.body);
  return token;
}

describe('GET /v1/vault/activity owner-token guard', () => {
  let server: FastifyInstance;
  let testVaultDir: string;
  let storage: VaultStorage;
  const passphrase = 'test-passphrase-123';

  beforeAll(async () => {
    resetStorage();
    testVaultDir = path.join(os.tmpdir(), `dcp-activity-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    process.env.VAULT_DIR = testVaultDir;

    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();
    const masterKey = deriveKeyFromMnemonic(generateRecoveryMnemonic());
    try {
      await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });
  });

  afterAll(async () => {
    await server.close();
    resetStorage();
    if (testVaultDir && fs.existsSync(testVaultDir)) fs.rmSync(testVaultDir, { recursive: true, force: true });
    delete process.env.VAULT_DIR;
  });

  it('rejects an unauthenticated read', async () => {
    const res = await server.inject({ method: 'GET', url: '/v1/vault/activity' });
    // requireOwnerToken throws VaultError('UNAUTHORIZED'); the shared error mapper
    // renders that as 400 for every owner-gated route (consistent, not 2xx).
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('UNAUTHORIZED');
  });

  it('accepts a read with a valid owner token', async () => {
    const token = await mintOwnerToken(server);
    const res = await server.inject({
      method: 'GET',
      url: '/v1/vault/activity',
      headers: { 'x-dcp-owner-token': token },
    });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json().events)).toBe(true);
  });
});
