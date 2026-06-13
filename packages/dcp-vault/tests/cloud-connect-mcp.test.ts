/**
 * Vault-side Cloud-Connect MCP handler (P2e-2 final piece).
 *
 * Provisions a vault, binds an active cloud agent via the real connect flow, then
 * drives handleCloudConnectMcp directly. The critical assertion: a sensitive call
 * (vault_sign_tx) NEVER returns a signature — it yields a pending consent / scope
 * gate, proving the "doorbell, not a key" property (#8) end-to-end.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer, handleCloudConnectMcp } from '../src/index.js';
import {
  VaultStorage,
  resetStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  createWallet,
  generateSigningKeyPair,
  signMessage,
} from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

async function mintOwnerToken(server: FastifyInstance): Promise<string> {
  const keys = generateSigningKeyPair();
  const desktopId = 'desktop_' + Math.random().toString(36).slice(2);
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
  return JSON.parse(vr.body).token;
}

describe('Cloud-Connect vault MCP handler', () => {
  let server: FastifyInstance;
  let testVaultDir: string;
  let ownerToken: string;
  let agentId: string;
  const passphrase = 'test-passphrase-123';
  const owner = () => ({ 'x-dcp-owner-token': ownerToken });

  beforeAll(async () => {
    resetStorage();
    testVaultDir = path.join(os.tmpdir(), `dcp-ccmcp-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    process.env.VAULT_DIR = testVaultDir;

    const storage = new VaultStorage(testVaultDir);
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
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });
    ownerToken = await mintOwnerToken(server);

    // Bind an active cloud agent via the real connect flow.
    const issue = JSON.parse(
      (
        await server.inject({
          method: 'POST',
          url: '/v1/cloud-connect/links',
          headers: owner(),
          payload: {
            name: 'openclaw-aws',
            scopes: ['read:wallet.address', 'sign:solana'],
            budget: { daily: 10, currency: 'USD', auto_approve_under: 0 },
          },
        })
      ).body
    );
    agentId = issue.agent_id;
    const agentKeys = generateSigningKeyPair();
    const redeem = JSON.parse(
      (
        await server.inject({
          method: 'POST',
          url: '/v1/cloud-connect/redeem',
          payload: { connect_link: issue.connect_link, agent_public_key: agentKeys.publicKey.toString('base64') },
        })
      ).body
    );
    await server.inject({
      method: 'POST',
      url: `/v1/cloud-connect/pending/${agentId}/approve`,
      headers: owner(),
      payload: { match_code: redeem.match_code },
    });
  });

  afterAll(async () => {
    await server.close();
    resetStorage();
    if (testVaultDir && fs.existsSync(testVaultDir)) fs.rmSync(testVaultDir, { recursive: true, force: true });
    delete process.env.VAULT_DIR;
  });

  it('handles initialize + tools/list', async () => {
    const init = await handleCloudConnectMcp(server, agentId, { jsonrpc: '2.0', id: 1, method: 'initialize' });
    expect((init.body as any).result.protocolVersion).toBeTruthy();
    expect((init.body as any).result.serverInfo.name).toBe('dcp-vault');

    const list = await handleCloudConnectMcp(server, agentId, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const names = (list.body as any).result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('vault_get_address');
    expect(names).toContain('vault_sign_tx');
  });

  it('forwards a read-only tool (vault_get_address) to the vault', async () => {
    const res = await handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'vault_get_address', arguments: { chain: 'solana' } },
    });
    const text = (res.body as any).result.content[0].text as string;
    // Returns the wallet's public address (read-only).
    expect(text.length).toBeGreaterThan(0);
    expect((res.body as any).result.isError).toBeFalsy();
  });

  it('NEVER signs without on-device approval — vault_sign_tx yields a gate, not a signature (#8)', async () => {
    const res = await handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'vault_sign_tx',
        arguments: {
          chain: 'solana',
          unsigned_tx: Buffer.from('dummy-unsigned-tx').toString('base64'),
          amount: 1,
          currency: 'SOL',
          description: 'test transfer',
        },
      },
    });
    const text = (res.body as any).result.content[0].text as string;
    // The result must NOT contain a real signature — it is a consent/scope gate.
    expect(text).not.toMatch(/"signature"\s*:\s*"[1-9A-HJ-NP-Za-km-z]{40,}"/);
    expect((res.body as any).result.isError).toBe(true);
  });

  it('rejects calls for a revoked agent', async () => {
    await server.inject({
      method: 'POST',
      url: `/v1/cloud-connect/agents/${agentId}/revoke`,
      headers: owner(),
    });
    const res = await handleCloudConnectMcp(server, agentId, { jsonrpc: '2.0', id: 5, method: 'tools/list' });
    expect((res.body as any).error).toBeTruthy();
    expect((res.body as any).error.message).toMatch(/not authorized/i);
  });
});
