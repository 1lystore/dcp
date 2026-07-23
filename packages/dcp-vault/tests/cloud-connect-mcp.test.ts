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
    // FULL parity with the local agent — an agentic wallet exposes the SAME 14
    // tools to remote/cloud agents as to local ones (no second-class agents).
    const expected = [
      'vault_get_address', 'vault_read', 'vault_write', 'vault_scope_guide', 'vault_budget_check',
      'vault_sign_tx', 'vault_sign_message', 'vault_sign_x402',
      'vault_transfer', 'vault_swap',
      'vault_get_balances', 'vault_get_tx_status', 'vault_get_tx_history', 'vault_search_tokens',
    ];
    for (const t of expected) expect(names).toContain(t);
    expect(names.length).toBe(expected.length);
  });

  it('advertises vault_scope_guide and returns the canonical scope names', async () => {
    const res = await handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'vault_scope_guide', arguments: {} },
    });
    const text = (res.body as any).result.content[0].text as string;
    expect(text).toContain('identity.name');
    expect(text).toContain('identity.email');
    expect((res.body as any).result.isError).toBeFalsy();
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

  it('records activity (last_seen + request_count) on each cloud-connect tool call', async () => {
    const before = await server.inject({ method: 'GET', url: '/v1/agent-connections', headers: owner() });
    const beforeAgent = JSON.parse(before.body).agents.find((a: any) => a.agent_id === agentId);
    const beforeCount = beforeAgent?.request_count ?? 0;

    await handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 31,
      method: 'tools/call',
      params: { name: 'vault_get_address', arguments: { chain: 'solana' } },
    });

    const after = await server.inject({ method: 'GET', url: '/v1/agent-connections', headers: owner() });
    const afterAgent = JSON.parse(after.body).agents.find((a: any) => a.agent_id === agentId);
    expect(afterAgent.request_count).toBe(beforeCount + 1);
    expect(afterAgent.last_seen_at).toBeTruthy();
  });

  it('scope enforcement: a NOT-granted scope is denied outright (No) — no consent created', async () => {
    // The agent is granted wallet.address + sign:solana only — not address.home.
    const res = await handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 60,
      method: 'tools/call',
      params: { name: 'vault_read', arguments: { scope: 'address.home' } },
    });
    const text = (res.body as any).result.content[0].text as string;
    expect(text).toContain('SCOPE_NOT_PERMITTED');
    expect((res.body as any).result.isError).toBe(true);
    // Crucially: NO consent should have been created (owner is never pestered).
    const pending = JSON.parse(
      (await server.inject({ method: 'GET', url: '/consent', headers: owner() })).body
    );
    expect((pending.pending || []).some((c: any) => c.scope === 'address.home')).toBe(false);
  });

  it('one-go consent: approving mid-call resumes and returns data (no "try again")', async () => {
    // Owner stores a value the agent will read.
    await server.inject({
      method: 'POST',
      url: '/v1/vault/write',
      headers: owner(),
      payload: { scope: 'identity.name', data: { full: 'Ada Lovelace' }, agent_name: 'desktop-ui' },
    });
    // Grant the read scope (otherwise it's denied as "No" before consent).
    await server.inject({
      method: 'PATCH',
      url: `/v1/agent-connections/${agentId}`,
      headers: owner(),
      payload: { permission_scopes: ['read:wallet.address', 'sign:solana', 'read:identity.name'] },
    });

    // Start a consent-gated read. The handler creates a pending consent, then
    // polls in-process for the approval (it must NOT return the gate immediately).
    const callP = handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 70,
      method: 'tools/call',
      params: { name: 'vault_read', arguments: { scope: 'identity.name' } },
    });

    // Find the pending consent and approve it mid-call.
    let consentId: string | undefined;
    for (let i = 0; i < 150 && !consentId; i++) {
      await new Promise((r) => setTimeout(r, 20));
      const list = JSON.parse(
        (await server.inject({ method: 'GET', url: '/consent', headers: owner() })).body
      );
      consentId = (list.pending || []).find(
        (c: any) => c.scope === 'identity.name' && c.status === 'pending'
      )?.id;
    }
    expect(consentId).toBeTruthy();
    await server.inject({
      method: 'POST',
      url: `/consent/${consentId}/approve`,
      headers: owner(),
      payload: {},
    });

    // The single MCP call resolves with the DATA — not a "requires_consent" gate.
    const res = await callP;
    const text = (res.body as any).result.content[0].text as string;
    expect(text).not.toContain('requires_consent');
    expect(text).toContain('Ada Lovelace');
    expect((res.body as any).result.isError).toBeFalsy();
  }, 20000);

  it('auto-approve: a pre-authorized scope reads in one call with NO consent prompt', async () => {
    await server.inject({
      method: 'POST',
      url: '/v1/vault/write',
      headers: owner(),
      payload: { scope: 'identity.email', data: { email: 'ada@dcp.dev' }, agent_name: 'desktop-ui' },
    });
    // Grant the read scope first (Allow = granted + auto-approve).
    await server.inject({
      method: 'PATCH',
      url: `/v1/agent-connections/${agentId}`,
      headers: owner(),
      payload: {
        permission_scopes: ['read:wallet.address', 'sign:solana', 'read:identity.name', 'read:identity.email'],
      },
    });

    // Owner pre-authorizes this agent to auto-approve identity.email.
    const enable = await server.inject({
      method: 'POST',
      url: `/v1/agent-connections/${agentId}/auto-approve`,
      headers: owner(),
      payload: { scope: 'identity.email' },
    });
    expect(enable.statusCode).toBe(200);
    expect(JSON.parse(enable.body).auto_approve_scopes).toContain('identity.email');

    // No consent should be created — the read returns data directly.
    const res = await handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 80,
      method: 'tools/call',
      params: { name: 'vault_read', arguments: { scope: 'identity.email' } },
    });
    const text = (res.body as any).result.content[0].text as string;
    expect(text).not.toContain('requires_consent');
    expect(text).toContain('ada@dcp.dev');
    expect((res.body as any).result.isError).toBeFalsy();

    const pending = JSON.parse(
      (await server.inject({ method: 'GET', url: '/consent', headers: owner() })).body
    );
    expect((pending.pending || []).some((c: any) => c.scope === 'identity.email')).toBe(false);
  });

  it('auto-approve: signing scopes are rejected (signing stays budget-bounded)', async () => {
    const res = await server.inject({
      method: 'POST',
      url: `/v1/agent-connections/${agentId}/auto-approve`,
      headers: owner(),
      payload: { scope: 'sign:solana' },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe('SCOPE_NOT_AUTO_APPROVABLE');
  });

  it('auto-approve: disabling revokes the standing grant (consent required again)', async () => {
    await server.inject({
      method: 'POST',
      url: '/v1/vault/write',
      headers: owner(),
      payload: { scope: 'identity.phone', data: { number: '555' }, agent_name: 'desktop-ui' },
    });
    await server.inject({
      method: 'PATCH',
      url: `/v1/agent-connections/${agentId}`,
      headers: owner(),
      payload: {
        permission_scopes: [
          'read:wallet.address',
          'sign:solana',
          'read:identity.name',
          'read:identity.email',
          'read:identity.phone',
        ],
      },
    });
    await server.inject({
      method: 'POST',
      url: `/v1/agent-connections/${agentId}/auto-approve`,
      headers: owner(),
      payload: { scope: 'identity.phone' },
    });
    const off = await server.inject({
      method: 'DELETE',
      url: `/v1/agent-connections/${agentId}/auto-approve`,
      headers: owner(),
      payload: { scope: 'identity.phone' },
    });
    expect(off.statusCode).toBe(200);
    expect(JSON.parse(off.body).auto_approve_scopes).not.toContain('identity.phone');

    // With the grant gone, a read must create a pending consent again.
    const callP = handleCloudConnectMcp(server, agentId, {
      jsonrpc: '2.0',
      id: 81,
      method: 'tools/call',
      params: { name: 'vault_read', arguments: { scope: 'identity.phone' } },
    });
    // It will now poll for consent; deny it so the call returns promptly.
    let cid: string | undefined;
    for (let i = 0; i < 150 && !cid; i++) {
      await new Promise((r) => setTimeout(r, 20));
      const list = JSON.parse(
        (await server.inject({ method: 'GET', url: '/consent', headers: owner() })).body
      );
      cid = (list.pending || []).find(
        (c: any) => c.scope === 'identity.phone' && c.status === 'pending'
      )?.id;
    }
    expect(cid).toBeTruthy();
    await server.inject({ method: 'POST', url: `/consent/${cid}/deny`, headers: owner() });
    await callP;
  }, 20000);

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

  it('revoking an agent also purges its standing grants (no orphaned sessions)', async () => {
    // Give the agent a standing Allow grant.
    await server.inject({
      method: 'POST',
      url: `/v1/agent-connections/${agentId}/auto-approve`,
      headers: owner(),
      payload: { scope: 'identity.name' },
    });
    let agentsList = JSON.parse(
      (await server.inject({ method: 'GET', url: '/v1/agent-connections', headers: owner() })).body
    );
    let me = agentsList.agents.find((a: any) => a.agent_id === agentId);
    expect(me.auto_approve_scopes).toContain('identity.name');

    // Revoke the agent → its sessions must be gone.
    await server.inject({
      method: 'POST',
      url: `/v1/cloud-connect/agents/${agentId}/revoke`,
      headers: owner(),
    });
    agentsList = JSON.parse(
      (await server.inject({ method: 'GET', url: '/v1/agent-connections', headers: owner() })).body
    );
    me = agentsList.agents.find((a: any) => a.agent_id === agentId);
    // Either the agent is gone, or it has no active standing grants left.
    expect(me ? me.auto_approve_scopes : []).not.toContain('identity.name');
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
