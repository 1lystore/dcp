/**
 * Cloud-Connect (Cloud Agent Connect) — vault integration tests.
 *
 * Exercises the full P1 flow end-to-end via the REST server:
 *   issue connect-link -> redeem (pending agent + match-code) -> on-device
 *   approve (match-code verified) -> agent mints session token -> revoke.
 * Plus the security invariants: single-use, owner-gating, inert-until-approved,
 * match-code enforcement, key-pin/signature rejection.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer } from '../src/index.js';
import {
  VaultStorage,
  resetStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  createWallet,
  generateSigningKeyPair,
  signMessage,
  createConnectLink,
  decodeConnectLink,
  isConnectLink,
  CONNECT_LINK_PREFIX,
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
  const ch = await server.inject({
    method: 'GET',
    url: `/v1/desktop/challenge?desktop_id=${desktopId}`,
  });
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

describe('Cloud-Connect', () => {
  let server: FastifyInstance;
  let testVaultDir: string;
  let storage: VaultStorage;
  let ownerToken: string;
  const passphrase = 'test-passphrase-123';
  const owner = () => ({ 'x-dcp-owner-token': ownerToken });

  beforeAll(async () => {
    resetStorage();
    testVaultDir = path.join(
      os.tmpdir(),
      `dcp-cc-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    process.env.VAULT_DIR = testVaultDir;

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
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });
    ownerToken = await mintOwnerToken(server);
  });

  afterAll(async () => {
    await server.close();
    resetStorage();
    if (testVaultDir && fs.existsSync(testVaultDir)) {
      fs.rmSync(testVaultDir, { recursive: true, force: true });
    }
    delete process.env.VAULT_DIR;
  });

  // -- Helpers ---------------------------------------------------------------

  async function issueLink(
    body: Record<string, unknown> = {}
  ): Promise<{ connect_link: string; agent_id: string; link_id: string; vault_hpke_fingerprint: string }> {
    const res = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/links',
      headers: owner(),
      payload: { name: 'openclaw-aws', scopes: ['read:wallet.address'], ...body },
    });
    expect(res.statusCode).toBe(200);
    return JSON.parse(res.body);
  }

  // -- Happy path ------------------------------------------------------------

  it('runs the full connect -> approve -> token -> revoke flow', async () => {
    // 1. Owner issues a one-time, key-pinned connect-link.
    const issued = await issueLink({
      budget: { daily: 5, currency: 'USD', auto_approve_under: 0 },
    });
    expect(isConnectLink(issued.connect_link)).toBe(true);
    expect(issued.vault_hpke_fingerprint).toMatch(/^[0-9a-f]{64}$/);

    // 2. Agent redeems it -> pending agent + match-code (inert until approved).
    const agentKeys = generateSigningKeyPair();
    const redeemRes = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/redeem',
      payload: {
        connect_link: issued.connect_link,
        agent_public_key: agentKeys.publicKey.toString('base64'),
      },
    });
    expect(redeemRes.statusCode).toBe(200);
    const redeem = JSON.parse(redeemRes.body);
    expect(redeem.status).toBe('pending_approval');
    expect(redeem.agent_id).toBe(issued.agent_id);
    expect(redeem.match_code).toMatch(/^[2-9A-HJ-NP-Z]{6}$/);

    // 3. BEFORE approval: a stolen link grants nothing (Rule #5/#8 — inert).
    const preApprove = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/status',
      payload: { connect_link: issued.connect_link },
    });
    expect(JSON.parse(preApprove.body).status).toBe('pending_approval');
    expect(JSON.parse(preApprove.body).session_token).toBeUndefined();

    // 4. Owner sees the pending approval with server-derived facts + match-code.
    const pendingRes = await server.inject({
      method: 'GET',
      url: '/v1/cloud-connect/pending',
      headers: owner(),
    });
    const pending = JSON.parse(pendingRes.body).pending;
    const entry = pending.find((p: { agent_id: string }) => p.agent_id === issued.agent_id);
    expect(entry).toBeTruthy();
    expect(entry.match_code).toBe(redeem.match_code);
    expect(entry.scopes).toEqual(['read:wallet.address']);
    expect(entry.budget).toEqual({ daily: 5, currency: 'USD', auto_approve_under: 0 });
    expect(entry.agent_fingerprint).toMatch(/^[0-9a-f]{64}$/);

    // 5. Wrong match-code is rejected (Rule #6 anti-phishing).
    const wrong = await server.inject({
      method: 'POST',
      url: `/v1/cloud-connect/pending/${issued.agent_id}/approve`,
      headers: owner(),
      payload: { match_code: 'WRONG9' },
    });
    expect(wrong.statusCode).toBe(400);
    expect(JSON.parse(wrong.body).error.code).toBe('MATCH_CODE_MISMATCH');

    // 6. Correct match-code approves and binds the agent.
    const approve = await server.inject({
      method: 'POST',
      url: `/v1/cloud-connect/pending/${issued.agent_id}/approve`,
      headers: owner(),
      payload: { match_code: redeem.match_code },
    });
    expect(approve.statusCode).toBe(200);
    expect(JSON.parse(approve.body).approved).toBe(true);

    // 7. Agent polls -> mints its session token exactly once.
    const tokenRes = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/status',
      payload: { connect_link: issued.connect_link },
    });
    const tokenBody = JSON.parse(tokenRes.body);
    expect(tokenBody.status).toBe('approved');
    expect(typeof tokenBody.session_token).toBe('string');
    expect(tokenBody.session_token.length).toBeGreaterThan(20);
    expect(tokenBody.scopes).toEqual(['read:wallet.address']);
    expect(tokenBody.budget.auto_approve_under).toBe(0);

    // Second poll: token already issued, not re-minted.
    const tokenRes2 = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/status',
      payload: { connect_link: issued.connect_link },
    });
    const tokenBody2 = JSON.parse(tokenRes2.body);
    expect(tokenBody2.status).toBe('approved');
    expect(tokenBody2.token_already_issued).toBe(true);
    expect(tokenBody2.session_token).toBeUndefined();

    // 8. Instant revoke kills the agent; subsequent polls report revoked.
    const revoke = await server.inject({
      method: 'POST',
      url: `/v1/cloud-connect/agents/${issued.agent_id}/revoke`,
      headers: owner(),
    });
    expect(revoke.statusCode).toBe(200);
    expect(JSON.parse(revoke.body).revoked).toBe(true);

    const afterRevoke = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/status',
      payload: { connect_link: issued.connect_link },
    });
    expect(JSON.parse(afterRevoke.body).status).toBe('revoked');
  });

  // -- Security invariants ---------------------------------------------------

  it('defaults to $0 budget / no auto-approve when omitted (Rule #5)', async () => {
    const issued = await issueLink({ budget: undefined });
    const pendingBudgetRes = await server.inject({
      method: 'GET',
      url: '/v1/cloud-connect/links',
      headers: owner(),
    });
    const link = JSON.parse(pendingBudgetRes.body).links.find(
      (l: { link_id: string }) => l.link_id === issued.link_id
    );
    expect(link.budget).toEqual({ daily: 0, currency: 'USD', auto_approve_under: 0 });
  });

  it('is single-use: a redeemed link cannot be redeemed again', async () => {
    const issued = await issueLink();
    const a1 = generateSigningKeyPair();
    const first = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/redeem',
      payload: { connect_link: issued.connect_link, agent_public_key: a1.publicKey.toString('base64') },
    });
    expect(first.statusCode).toBe(200);

    const a2 = generateSigningKeyPair();
    const second = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/redeem',
      payload: { connect_link: issued.connect_link, agent_public_key: a2.publicKey.toString('base64') },
    });
    expect(second.statusCode).toBe(400);
    expect(JSON.parse(second.body).error.code).toMatch(/LINK_REDEEMED|LINK_CONSUMED|LINK_REVOKED/);
  });

  it('rejects a connect-link signed by a different (rogue) key — key-pin (Rule #1)', async () => {
    const rogue = generateSigningKeyPair();
    const fakeHpke = Buffer.from(generateSigningKeyPair().publicKey).toString('base64');
    const fake = createConnectLink(
      {
        vault_id: 'vault_attacker',
        agent_id: 'agent_x',
        agent_name: 'evil',
        mode: 'mcp',
        relay_url: '',
        vault_hpke_public_key: fakeHpke,
        vault_signing_public_key: rogue.publicKey.toString('base64'),
      },
      rogue.privateKey
    );
    const agentKeys = generateSigningKeyPair();
    const res = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/redeem',
      payload: { connect_link: fake.token, agent_public_key: agentKeys.publicKey.toString('base64') },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error.code).toMatch(/INVALID_CONNECT_LINK|WRONG_VAULT/);
  });

  it('rejects redeem with an invalid agent public key', async () => {
    const issued = await issueLink();
    const res = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/redeem',
      payload: { connect_link: issued.connect_link, agent_public_key: 'not-a-key' },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe('INVALID_AGENT_KEY');
  });

  it('requires an owner token to issue links or view pending/management', async () => {
    const issue = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/links',
      payload: { name: 'x' },
    });
    expect(issue.statusCode).toBe(403);

    const pending = await server.inject({ method: 'GET', url: '/v1/cloud-connect/pending' });
    expect(pending.statusCode).toBe(403);

    const links = await server.inject({ method: 'GET', url: '/v1/cloud-connect/links' });
    expect(links.statusCode).toBe(403);
  });

  it('rejects a malformed connect-link', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/v1/cloud-connect/redeem',
      payload: { connect_link: 'garbage', agent_public_key: generateSigningKeyPair().publicKey.toString('base64') },
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error.code).toBe('INVALID_CONNECT_LINK');
  });
});
