/**
 * Browser auth-code adapter (/oauth/authorize) for vanilla MCP clients (Claude.ai /
 * ChatGPT). Drives the full path through the server with a fake vault bridge:
 * GET /oauth/authorize -> redeem + session -> status poll -> authorization_code at /token.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { randomUUID, createHash } from 'crypto';
import { RelayServer } from '../src/relay.js';
import type { VaultConnectBridge } from '../src/oauth/index.js';

const VAULT = 'vault_authz_1';
const makeConnectLink = (vault_id = VAULT, link_id = 'cl_1') =>
  'dcp_connect_v1_' +
  Buffer.from(JSON.stringify({ payload: { version: 1, vault_id, link_id }, signature: '' }), 'utf8').toString('base64url');
const s256 = (v: string) => createHash('sha256').update(v, 'ascii').digest('base64url');
const ath = (t: string) => createHash('sha256').update(t, 'ascii').digest('base64url');

async function makeAgentKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  return { privateKey, publicJwk: await exportJWK(publicKey) };
}
async function dpop(
  key: { privateKey: CryptoKey | Uint8Array; publicJwk: JWK },
  method: string,
  url: string,
  athClaim?: string
): Promise<string> {
  const payload: Record<string, unknown> = { htm: method, htu: url };
  if (athClaim) payload.ath = athClaim;
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.publicJwk })
    .setIssuedAt()
    .setJti(randomUUID())
    .sign(key.privateKey as Parameters<SignJWT['sign']>[0]);
}

describe('Browser auth-code adapter (/oauth/authorize)', () => {
  let server: RelayServer;
  let port: number;
  const base = () => `http://127.0.0.1:${port}`;

  const fakeVault: VaultConnectBridge = {
    async redeem() {
      return { ok: true, agentId: 'agent_1', matchCode: 'AB23CD' };
    },
    async approvalStatus() {
      return { status: 'approved', scope: 'read:wallet.address' };
    },
  };

  beforeAll(async () => {
    port = 23000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, vaultBridge: fakeVault });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });

  it('shows a paste form when no connect-link is supplied', async () => {
    const res = await fetch(`${base()}/oauth/authorize?redirect_uri=https://app/cb&state=xyz`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('name="connect_link"');
  });

  it('rejects a malformed redirect_uri', async () => {
    const res = await fetch(`${base()}/oauth/authorize?redirect_uri=not-a-url`);
    expect(res.status).toBe(400);
  });

  it('redeems a connect-link, surfaces the match code, and completes the auth-code flow', async () => {
    const verifier = 'v'.repeat(64);
    const url =
      `${base()}/oauth/authorize?connect_link=${encodeURIComponent(makeConnectLink())}` +
      `&code_challenge=${s256(verifier)}&code_challenge_method=S256` +
      `&redirect_uri=${encodeURIComponent('https://app.example/cb')}&state=st123`;
    const res = await fetch(url);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('AB23CD'); // match code surfaced
    const sessionId = (html.match(/"sessionId":"(as_[^"]+)"/) || [])[1];
    expect(sessionId).toBeTruthy();

    // The page polls this; the (fake) vault reports approved.
    const statusRes = await fetch(`${base()}/oauth/authorize/status?session=${sessionId}`);
    const status = await statusRes.json();
    expect(status.status).toBe('approved');
    expect(status.code).toBe(sessionId);

    // Exchange the authorization code for a token (DPoP binds here, TOFU).
    const agent = await makeAgentKey();
    const tokenRes = await fetch(`${base()}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/token`) },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: status.code,
        code_verifier: verifier,
        redirect_uri: 'https://app.example/cb',
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tok = await tokenRes.json();
    expect(tok.token_type).toBe('DPoP');
    expect(tok.access_token).toBeTruthy();

    // The token works at the facade for this vault.
    const mcpUrl = `${base()}/v/${VAULT}/mcp`;
    const facade = await fetch(mcpUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `DPoP ${tok.access_token}`,
        dpop: await dpop(agent, 'POST', mcpUrl, ath(tok.access_token)),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    // 503 = facade auth passed, data plane (no real vault) unavailable — which is
    // exactly what proves the token + DPoP were accepted (not a 401).
    expect([200, 503]).toContain(facade.status);
    expect(facade.status).not.toBe(401);
  });

  it('rejects an auth-code exchange with the wrong PKCE verifier', async () => {
    const verifier = 'v'.repeat(64);
    const html = await (
      await fetch(
        `${base()}/oauth/authorize?connect_link=${encodeURIComponent(makeConnectLink())}` +
          `&code_challenge=${s256(verifier)}&code_challenge_method=S256` +
          `&redirect_uri=${encodeURIComponent('https://app.example/cb')}`
      )
    ).text();
    const sessionId = (html.match(/"sessionId":"(as_[^"]+)"/) || [])[1];
    const agent = await makeAgentKey();
    const tokenRes = await fetch(`${base()}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/token`) },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: sessionId,
        code_verifier: 'w'.repeat(64),
      }),
    });
    expect(tokenRes.status).toBe(400);
    expect((await tokenRes.json()).error).toBe('invalid_grant');
  });
});
