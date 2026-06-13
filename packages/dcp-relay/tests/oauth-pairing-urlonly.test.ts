/**
 * Link-less "paste-URL" pairing (Model A): a vanilla OAuth MCP client (Hermes /
 * Claude.ai / ChatGPT) connects with ONLY the per-vault MCP URL — no connect-link
 * secret. The relay derives the vault from the `resource` and asks the vault to
 * open an on-device approval directly. Drives the full path with a fake bridge:
 * GET /oauth/authorize?resource=... -> pairing + session -> status poll ->
 * authorization_code at /token -> token works at the facade.
 *
 * Also asserts the device-flow (/oauth/connect) link-less path, and that a bridge
 * WITHOUT requestPairing falls back safely (form for browser, error for device).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { randomUUID, createHash } from 'crypto';
import { RelayServer } from '../src/relay.js';
import type { VaultConnectBridge, BridgePairingInput } from '../src/oauth/index.js';

const VAULT = 'vault_urlonly_123456';
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

describe('Link-less paste-URL pairing (/oauth/authorize + /oauth/connect)', () => {
  let server: RelayServer;
  let port: number;
  const base = () => `http://127.0.0.1:${port}`;
  const resource = () => `${base()}/v/${VAULT}/mcp`;

  const pairingCalls: BridgePairingInput[] = [];
  const fakeVault: VaultConnectBridge = {
    async redeem() {
      return { ok: true, agentId: 'agent_link', matchCode: 'AB23CD' };
    },
    async approvalStatus() {
      return { status: 'approved', scope: 'read:wallet.address' };
    },
    async requestPairing(input) {
      pairingCalls.push(input);
      return { ok: true, agentId: 'agent_url', matchCode: 'X9MK7P' };
    },
  };

  beforeAll(async () => {
    port = 24000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, vaultBridge: fakeVault });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });

  it('pairs from the URL alone (no connect-link), surfaces a match code, completes auth-code', async () => {
    const verifier = 'v'.repeat(64);
    const url =
      `${base()}/oauth/authorize?resource=${encodeURIComponent(resource())}` +
      `&code_challenge=${s256(verifier)}&code_challenge_method=S256` +
      `&redirect_uri=${encodeURIComponent('https://app.example/cb')}&state=st1`;
    const res = await fetch(url);
    expect(res.status).toBe(200);
    const html = await res.text();
    // No connect-link form was shown — we went straight to the approval page.
    expect(html).not.toContain('name="connect_link"');
    expect(html).toContain('X9MK7P'); // match code surfaced
    expect(pairingCalls.length).toBeGreaterThan(0);
    expect(pairingCalls[0].vaultId).toBe(VAULT);

    const sessionId = (html.match(/"sessionId":"(as_[^"]+)"/) || [])[1];
    expect(sessionId).toBeTruthy();

    const status = await (await fetch(`${base()}/oauth/authorize/status?session=${sessionId}`)).json();
    expect(status.status).toBe('approved');

    const agent = await makeAgentKey();
    const tokenRes = await fetch(`${base()}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/token`) },
      body: JSON.stringify({ grant_type: 'authorization_code', code: status.code, code_verifier: verifier }),
    });
    expect(tokenRes.status).toBe(200);
    const tok = await tokenRes.json();
    expect(tok.access_token).toBeTruthy();

    // Token is accepted at the per-vault facade (503 = auth OK, no real data plane).
    const facade = await fetch(resource(), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `DPoP ${tok.access_token}`,
        dpop: await dpop(agent, 'POST', resource(), ath(tok.access_token)),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(facade.status).not.toBe(401);
    expect([200, 503]).toContain(facade.status);
  });

  it('issues a BEARER token to a non-DPoP client and accepts it at the facade', async () => {
    const verifier = 'b'.repeat(64);
    // Browser-style auth: GET authorize (no DPoP), approve (fake auto-approves).
    const html = await (
      await fetch(
        `${base()}/oauth/authorize?resource=${encodeURIComponent(resource())}` +
          `&code_challenge=${s256(verifier)}&code_challenge_method=S256` +
          `&redirect_uri=${encodeURIComponent('https://app.example/cb')}`
      )
    ).text();
    const sessionId = (html.match(/"sessionId":"(as_[^"]+)"/) || [])[1];
    expect(sessionId).toBeTruthy();

    // Token exchange as FORM-ENCODED with NO DPoP header (the Hermes reality).
    const tokenRes = await fetch(`${base()}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: sessionId,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const tok = await tokenRes.json();
    expect(tok.token_type).toBe('Bearer'); // not DPoP
    expect(tok.access_token).toBeTruthy();

    // The Bearer token is accepted at the facade WITHOUT a DPoP proof.
    const facade = await fetch(resource(), {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${tok.access_token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(facade.status).not.toBe(401);
    expect([200, 503]).toContain(facade.status);
  });

  it('device-flow /oauth/connect pairs from a resource (no connect-link)', async () => {
    const verifier = 'd'.repeat(64);
    const agent = await makeAgentKey();
    const res = await fetch(`${base()}/oauth/connect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/connect`) },
      body: JSON.stringify({ resource: resource(), code_challenge: s256(verifier), code_challenge_method: 'S256' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.device_code).toBeTruthy();
    expect(body.match_code).toBe('X9MK7P');
  });

  it('falls back to the connect-link form when neither link nor resolvable resource is present', async () => {
    const res = await fetch(`${base()}/oauth/authorize?redirect_uri=https://app/cb`);
    const html = await res.text();
    expect(html).toContain('name="connect_link"');
  });
});

describe('Link-less pairing when the bridge does not support it', () => {
  let server: RelayServer;
  let port: number;
  const base = () => `http://127.0.0.1:${port}`;
  const resource = () => `${base()}/v/${VAULT}/mcp`;

  // No requestPairing implemented.
  const noPairing: VaultConnectBridge = {
    async redeem() {
      return { ok: true, agentId: 'agent_link', matchCode: 'AB23CD' };
    },
    async approvalStatus() {
      return { status: 'pending' };
    },
  };

  beforeAll(async () => {
    port = 25000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, vaultBridge: noPairing });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });

  it('device-flow returns an error rather than pairing silently', async () => {
    const verifier = 'd'.repeat(64);
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const proof = await new SignJWT({ htm: 'POST', htu: `${base()}/oauth/connect` })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(privateKey);
    const res = await fetch(`${base()}/oauth/connect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', dpop: proof },
      body: JSON.stringify({ resource: resource(), code_challenge: s256(verifier), code_challenge_method: 'S256' }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_request');
  });
});
