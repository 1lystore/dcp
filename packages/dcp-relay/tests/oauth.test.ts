/**
 * Tests for the relay OAuth 2.1 primitives (Cloud-Connect P2 foundation):
 * keys/JWKS, PKCE (S256), DPoP (RFC 9449), access tokens (audience + cnf.jkt),
 * and discovery metadata.
 */

import { describe, it, expect } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, calculateJwkThumbprint, type JWK } from 'jose';
import { randomUUID, createHash } from 'crypto';
import {
  initOAuthKeys,
  computeS256Challenge,
  verifyPkceS256,
  isValidCodeVerifier,
  verifyDpopProof,
  createJtiGuard,
  issueAccessToken,
  verifyAccessToken,
  AccessTokenError,
  DpopError,
  authorizationServerMetadata,
  protectedResourceMetadata,
} from '../src/oauth/index.js';

// --- helpers ----------------------------------------------------------------

async function makeDpopKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { publicKey, privateKey, publicJwk, jkt };
}

async function makeProof(
  privateKey: CryptoKey | Uint8Array,
  publicJwk: JWK,
  method: string,
  url: string,
  opts: { jti?: string; ath?: string; iat?: number } = {}
): Promise<string> {
  const payload: Record<string, unknown> = { htm: method, htu: url };
  if (opts.ath) payload.ath = opts.ath;
  const jwt = new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
    .setJti(opts.jti ?? randomUUID());
  if (opts.iat !== undefined) jwt.setIssuedAt(opts.iat);
  else jwt.setIssuedAt();
  return jwt.sign(privateKey as Parameters<SignJWT['sign']>[0]);
}

// --- PKCE -------------------------------------------------------------------

describe('PKCE (S256)', () => {
  it('verifies a correct verifier against its challenge', () => {
    const verifier = 'a'.repeat(64);
    const challenge = computeS256Challenge(verifier);
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it('rejects a wrong verifier and malformed input', () => {
    const challenge = computeS256Challenge('a'.repeat(64));
    expect(verifyPkceS256('b'.repeat(64), challenge)).toBe(false);
    expect(verifyPkceS256('too-short', challenge)).toBe(false);
    expect(verifyPkceS256('a'.repeat(64), 'not-the-challenge')).toBe(false);
  });

  it('validates verifier charset/length per RFC 7636', () => {
    expect(isValidCodeVerifier('a'.repeat(43))).toBe(true);
    expect(isValidCodeVerifier('a'.repeat(128))).toBe(true);
    expect(isValidCodeVerifier('a'.repeat(42))).toBe(false);
    expect(isValidCodeVerifier('a'.repeat(129))).toBe(false);
    expect(isValidCodeVerifier('has spaces!!' + 'a'.repeat(40))).toBe(false);
  });
});

// --- keys / JWKS ------------------------------------------------------------

describe('OAuth keys', () => {
  it('generates a usable signing key and a public-only JWKS', async () => {
    const keys = await initOAuthKeys({ warn: () => {} });
    expect(keys.alg).toBe('ES256');
    expect(keys.kid).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    const jwks = keys.jwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kid).toBe(keys.kid);
    expect(jwks.keys[0].use).toBe('sig');
    // The published JWK must NOT contain private material.
    expect((jwks.keys[0] as JWK).d).toBeUndefined();
  });
});

// --- DPoP -------------------------------------------------------------------

describe('DPoP (RFC 9449)', () => {
  const url = 'https://relay.example/v/vault_1/mcp';

  it('verifies a valid proof and returns the bound jkt', async () => {
    const k = await makeDpopKey();
    const proof = await makeProof(k.privateKey, k.publicJwk, 'POST', url);
    const res = await verifyDpopProof(proof, { method: 'POST', url, jtiGuard: createJtiGuard() });
    expect(res.jkt).toBe(k.jkt);
  });

  it('rejects method / URL mismatch', async () => {
    const k = await makeDpopKey();
    const guard = createJtiGuard();
    const proof = await makeProof(k.privateKey, k.publicJwk, 'POST', url);
    await expect(
      verifyDpopProof(proof, { method: 'GET', url, jtiGuard: guard })
    ).rejects.toBeInstanceOf(DpopError);
    const proof2 = await makeProof(k.privateKey, k.publicJwk, 'POST', url);
    await expect(
      verifyDpopProof(proof2, { method: 'POST', url: url + '/other', jtiGuard: guard })
    ).rejects.toBeInstanceOf(DpopError);
  });

  it('ignores query/fragment when matching htu', async () => {
    const k = await makeDpopKey();
    const proof = await makeProof(k.privateKey, k.publicJwk, 'POST', url);
    const res = await verifyDpopProof(proof, {
      method: 'POST',
      url: url + '?foo=bar#frag',
      jtiGuard: createJtiGuard(),
    });
    expect(res.jkt).toBe(k.jkt);
  });

  it('blocks replay (same jti twice)', async () => {
    const k = await makeDpopKey();
    const guard = createJtiGuard();
    const jti = randomUUID();
    const proof = await makeProof(k.privateKey, k.publicJwk, 'POST', url, { jti });
    await verifyDpopProof(proof, { method: 'POST', url, jtiGuard: guard });
    // Same proof again -> replay.
    await expect(
      verifyDpopProof(proof, { method: 'POST', url, jtiGuard: guard })
    ).rejects.toMatchObject({ code: 'dpop_replay' });
  });

  it('rejects a proof whose header jwk contains private material', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const privJwk = await exportJWK(privateKey); // includes "d"
    const proof = await new SignJWT({ htm: 'POST', htu: url })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: privJwk })
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(privateKey);
    await expect(
      verifyDpopProof(proof, { method: 'POST', url, jtiGuard: createJtiGuard() })
    ).rejects.toBeInstanceOf(DpopError);
  });

  it('enforces ath when bound to an access token', async () => {
    const k = await makeDpopKey();
    const token = 'fake.access.token';
    const ath = createHash('sha256').update(token, 'ascii').digest('base64url');
    const good = await makeProof(k.privateKey, k.publicJwk, 'POST', url, { ath });
    const res = await verifyDpopProof(good, {
      method: 'POST',
      url,
      jtiGuard: createJtiGuard(),
      accessToken: token,
    });
    expect(res.jkt).toBe(k.jkt);

    const bad = await makeProof(k.privateKey, k.publicJwk, 'POST', url, { ath: 'wronghash' });
    await expect(
      verifyDpopProof(bad, { method: 'POST', url, jtiGuard: createJtiGuard(), accessToken: token })
    ).rejects.toBeInstanceOf(DpopError);
  });

  it('rejects a stale proof (iat too old)', async () => {
    const k = await makeDpopKey();
    const oldIat = Math.floor(Date.now() / 1000) - 10_000;
    const proof = await makeProof(k.privateKey, k.publicJwk, 'POST', url, { iat: oldIat });
    await expect(
      verifyDpopProof(proof, { method: 'POST', url, jtiGuard: createJtiGuard(), maxAgeSec: 300 })
    ).rejects.toBeInstanceOf(DpopError);
  });
});

// --- access tokens ----------------------------------------------------------

describe('Access tokens (audience + DPoP binding)', () => {
  const issuer = 'https://relay.example';
  const audience = 'https://relay.example/v/vault_1/mcp';

  it('issues and verifies a token bound to audience + jkt', async () => {
    const keys = await initOAuthKeys({ warn: () => {} });
    const token = await issueAccessToken({
      keys,
      issuer,
      subject: 'agent_1',
      audience,
      vaultId: 'vault_1',
      scope: 'read:wallet.address',
      jkt: 'THUMBPRINT_ABC',
    });
    const claims = await verifyAccessToken({
      keys,
      token,
      issuer,
      expectedAudience: audience,
      expectedJkt: 'THUMBPRINT_ABC',
    });
    expect(claims.sub).toBe('agent_1');
    expect(claims.vault_id).toBe('vault_1');
    expect(claims.cnf.jkt).toBe('THUMBPRINT_ABC');
    expect(claims.scope).toBe('read:wallet.address');
  });

  it('rejects audience isolation violation (token for vault A at vault B)', async () => {
    const keys = await initOAuthKeys({ warn: () => {} });
    const token = await issueAccessToken({
      keys,
      issuer,
      subject: 'agent_1',
      audience,
      vaultId: 'vault_1',
      scope: '',
      jkt: 'jkt1',
    });
    await expect(
      verifyAccessToken({
        keys,
        token,
        issuer,
        expectedAudience: 'https://relay.example/v/vault_2/mcp',
      })
    ).rejects.toBeInstanceOf(AccessTokenError);
  });

  it('rejects a DPoP-key mismatch (stolen bearer without the key)', async () => {
    const keys = await initOAuthKeys({ warn: () => {} });
    const token = await issueAccessToken({
      keys,
      issuer,
      subject: 'agent_1',
      audience,
      vaultId: 'vault_1',
      scope: '',
      jkt: 'real_jkt',
    });
    await expect(
      verifyAccessToken({ keys, token, issuer, expectedAudience: audience, expectedJkt: 'attacker_jkt' })
    ).rejects.toBeInstanceOf(AccessTokenError);
  });

  it('rejects a token signed by a different relay key', async () => {
    const keysA = await initOAuthKeys({ warn: () => {} });
    const keysB = await initOAuthKeys({ warn: () => {} });
    const token = await issueAccessToken({
      keys: keysA,
      issuer,
      subject: 'agent_1',
      audience,
      vaultId: 'vault_1',
      scope: '',
      jkt: 'jkt1',
    });
    await expect(
      verifyAccessToken({ keys: keysB, token, issuer, expectedAudience: audience })
    ).rejects.toBeInstanceOf(AccessTokenError);
  });
});

// --- metadata ---------------------------------------------------------------

describe('Discovery metadata', () => {
  it('AS metadata advertises only OAuth 2.1-safe options', () => {
    const md = authorizationServerMetadata({ issuer: 'https://relay.example/' });
    expect(md.issuer).toBe('https://relay.example');
    expect(md.code_challenge_methods_supported).toEqual(['S256']);
    expect(md.response_types_supported).toEqual(['code']);
    expect(md.grant_types_supported).toContain('authorization_code');
    expect(md.grant_types_supported).toContain('refresh_token');
    expect(md.dpop_signing_alg_values_supported).toContain('ES256');
    expect(md.token_endpoint).toBe('https://relay.example/oauth/token');
  });

  it('PRM points at the authorization server for a resource', () => {
    const md = protectedResourceMetadata({
      resource: 'https://relay.example/v/vault_1/mcp',
      authorizationServers: ['https://relay.example'],
    });
    expect(md.resource).toBe('https://relay.example/v/vault_1/mcp');
    expect(md.authorization_servers).toEqual(['https://relay.example']);
    expect(md.bearer_methods_supported).toEqual(['header']);
  });
});
