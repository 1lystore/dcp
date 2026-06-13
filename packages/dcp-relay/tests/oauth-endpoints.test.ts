/**
 * Integration tests for the relay's static OAuth 2.1 discovery + client endpoints
 * (Cloud-Connect P2c, decision-independent): metadata, JWKS, DCR, revoke.
 * Starts a real RelayServer and hits it over HTTP.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RelayServer } from '../src/relay.js';

describe('Relay OAuth endpoints', () => {
  let server: RelayServer;
  let port: number;
  const base = () => `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    port = 19000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, debug: false });
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('serves Authorization Server Metadata (RFC 8414) with OAuth 2.1-safe options', async () => {
    const res = await fetch(`${base()}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const md = await res.json();
    expect(md.issuer).toBe(base());
    expect(md.authorization_endpoint).toBe(`${base()}/oauth/authorize`);
    expect(md.token_endpoint).toBe(`${base()}/oauth/token`);
    expect(md.jwks_uri).toBe(`${base()}/oauth/jwks`);
    expect(md.code_challenge_methods_supported).toEqual(['S256']);
    expect(md.grant_types_supported).toContain('refresh_token');
    expect(md.dpop_signing_alg_values_supported).toContain('ES256');
  });

  it('serves per-vault Protected Resource Metadata (RFC 9728)', async () => {
    const res = await fetch(`${base()}/.well-known/oauth-protected-resource/v/vault_abc/mcp`);
    expect(res.status).toBe(200);
    const md = await res.json();
    expect(md.resource).toBe(`${base()}/v/vault_abc/mcp`);
    expect(md.authorization_servers).toEqual([base()]);
  });

  it('serves a public-only JWKS', async () => {
    const res = await fetch(`${base()}/oauth/jwks`);
    expect(res.status).toBe(200);
    const jwks = await res.json();
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBe(1);
    expect(jwks.keys[0].kty).toBeTruthy();
    expect(jwks.keys[0].use).toBe('sig');
    expect(jwks.keys[0].d).toBeUndefined(); // no private material
  });

  it('registers a public client via DCR (RFC 7591)', async () => {
    const res = await fetch(`${base()}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'OpenClaw on AWS', redirect_uris: ['https://app/cb'] }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.client_id).toMatch(/^dcpc_/);
    expect(body.token_endpoint_auth_method).toBe('none');
    expect(body.redirect_uris).toEqual(['https://app/cb']);
  });

  it('accepts revoke requests idempotently (RFC 7009 — always 200)', async () => {
    const res = await fetch(`${base()}/oauth/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'dcprt_does_not_exist' }),
    });
    expect(res.status).toBe(200);
  });
});
