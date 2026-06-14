/**
 * Full data-plane E2E (P2e-2): a simulated vault registers over /ws and answers
 * ALL Cloud-Connect control messages (redeem, status, mcp). With the relay's
 * DEFAULT WS-backed bridges, an agent runs connect -> token -> /v/:vaultId/mcp and
 * the authorized MCP request is forwarded over the WS and its response returned.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import WebSocket from 'ws';
import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes, randomUUID, createHash } from 'crypto';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { RelayServer } from '../src/relay.js';

const VAULT = 'vault_dataplane_1';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

const makeConnectLink = (vault_id: string, link_id = 'cl_1') =>
  'dcp_connect_v1_' +
  Buffer.from(JSON.stringify({ payload: { version: 1, vault_id, link_id }, signature: '' }), 'utf8').toString(
    'base64url'
  );
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

describe('Cloud-Connect MCP data plane (E2E over WS)', () => {
  let server: RelayServer;
  let port: number;
  let vaultWs: WebSocket;
  let lastMcp: { agent_id?: string; body?: unknown } | null = null;
  const base = () => `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    port = 22000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, debug: false });
    await server.start();

    const signPriv = ed25519.utils.randomPrivateKey();
    const signPub = ed25519.getPublicKey(signPriv);
    vaultWs = new WebSocket(`ws://127.0.0.1:${port}/ws`);
    const reply = (controlId: string, extra: Record<string, unknown>) =>
      vaultWs.send(
        JSON.stringify({
          type: 'cloud_connect_result',
          payload: { control_id: controlId, ...extra },
          timestamp: new Date().toISOString(),
        })
      );

    await new Promise<void>((resolve, reject) => {
      vaultWs.on('open', () => {
        const timestamp = new Date().toISOString();
        const nonce = randomBytes(32);
        const message = Buffer.concat([Buffer.from(VAULT), Buffer.from(timestamp), nonce]);
        const signature = ed25519.sign(message, signPriv);
        vaultWs.send(
          JSON.stringify({
            type: 'register',
            payload: {
              vault_id: VAULT,
              public_key: Buffer.from(randomBytes(32)).toString('base64'),
              signing_public_key: Buffer.from(signPub).toString('base64'),
              timestamp,
              nonce: nonce.toString('base64'),
              signature: Buffer.from(signature).toString('base64'),
            },
            timestamp,
          })
        );
      });
      vaultWs.on('message', (data: Buffer) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'ack' && msg.payload?.registered) resolve();
        if (msg.type === 'cloud_connect_redeem')
          reply(msg.payload.control_id, { ok: true, agent_id: 'agent_1', match_code: 'AB23CD' });
        if (msg.type === 'cloud_connect_status')
          reply(msg.payload.control_id, { status: 'approved', scope: 'read:wallet.address' });
        if (msg.type === 'cloud_connect_mcp') {
          lastMcp = { agent_id: msg.payload.agent_id, body: msg.payload.body };
          // Simulated MCP handler: echo a JSON-RPC result.
          reply(msg.payload.control_id, {
            status: 200,
            body: {
              jsonrpc: '2.0',
              id: (msg.payload.body as { id?: unknown })?.id ?? null,
              result: { tools: ['vault_get_address'], handled_for: msg.payload.agent_id },
            },
          });
        }
      });
      vaultWs.on('error', reject);
    });
  });

  afterAll(async () => {
    vaultWs?.close();
    await server.stop();
  });

  it('forwards an authorized MCP call to the vault and returns its response', async () => {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);

    // connect
    const c = await (
      await fetch(`${base()}/oauth/connect`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/connect`) },
        body: JSON.stringify({ connect_link: makeConnectLink(VAULT), code_challenge: s256(verifier) }),
      })
    ).json();
    expect(c.match_code).toBe('AB23CD');

    // token
    const t = await (
      await fetch(`${base()}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/token`) },
        body: JSON.stringify({ grant_type: DEVICE_GRANT, device_code: c.device_code, code_verifier: verifier }),
      })
    ).json();
    const accessToken = t.access_token as string;
    expect(accessToken).toBeTruthy();

    // MCP call through the facade -> forwarded over WS to the vault.
    const url = `${base()}/v/${VAULT}/mcp`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `DPoP ${accessToken}`,
        dpop: await dpop(agent, 'POST', url, ath(accessToken)),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.jsonrpc).toBe('2.0');
    expect(body.id).toBe(7);
    expect(body.result.handled_for).toBe('agent_1');

    // The vault received the authenticated agent id + the original MCP body.
    expect(lastMcp?.agent_id).toBe('agent_1');
    expect((lastMcp?.body as { method?: string })?.method).toBe('tools/list');
  });

  it('honors a vault revoke push over WS (Rule #7 fast-fail at the relay)', async () => {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);
    const c = await (
      await fetch(`${base()}/oauth/connect`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/connect`) },
        body: JSON.stringify({ connect_link: makeConnectLink(VAULT), code_challenge: s256(verifier) }),
      })
    ).json();
    const t = await (
      await fetch(`${base()}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/token`) },
        body: JSON.stringify({ grant_type: DEVICE_GRANT, device_code: c.device_code, code_verifier: verifier }),
      })
    ).json();
    const accessToken = t.access_token as string;
    const url = `${base()}/v/${VAULT}/mcp`;
    const call = async () =>
      fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `DPoP ${accessToken}`,
          dpop: await dpop(agent, 'POST', url, ath(accessToken)),
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      });

    expect((await call()).status).toBe(200);

    // Simulate a relay restart losing the fresh agent->vault cache. The vault's
    // authenticated socket must still be able to revoke its own agent, scoped by vault.
    (server as any).agentVault.clear();

    // The vault pushes a revoke; the relay must denylist the agent.
    vaultWs.send(
      JSON.stringify({
        type: 'cloud_connect_revoke',
        payload: { vault_id: VAULT, agent_id: 'agent_1' },
        timestamp: new Date().toISOString(),
      })
    );
    await new Promise((r) => setTimeout(r, 150));

    expect((await call()).status).toBe(401);
  });
});
