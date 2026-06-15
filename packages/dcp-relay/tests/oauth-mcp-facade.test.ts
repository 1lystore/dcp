/**
 * Tests for the per-vault MCP facade /v/:vaultId/mcp (P2e):
 * full grant -> facade auth gate (audience + DPoP ath/jkt + jti replay + revoke),
 * with a fake vault bridge (approves) and a fake MCP data bridge (echoes).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { randomUUID, createHash } from 'crypto';
import { RelayServer } from '../src/relay.js';
import type { VaultConnectBridge, McpDataBridge, AuthedMcpRequest } from '../src/oauth/index.js';

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

function makeConnectLink(vault_id: string, link_id = 'cl_1'): string {
  const env = { payload: { version: 1, vault_id, link_id }, signature: '' };
  return 'dcp_connect_v1_' + Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');
}
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

describe('MCP facade /v/:vaultId/mcp', () => {
  let server: RelayServer;
  let port: number;
  let forwarded: AuthedMcpRequest | null = null;
  const base = () => `http://127.0.0.1:${port}`;

  const fakeVault: VaultConnectBridge = {
    async redeem() {
      return { ok: true, agentId: 'agent_1', matchCode: 'AB23CD' };
    },
    async approvalStatus() {
      return { status: 'approved', scope: 'read:wallet.address' };
    },
  };
  const fakeMcp: McpDataBridge = {
    async forward(req) {
      forwarded = req;
      return { status: 200, body: { ok: true, agent: req.agentId, echo: req.body } };
    },
  };

  beforeAll(async () => {
    port = 21000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, vaultBridge: fakeVault, mcpBridge: fakeMcp });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });

  /** Run the full grant for a vault and return the agent key + access token. */
  async function getToken(vaultId: string) {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);
    const c = await (
      await fetch(`${base()}/oauth/connect`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/connect`) },
        body: JSON.stringify({ connect_link: makeConnectLink(vaultId), code_challenge: s256(verifier) }),
      })
    ).json();
    const t = await (
      await fetch(`${base()}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', dpop: await dpop(agent, 'POST', `${base()}/oauth/token`) },
        body: JSON.stringify({ grant_type: DEVICE_GRANT, device_code: c.device_code, code_verifier: verifier }),
      })
    ).json();
    return { agent, accessToken: t.access_token as string };
  }

  async function mcpCall(
    vaultId: string,
    agent: Awaited<ReturnType<typeof makeAgentKey>>,
    accessToken: string,
    opts: { proof?: string } = {}
  ) {
    const url = `${base()}/v/${vaultId}/mcp`;
    const proof = opts.proof ?? (await dpop(agent, 'POST', url, ath(accessToken)));
    return fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `DPoP ${accessToken}`, dpop: proof },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });
  }

  it('forwards an authorized MCP request to the vault', async () => {
    forwarded = null;
    const { agent, accessToken } = await getToken('vault_A');
    const res = await mcpCall('vault_A', agent, accessToken);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.agent).toBe('agent_1');
    expect(forwarded?.vaultId).toBe('vault_A');
    expect(forwarded?.scope).toBe('read:wallet.address');
  });

  it('401s with no/!DPoP authorization', async () => {
    const res = await fetch(`${base()}/v/vault_A/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('resource_metadata=');
  });

  it('enforces audience isolation: a token for vault A is rejected at vault B', async () => {
    const { agent, accessToken } = await getToken('vault_A');
    const res = await mcpCall('vault_B', agent, accessToken);
    expect(res.status).toBe(401);
  });

  it('blocks DPoP proof replay (same jti twice)', async () => {
    const { agent, accessToken } = await getToken('vault_A');
    const url = `${base()}/v/vault_A/mcp`;
    const proof = await dpop(agent, 'POST', url, ath(accessToken));
    const first = await mcpCall('vault_A', agent, accessToken, { proof });
    expect(first.status).toBe(200);
    const replay = await mcpCall('vault_A', agent, accessToken, { proof });
    expect(replay.status).toBe(401);
  });

  it('rejects a DPoP proof without the access-token hash (ath)', async () => {
    const { agent, accessToken } = await getToken('vault_A');
    const url = `${base()}/v/vault_A/mcp`;
    const proofNoAth = await dpop(agent, 'POST', url); // no ath
    const res = await mcpCall('vault_A', agent, accessToken, { proof: proofNoAth });
    expect(res.status).toBe(401);
  });

  it('honors instant revoke (Rule #7): revoked agent is rejected', async () => {
    const { agent, accessToken } = await getToken('vault_A');
    // Works first.
    expect((await mcpCall('vault_A', agent, accessToken)).status).toBe(200);
    // Owner revokes the agent.
    server.revokeAgentAccess('agent_1');
    const res = await mcpCall('vault_A', agent, accessToken);
    expect(res.status).toBe(401);
  });
});
