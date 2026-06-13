/**
 * Tests for the Cloud-Connect OAuth grant: connect-link redemption -> device-flow
 * poll -> DPoP/audience-bound access token + rotating refresh. Uses a FAKE vault
 * bridge so the full grant state machine is exercised without the WS plumbing.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { randomUUID } from 'crypto';
import {
  initOAuthKeys,
  AuthSessionStore,
  RefreshTokenStore,
  createJtiGuard,
  processConnect,
  processToken,
  verifyAccessToken,
  computeS256Challenge,
  DEVICE_CODE_GRANT,
  type GrantDeps,
  type VaultConnectBridge,
  type BridgeRedeemResult,
  type BridgeApprovalResult,
} from '../src/oauth/index.js';

const ISSUER = 'https://relay.example';
const VAULT = 'vault_1';
const RESOURCE = `${ISSUER}/v/${VAULT}/mcp`;

function makeConnectLink(vault_id = VAULT, link_id = 'cl_1'): string {
  const env = { payload: { version: 1, vault_id, link_id }, signature: '' };
  return 'dcp_connect_v1_' + Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');
}

class FakeBridge implements VaultConnectBridge {
  redeemResult: BridgeRedeemResult = { ok: true, agentId: 'agent_1', matchCode: 'AB23CD' };
  approval: BridgeApprovalResult = { status: 'pending' };
  async redeem(): Promise<BridgeRedeemResult> {
    return this.redeemResult;
  }
  async approvalStatus(): Promise<BridgeApprovalResult> {
    return this.approval;
  }
}

async function makeAgentKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  return { privateKey, publicJwk };
}

async function dpop(
  key: { privateKey: CryptoKey | Uint8Array; publicJwk: JWK },
  method: string,
  url: string
): Promise<string> {
  return new SignJWT({ htm: method, htu: url })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.publicJwk })
    .setIssuedAt()
    .setJti(randomUUID())
    .sign(key.privateKey as Parameters<SignJWT['sign']>[0]);
}

describe('Cloud-Connect OAuth grant', () => {
  let bridge: FakeBridge;
  let deps: GrantDeps;

  beforeEach(async () => {
    bridge = new FakeBridge();
    deps = {
      keys: await initOAuthKeys({ warn: () => {} }),
      sessions: new AuthSessionStore(),
      refresh: new RefreshTokenStore(),
      jtiGuard: createJtiGuard(),
      bridge,
      issuer: ISSUER,
    };
  });

  async function connect(agent: Awaited<ReturnType<typeof makeAgentKey>>, verifier: string) {
    return processConnect(deps, {
      connectLink: makeConnectLink(),
      codeChallenge: computeS256Challenge(verifier),
      dpopProof: await dpop(agent, 'POST', `${ISSUER}/oauth/connect`),
      method: 'POST',
      url: `${ISSUER}/oauth/connect`,
      sourceIp: '203.0.113.7',
    });
  }

  async function tokenDeviceCode(
    agent: Awaited<ReturnType<typeof makeAgentKey>>,
    deviceCode: string,
    verifier: string
  ) {
    return processToken(deps, {
      grantType: DEVICE_CODE_GRANT,
      deviceCode,
      codeVerifier: verifier,
      dpopProof: await dpop(agent, 'POST', `${ISSUER}/oauth/token`),
      method: 'POST',
      url: `${ISSUER}/oauth/token`,
    });
  }

  it('runs connect -> pending -> approved -> token (DPoP + audience bound)', async () => {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);

    const c = await connect(agent, verifier);
    expect(c.status).toBe(200);
    expect(c.body.device_code).toBeTruthy();
    expect(c.body.match_code).toBe('AB23CD');
    const deviceCode = c.body.device_code as string;

    // Pending until the owner approves on-device.
    const pending = await tokenDeviceCode(agent, deviceCode, verifier);
    expect(pending.status).toBe(400);
    expect(pending.body.error).toBe('authorization_pending');

    // Owner approves; the vault returns the authoritative scope.
    bridge.approval = { status: 'approved', scope: 'read:wallet.address' };

    const tok = await tokenDeviceCode(agent, deviceCode, verifier);
    expect(tok.status).toBe(200);
    expect(tok.body.token_type).toBe('DPoP');
    expect(tok.body.refresh_token).toBeTruthy();
    expect(tok.body.scope).toBe('read:wallet.address');

    // The access token is bound to this vault's resource (audience).
    const claims = await verifyAccessToken({
      keys: deps.keys,
      token: tok.body.access_token as string,
      issuer: ISSUER,
      expectedAudience: RESOURCE,
    });
    expect(claims.vault_id).toBe(VAULT);
    expect(claims.sub).toBe('agent_1');
    expect(claims.cnf.jkt).toBeTruthy();
  });

  it('rejects a reused device_code after issuance', async () => {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);
    const c = await connect(agent, verifier);
    const deviceCode = c.body.device_code as string;
    bridge.approval = { status: 'approved', scope: 'read:wallet.address' };
    expect((await tokenDeviceCode(agent, deviceCode, verifier)).status).toBe(200);
    const again = await tokenDeviceCode(agent, deviceCode, verifier);
    expect(again.status).toBe(400);
    expect(again.body.error).toBe('invalid_grant');
  });

  it('rejects a wrong PKCE verifier', async () => {
    const agent = await makeAgentKey();
    const c = await connect(agent, 'v'.repeat(64));
    bridge.approval = { status: 'approved' };
    const bad = await tokenDeviceCode(agent, c.body.device_code as string, 'w'.repeat(64));
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe('invalid_grant');
  });

  it('rejects a token request from a different DPoP key than connect', async () => {
    const agent = await makeAgentKey();
    const attacker = await makeAgentKey();
    const verifier = 'v'.repeat(64);
    const c = await connect(agent, verifier);
    bridge.approval = { status: 'approved' };
    const bad = await tokenDeviceCode(attacker, c.body.device_code as string, verifier);
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe('invalid_grant');
  });

  it('requires PKCE on connect and rejects bad DPoP', async () => {
    const agent = await makeAgentKey();
    const noPkce = await processConnect(deps, {
      connectLink: makeConnectLink(),
      codeChallenge: '',
      dpopProof: await dpop(agent, 'POST', `${ISSUER}/oauth/connect`),
      method: 'POST',
      url: `${ISSUER}/oauth/connect`,
    });
    expect(noPkce.status).toBe(400);
    expect(noPkce.body.error).toBe('invalid_request');

    const badDpop = await processConnect(deps, {
      connectLink: makeConnectLink(),
      codeChallenge: computeS256Challenge('v'.repeat(64)),
      dpopProof: 'not-a-proof',
      method: 'POST',
      url: `${ISSUER}/oauth/connect`,
    });
    expect(badDpop.status).toBe(400);
    expect(badDpop.body.error).toBe('invalid_dpop_proof');
  });

  it('maps bridge failures: unreachable -> 503, redeem-fail -> invalid_grant', async () => {
    const agent = await makeAgentKey();
    bridge.redeemResult = { ok: false, reason: 'vault_unreachable' };
    const offline = await connect(agent, 'v'.repeat(64));
    expect(offline.status).toBe(503);

    bridge.redeemResult = { ok: false, reason: 'LINK_REDEEMED' };
    const spent = await connect(agent, 'v'.repeat(64));
    expect(spent.status).toBe(400);
    expect(spent.body.error).toBe('invalid_grant');
  });

  it('rotates refresh tokens and detects reuse (revokes the chain)', async () => {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);
    const c = await connect(agent, verifier);
    bridge.approval = { status: 'approved', scope: 'read:wallet.address' };
    const first = await tokenDeviceCode(agent, c.body.device_code as string, verifier);
    const rt0 = first.body.refresh_token as string;

    const refresh = async (rt: string) =>
      processToken(deps, {
        grantType: 'refresh_token',
        refreshToken: rt,
        dpopProof: await dpop(agent, 'POST', `${ISSUER}/oauth/token`),
        method: 'POST',
        url: `${ISSUER}/oauth/token`,
      });

    const r1 = await refresh(rt0);
    expect(r1.status).toBe(200);
    const rt1 = r1.body.refresh_token as string;
    expect(rt1).not.toBe(rt0);

    // Reuse the spent rt0 -> chain revoked.
    const reuse = await refresh(rt0);
    expect(reuse.status).toBe(400);
    // The newer rt1 is now dead too.
    expect((await refresh(rt1)).status).toBe(400);
  });
});
