/**
 * End-to-end test of the Cloud-Connect WS control bridge (P2d-2):
 * a (simulated) vault registers over /ws and answers cloud_connect_redeem /
 * cloud_connect_status control messages; the relay's /oauth/connect + /oauth/token
 * drive that bridge to issue a real DPoP/audience-bound token.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import WebSocket from 'ws';
import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes, randomUUID } from 'crypto';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { createHash } from 'crypto';
import { RelayServer } from '../src/relay.js';

const VAULT = 'vault_wsbridge_1';

function makeConnectLink(vault_id = VAULT, link_id = 'cl_1'): string {
  const env = { payload: { version: 1, vault_id, link_id }, signature: '' };
  return 'dcp_connect_v1_' + Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');
}

function s256(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

async function makeAgentKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  return { privateKey, publicJwk: await exportJWK(publicKey) };
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

describe('Cloud-Connect WS bridge (relay <-> vault)', () => {
  let server: RelayServer;
  let port: number;
  let vaultWs: WebSocket;
  let approvalStatus = 'pending';
  const base = () => `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    port = 20000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, debug: false });
    await server.start();

    // Simulate a vault: register over /ws, then answer cloud-connect control msgs.
    const signPriv = ed25519.utils.randomPrivateKey();
    const signPub = ed25519.getPublicKey(signPriv);
    vaultWs = new WebSocket(`ws://127.0.0.1:${port}/ws`);

    await new Promise<void>((resolve, reject) => {
      vaultWs.on('open', () => {
        const timestamp = new Date().toISOString();
        const nonce = randomBytes(32);
        const message = Buffer.concat([
          Buffer.from(VAULT, 'utf8'),
          Buffer.from(timestamp, 'utf8'),
          nonce,
        ]);
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
        if (msg.type === 'cloud_connect_redeem') {
          vaultWs.send(
            JSON.stringify({
              type: 'cloud_connect_result',
              payload: {
                control_id: msg.payload.control_id,
                ok: true,
                agent_id: 'agent_1',
                match_code: 'AB23CD',
              },
              timestamp: new Date().toISOString(),
            })
          );
        }
        if (msg.type === 'cloud_connect_status') {
          vaultWs.send(
            JSON.stringify({
              type: 'cloud_connect_result',
              payload: {
                control_id: msg.payload.control_id,
                status: approvalStatus,
                scope: 'read:wallet.address',
              },
              timestamp: new Date().toISOString(),
            })
          );
        }
      });
      vaultWs.on('error', reject);
    });
  });

  afterAll(async () => {
    vaultWs?.close();
    await server.stop();
  });

  it('drives connect -> (pending) -> approved -> token over the WS bridge', async () => {
    const agent = await makeAgentKey();
    const verifier = 'v'.repeat(64);

    // 1. /oauth/connect — relay redeems via the WS bridge, returns the vault's match-code.
    const connectRes = await fetch(`${base()}/oauth/connect`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        dpop: await dpop(agent, 'POST', `${base()}/oauth/connect`),
      },
      body: JSON.stringify({ connect_link: makeConnectLink(), code_challenge: s256(verifier) }),
    });
    expect(connectRes.status).toBe(200);
    const connect = await connectRes.json();
    expect(connect.match_code).toBe('AB23CD');
    const deviceCode = connect.device_code as string;

    const token = async () =>
      fetch(`${base()}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          dpop: await dpop(agent, 'POST', `${base()}/oauth/token`),
        },
        body: JSON.stringify({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: deviceCode,
          code_verifier: verifier,
        }),
      });

    // 2. Pending until the (simulated) owner approves.
    approvalStatus = 'pending';
    const pending = await token();
    expect(pending.status).toBe(400);
    expect((await pending.json()).error).toBe('authorization_pending');

    // 3. Approved -> issues a DPoP + audience-bound access token.
    approvalStatus = 'approved';
    const ok = await token();
    expect(ok.status).toBe(200);
    const body = await ok.json();
    expect(body.token_type).toBe('DPoP');
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.scope).toBe('read:wallet.address');
  });

  it('returns vault_unreachable (503) when the target vault is not connected', async () => {
    const agent = await makeAgentKey();
    const res = await fetch(`${base()}/oauth/connect`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        dpop: await dpop(agent, 'POST', `${base()}/oauth/connect`),
      },
      body: JSON.stringify({
        connect_link: makeConnectLink('vault_not_connected'),
        code_challenge: s256('v'.repeat(64)),
      }),
    });
    expect(res.status).toBe(503);
    expect((await res.json()).error).toBe('temporarily_unavailable');
  });
});
