/**
 * Security regressions for the relay hardening:
 *  - #6: a vault_id is bound to its first signing key (TOFU). A DIFFERENT key
 *        claiming an already-registered vault_id is rejected (anti-hijack).
 *  - #5: the HTTP-fallback /relay/poll and /relay/respond require a signed proof
 *        of vault ownership — unauthenticated callers cannot drain the queue or
 *        race responses.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import WebSocket from 'ws';
import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from 'crypto';
import { RelayServer } from '../src/relay.js';
import { RELAY_VERSION, type RelayEnvelope } from '../src/types.js';

const VAULT = 'vault_sec_regress_1';

function signRegister(vaultId: string, signPriv: Uint8Array) {
  const signPub = ed25519.getPublicKey(signPriv);
  const timestamp = new Date().toISOString();
  const nonce = randomBytes(32);
  const message = Buffer.concat([
    Buffer.from(vaultId, 'utf8'),
    Buffer.from(timestamp, 'utf8'),
    nonce,
  ]);
  const signature = ed25519.sign(message, signPriv);
  return {
    vault_id: vaultId,
    public_key: Buffer.from(randomBytes(32)).toString('base64'),
    signing_public_key: Buffer.from(signPub).toString('base64'),
    timestamp,
    nonce: nonce.toString('base64'),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function registerWs(port: number, payload: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
    let settled = false;
    const done = (r: { ok: boolean; error?: string }) => {
      if (settled) return;
      settled = true;
      try { ws.close(); } catch { /* noop */ }
      resolve(r);
    };
    ws.on('open', () => ws.send(JSON.stringify({ type: 'register', payload, timestamp: new Date().toISOString() })));
    ws.on('message', (data: Buffer) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'ack' && msg.payload?.registered) done({ ok: true });
      if (msg.type === 'error') done({ ok: false, error: msg.payload?.code || 'error' });
    });
    ws.on('error', () => done({ ok: false, error: 'ws_error' }));
    setTimeout(() => done({ ok: false, error: 'timeout' }), 3000);
  });
}

function openRegisteredWs(
  port: number,
  payload: Record<string, unknown>
): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      try { ws.close(); } catch { /* noop */ }
      reject(err);
    };
    ws.on('open', () => ws.send(JSON.stringify({ type: 'register', payload, timestamp: new Date().toISOString() })));
    ws.on('message', (data: Buffer) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'ack' && msg.payload?.registered) {
        settled = true;
        resolve(ws);
      }
      if (msg.type === 'error') {
        fail(new Error(msg.payload?.code || 'error'));
      }
    });
    ws.on('error', fail);
    setTimeout(() => fail(new Error('timeout')), 3000);
  });
}

function waitForWsMessage(ws: WebSocket, predicate: (msg: any) => boolean): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.off('message', onMessage);
      reject(new Error('timeout'));
    }, 3000);
    const onMessage = (data: Buffer) => {
      const msg = JSON.parse(data.toString());
      if (!predicate(msg)) return;
      clearTimeout(timer);
      ws.off('message', onMessage);
      resolve(msg);
    };
    ws.on('message', onMessage);
  });
}

describe('Relay security regressions (#5 poll/respond auth, #6 vault_id binding)', () => {
  let server: RelayServer;
  let port: number;
  const base = () => `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    port = 26000 + Math.floor(Math.random() * 9000);
    server = new RelayServer({ port, enableLongPoll: true });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });

  it('#6: rejects a different key claiming an already-bound vault_id', async () => {
    const keyA = ed25519.utils.randomPrivateKey();
    const first = await registerWs(port, signRegister(VAULT, keyA));
    expect(first.ok).toBe(true);

    // Same key re-registers — allowed (idempotent reconnect).
    const again = await registerWs(port, signRegister(VAULT, keyA));
    expect(again.ok).toBe(true);

    // A DIFFERENT key claims the same vault_id — rejected (hijack).
    const keyB = ed25519.utils.randomPrivateKey();
    const hijack = await registerWs(port, signRegister(VAULT, keyB));
    expect(hijack.ok).toBe(false);
    expect(hijack.error).toBe('RELAY_UNAUTHORIZED');
  });

  it('#5: /relay/poll without a signed proof is rejected', async () => {
    const res = await fetch(`${base()}/relay/poll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ vault_id: VAULT, timeout_ms: 100 }),
    });
    expect(res.status).toBe(401);
  });

  it('#5: /relay/poll WITH a valid proof from the bound owner is accepted', async () => {
    // Bind the vault first.
    const key = ed25519.utils.randomPrivateKey();
    const v = 'vault_poll_ok_1';
    expect((await registerWs(port, signRegister(v, key))).ok).toBe(true);

    const proof = signRegister(v, key);
    const res = await fetch(`${base()}/relay/poll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        vault_id: v,
        timeout_ms: 100,
        signing_public_key: proof.signing_public_key,
        timestamp: proof.timestamp,
        nonce: proof.nonce,
        signature: proof.signature,
      }),
    });
    expect(res.status).toBe(200);
  });

  it('#5: /relay/respond without a signed proof is rejected', async () => {
    const res = await fetch(`${base()}/relay/respond`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        version: '1',
        request_id: 'req_whatever',
        encrypted_payload: 'x',
        timestamp: new Date().toISOString(),
      }),
    });
    expect(res.status).toBe(401);
  });

  it('#3: the unauthenticated HTTP pairing-claims resolve route is removed', async () => {
    const res = await fetch(`${base()}/v1/pairing-claims/claim_anything/resolve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve', vault_id: VAULT }),
    });
    // Route no longer exists → Fastify 404 (definitely not a 200 success).
    expect(res.status).toBe(404);
  });

  it('#5: WS response from the wrong vault cannot race another vault request', async () => {
    const ownerKey = ed25519.utils.randomPrivateKey();
    const attackerKey = ed25519.utils.randomPrivateKey();
    const ownerVault = 'vault_ws_response_owner';
    const attackerVault = 'vault_ws_response_attacker';
    const ownerWs = await openRegisteredWs(port, signRegister(ownerVault, ownerKey));
    const attackerWs = await openRegisteredWs(port, signRegister(attackerVault, attackerKey));

    try {
      const envelope: RelayEnvelope = {
        version: RELAY_VERSION,
        vault_id: ownerVault,
        request_id: `req_ws_owner_${Date.now()}`,
        action_type: 'sign',
        encrypted_payload: 'encrypted_request',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      };
      server.getMessageStore().storeMessage(envelope);

      attackerWs.send(JSON.stringify({
        type: 'response',
        payload: {
          version: RELAY_VERSION,
          request_id: envelope.request_id,
          encrypted_payload: 'attacker_response',
          timestamp: new Date().toISOString(),
        },
        timestamp: new Date().toISOString(),
      }));

      const err = await waitForWsMessage(attackerWs, (msg) => msg.type === 'error');
      expect(err.payload?.code).toBe('RELAY_UNAUTHORIZED');
      expect(server.getMessageStore().getResponse(envelope.request_id)).toBeUndefined();

      ownerWs.send(JSON.stringify({
        type: 'response',
        payload: {
          version: RELAY_VERSION,
          request_id: envelope.request_id,
          encrypted_payload: 'owner_response',
          timestamp: new Date().toISOString(),
        },
        timestamp: new Date().toISOString(),
      }));

      const ack = await waitForWsMessage(ownerWs, (msg) => msg.type === 'ack' && msg.payload?.stored);
      expect(ack.payload?.request_id).toBe(envelope.request_id);
      expect(server.getMessageStore().getResponse(envelope.request_id)?.encrypted_payload).toBe('owner_response');
    } finally {
      ownerWs.close();
      attackerWs.close();
    }
  });

  it('#7: WS revoke is vault-scoped even when the fresh agent ownership cache is absent', async () => {
    const vaultKey = ed25519.utils.randomPrivateKey();
    const otherKey = ed25519.utils.randomPrivateKey();
    const vaultWs = await openRegisteredWs(port, signRegister('vault_revoke_owner', vaultKey));
    const otherWs = await openRegisteredWs(port, signRegister('vault_revoke_other', otherKey));

    try {
      vaultWs.send(JSON.stringify({
        type: 'cloud_connect_revoke',
        payload: { vault_id: 'vault_revoke_owner', agent_id: 'agent_after_restart' },
        timestamp: new Date().toISOString(),
      }));
      await new Promise((r) => setTimeout(r, 100));

      otherWs.send(JSON.stringify({
        type: 'cloud_connect_revoke',
        payload: { vault_id: 'vault_revoke_owner', agent_id: 'agent_after_restart' },
        timestamp: new Date().toISOString(),
      }));
      const err = await waitForWsMessage(otherWs, (msg) => msg.type === 'error');
      expect(err.payload?.code).toBe('RELAY_UNAUTHORIZED');
    } finally {
      vaultWs.close();
      otherWs.close();
    }
  });
});
