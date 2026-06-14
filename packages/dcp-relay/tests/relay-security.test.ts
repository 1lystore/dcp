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
});
