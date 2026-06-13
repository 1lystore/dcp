/**
 * Tests for the relay OAuth AS state: DCR clients, authorization sessions, and
 * rotating refresh tokens with reuse detection (Rule #3).
 */

import { describe, it, expect } from 'vitest';
import { ClientStore, AuthSessionStore, RefreshTokenStore } from '../src/oauth/index.js';

describe('ClientStore (DCR)', () => {
  it('issues a client_id and treats display strings as untrusted (clamped)', () => {
    const store = new ClientStore();
    const c = store.register({ client_name: 'x'.repeat(500), redirect_uris: ['https://a', 'https://b'] });
    expect(c.client_id).toMatch(/^dcpc_/);
    expect(c.token_endpoint_auth_method).toBe('none');
    expect((c.client_name || '').length).toBeLessThanOrEqual(200);
    expect(store.get(c.client_id)).toBeTruthy();
  });
});

describe('AuthSessionStore', () => {
  const base = {
    vault_id: 'vault_1',
    link_id: 'cl_1',
    agent_jkt: 'jkt_abc',
    code_challenge: 'chal',
    scope: 'read:wallet.address',
    audience: 'https://relay/v/vault_1/mcp',
    match_code: 'AB23CD',
  };

  it('creates a pending session and transitions through approval', () => {
    const store = new AuthSessionStore();
    const s = store.create(base);
    expect(s.status).toBe('pending_approval');
    expect(s.session_id).toMatch(/^as_/);
    expect(store.setStatus(s.session_id, 'approved', 'agent_1')).toBe(true);
    expect(store.get(s.session_id)!.status).toBe('approved');
    expect(store.get(s.session_id)!.agent_id).toBe('agent_1');
  });

  it('auto-expires a stale, unissued session', () => {
    const store = new AuthSessionStore(-1); // already expired
    const s = store.create(base);
    expect(store.get(s.session_id)!.status).toBe('expired');
  });
});

describe('RefreshTokenStore (rotation + reuse detection)', () => {
  const ctx = {
    vault_id: 'vault_1',
    agent_id: 'agent_1',
    jkt: 'jkt_abc',
    scope: 'read:wallet.address',
    audience: 'https://relay/v/vault_1/mcp',
  };

  it('rotates a token and returns a fresh one bound to the same context', () => {
    const store = new RefreshTokenStore();
    const { token } = store.issue(ctx);
    const r = store.rotate(token);
    expect(r.ok).toBe(true);
    expect(r.token).toBeTruthy();
    expect(r.token).not.toBe(token);
    expect(r.context).toMatchObject({ vault_id: 'vault_1', agent_id: 'agent_1', jkt: 'jkt_abc' });
  });

  it('detects reuse of a spent token and revokes the WHOLE chain (Rule #3)', () => {
    const store = new RefreshTokenStore();
    const { token: t0 } = store.issue(ctx);
    const r1 = store.rotate(t0); // t0 spent, t1 issued
    expect(r1.ok).toBe(true);
    const t1 = r1.token!;

    // Attacker replays the already-rotated t0 -> reuse detected.
    const replay = store.rotate(t0);
    expect(replay.ok).toBe(false);
    expect(replay.reason).toBe('reuse_detected');

    // The legitimate (newer) t1 is now also dead — whole chain revoked.
    const afterRevoke = store.rotate(t1);
    expect(afterRevoke.ok).toBe(false);
    expect(afterRevoke.reason).toBe('revoked');
  });

  it('rejects unknown and revoked-by-agent tokens', () => {
    const store = new RefreshTokenStore();
    expect(store.rotate('dcprt_nope').reason).toBe('not_found');

    const { token } = store.issue(ctx);
    const n = store.revokeByAgent('agent_1');
    expect(n).toBe(1);
    expect(store.rotate(token).ok).toBe(false);
  });

  it('keeps separate chains independent', () => {
    const store = new RefreshTokenStore();
    const a = store.issue(ctx);
    const b = store.issue({ ...ctx, agent_id: 'agent_2' });
    // Reuse on chain A must not affect chain B.
    const a1 = store.rotate(a.token);
    store.rotate(a.token); // reuse -> revoke chain A
    expect(store.rotate(a1.token!).ok).toBe(false);
    expect(store.rotate(b.token).ok).toBe(true);
  });
});
