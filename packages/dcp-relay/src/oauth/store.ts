/**
 * In-memory state for the relay OAuth Authorization Server.
 *
 *  - ClientStore:        Dynamic Client Registration (RFC 7591). Self-registered
 *                        clients are UNTRUSTED display strings; the real gate is
 *                        the on-device approval at the vault (Rule #8).
 *  - AuthSessionStore:   connect-link-driven authorization sessions (device-flow-
 *                        like): pending_approval -> approved -> issued, bound to the
 *                        agent's DPoP key + PKCE challenge.
 *  - RefreshTokenStore:  rotating refresh tokens with REUSE DETECTION — presenting
 *                        an already-rotated token revokes the whole chain (Rule #3).
 *
 * All records are TTL'd and swept lazily. This is process-local (one relay node);
 * a multi-node deployment would back these with shared storage.
 */

import { randomUUID, randomBytes, createHash } from 'crypto';

const sha256Hex = (s: string): string => createHash('sha256').update(s).digest('hex');

// ============================================================================
// Dynamic Client Registration (RFC 7591)
// ============================================================================

export interface RegisteredClient {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: 'none';
  created_at: number;
}

export class ClientStore {
  private clients = new Map<string, RegisteredClient>();

  /** Register a public client. Display strings are stored but treated as untrusted. */
  register(input: { client_name?: string; redirect_uris?: string[] }): RegisteredClient {
    const client: RegisteredClient = {
      client_id: `dcpc_${randomUUID().replace(/-/g, '')}`,
      client_name: typeof input.client_name === 'string' ? input.client_name.slice(0, 200) : undefined,
      redirect_uris: Array.isArray(input.redirect_uris)
        ? input.redirect_uris.filter((u) => typeof u === 'string').slice(0, 10)
        : [],
      token_endpoint_auth_method: 'none',
      created_at: Date.now(),
    };
    this.clients.set(client.client_id, client);
    return client;
  }

  get(clientId: string): RegisteredClient | undefined {
    return this.clients.get(clientId);
  }
}

// ============================================================================
// Authorization sessions (connect-link-driven)
// ============================================================================

export type AuthSessionStatus =
  | 'pending_approval'
  | 'approved'
  | 'issued'
  | 'denied'
  | 'expired';

export interface AuthSession {
  session_id: string;
  vault_id: string;
  link_id: string;
  agent_id?: string;
  /** DPoP JWK thumbprint the eventual token is bound to. */
  agent_jkt: string;
  /** PKCE S256 challenge supplied at connect; verified at token issuance. */
  code_challenge: string;
  scope: string;
  audience: string;
  match_code?: string;
  client_id?: string;
  status: AuthSessionStatus;
  created_at: number;
  expires_at: number;
}

export class AuthSessionStore {
  private sessions = new Map<string, AuthSession>();

  constructor(private ttlMs = 15 * 60 * 1000) {}

  create(input: {
    vault_id: string;
    link_id: string;
    agent_jkt: string;
    code_challenge: string;
    scope: string;
    audience: string;
    match_code?: string;
    client_id?: string;
    agent_id?: string;
  }): AuthSession {
    this.sweep();
    const now = Date.now();
    const session: AuthSession = {
      session_id: `as_${randomUUID().replace(/-/g, '')}`,
      vault_id: input.vault_id,
      link_id: input.link_id,
      agent_id: input.agent_id,
      agent_jkt: input.agent_jkt,
      code_challenge: input.code_challenge,
      scope: input.scope,
      audience: input.audience,
      match_code: input.match_code,
      client_id: input.client_id,
      status: 'pending_approval',
      created_at: now,
      expires_at: now + this.ttlMs,
    };
    this.sessions.set(session.session_id, session);
    return session;
  }

  get(sessionId: string): AuthSession | undefined {
    const s = this.sessions.get(sessionId);
    if (!s) return undefined;
    if (s.expires_at <= Date.now() && s.status !== 'issued') {
      s.status = 'expired';
    }
    return s;
  }

  setStatus(sessionId: string, status: AuthSessionStatus, agentId?: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    s.status = status;
    if (agentId) s.agent_id = agentId;
    return true;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, s] of this.sessions) {
      if (s.expires_at + 5 * 60 * 1000 <= now) this.sessions.delete(id);
    }
  }
}

// ============================================================================
// Rotating refresh tokens with reuse detection (Rule #3)
// ============================================================================

export interface RefreshContext {
  vault_id: string;
  agent_id: string;
  jkt: string;
  scope: string;
  audience: string;
}

interface RefreshRecord extends RefreshContext {
  token_hash: string;
  chain_id: string;
  created_at: number;
  expires_at: number;
  /** True once this token has been rotated (a fresh one issued from it). */
  used: boolean;
  /** True once the chain was revoked (reuse / explicit / agent revoke). */
  revoked: boolean;
}

export interface RotateResult {
  ok: boolean;
  reason?: 'not_found' | 'expired' | 'revoked' | 'reuse_detected';
  token?: string;
  context?: RefreshContext;
}

export class RefreshTokenStore {
  private byHash = new Map<string, RefreshRecord>();
  /** chain_id -> revoked. A revoked chain rejects all its tokens. */
  private revokedChains = new Set<string>();

  constructor(private ttlMs = 30 * 24 * 60 * 60 * 1000) {}

  /** Issue the first refresh token of a NEW chain. */
  issue(ctx: RefreshContext): { token: string; chain_id: string } {
    const chain_id = `rc_${randomUUID().replace(/-/g, '')}`;
    const token = this.mint(ctx, chain_id);
    return { token, chain_id };
  }

  private mint(ctx: RefreshContext, chain_id: string): string {
    this.sweep();
    const token = `dcprt_${randomBytes(32).toString('base64url')}`;
    const now = Date.now();
    this.byHash.set(sha256Hex(token), {
      ...ctx,
      token_hash: sha256Hex(token),
      chain_id,
      created_at: now,
      expires_at: now + this.ttlMs,
      used: false,
      revoked: false,
    });
    return token;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [hash, rec] of this.byHash) {
      // Drop expired records, and revoked records after a short grace (so a
      // legit client still gets an informative 'revoked' for a while).
      if (rec.expires_at <= now) this.byHash.delete(hash);
      else if (rec.revoked && now - rec.created_at > 60 * 60 * 1000) this.byHash.delete(hash);
    }
  }

  /**
   * Rotate a refresh token. On success returns a fresh token (same chain) and the
   * bound context. If a token that was ALREADY rotated is presented again, that is
   * reuse — the ENTIRE chain is revoked and rotation fails (Rule #3).
   */
  rotate(presentedToken: string): RotateResult {
    const rec = this.byHash.get(sha256Hex(presentedToken));
    if (!rec) return { ok: false, reason: 'not_found' };
    if (rec.revoked || this.revokedChains.has(rec.chain_id)) return { ok: false, reason: 'revoked' };
    if (rec.expires_at <= Date.now()) return { ok: false, reason: 'expired' };
    if (rec.used) {
      // Replay of a spent token -> revoke the whole family.
      this.revokeChain(rec.chain_id);
      return { ok: false, reason: 'reuse_detected' };
    }
    rec.used = true;
    const ctx: RefreshContext = {
      vault_id: rec.vault_id,
      agent_id: rec.agent_id,
      jkt: rec.jkt,
      scope: rec.scope,
      audience: rec.audience,
    };
    const token = this.mint(ctx, rec.chain_id);
    return { ok: true, token, context: ctx };
  }

  /** Revoke an entire refresh-token chain (e.g. on reuse or explicit revoke). */
  revokeChain(chainId: string): void {
    this.revokedChains.add(chainId);
    for (const rec of this.byHash.values()) {
      if (rec.chain_id === chainId) rec.revoked = true;
    }
  }

  /** Revoke all chains bound to an agent (instant-revoke path, Rule #7). */
  revokeByAgent(agentId: string): number {
    const chains = new Set<string>();
    for (const rec of this.byHash.values()) {
      if (rec.agent_id === agentId) chains.add(rec.chain_id);
    }
    for (const c of chains) this.revokeChain(c);
    return chains.size;
  }

  /** Look up the chain for a live (un-rotated) token — for revocation endpoints. */
  chainFor(token: string): string | undefined {
    return this.byHash.get(sha256Hex(token))?.chain_id;
  }
}
