/**
 * DPoP (RFC 9449) — sender-constrained proof-of-possession.
 *
 * Each request carries a `DPoP` header: a JWT signed by the client's private
 * key whose PUBLIC key is embedded in the proof header. The access token is
 * bound to the JWK thumbprint (`cnf.jkt`), so a stolen bearer token is useless
 * without the matching private key. (Security rule #2.)
 */

import { createHash } from 'crypto';
import { jwtVerify, importJWK, decodeProtectedHeader, calculateJwkThumbprint, type JWK } from 'jose';

/** Allowed DPoP proof signing algorithms (asymmetric only). */
const DPOP_ALGS = ['ES256', 'ES384', 'EdDSA', 'RS256', 'PS256'] as const;

export interface DpopVerifyOptions {
  /** HTTP method of the request the proof covers (e.g. 'POST'). */
  method: string;
  /** Full request URL; query/fragment are ignored per RFC 9449 §4.2. */
  url: string;
  /** Max allowed clock skew / proof age in seconds (default 300). */
  maxAgeSec?: number;
  /** Replay guard for the `jti` claim (required to stop proof replay). */
  jtiGuard: JtiReplayGuard;
  /** When verifying a proof that accompanies an access token, the token to bind via `ath`. */
  accessToken?: string;
  /** Expected DPoP-Nonce (when the AS issued one). */
  expectedNonce?: string;
}

export interface DpopVerifyResult {
  /** JWK thumbprint of the proof key — bind the access token to this (`cnf.jkt`). */
  jkt: string;
  /** The proof's `jti` (already recorded as used). */
  jti: string;
}

export class DpopError extends Error {
  constructor(
    public code: string,
    message: string
  ) {
    super(message);
    this.name = 'DpopError';
  }
}

/** Replay guard: returns true if a jti was already seen (and records it otherwise). */
export interface JtiReplayGuard {
  seen(jti: string): boolean;
}

/** Simple in-memory jti replay guard with TTL eviction. */
export function createJtiGuard(ttlMs = 5 * 60 * 1000): JtiReplayGuard & { size(): number } {
  const seenMap = new Map<string, number>();
  let lastSweep = 0;
  const sweep = (now: number) => {
    if (now - lastSweep < 30_000) return;
    lastSweep = now;
    for (const [jti, exp] of seenMap) if (exp <= now) seenMap.delete(jti);
  };
  return {
    seen(jti: string): boolean {
      const now = Date.now();
      sweep(now);
      if (seenMap.has(jti)) return true;
      seenMap.set(jti, now + ttlMs);
      return false;
    },
    size: () => seenMap.size,
  };
}

/** Normalize an htu/URL for comparison: scheme+authority+path, no query/fragment. */
function normalizeHtu(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

/** base64url(SHA-256(input)) — used for the DPoP `ath` access-token hash. */
function sha256Base64Url(input: string): string {
  return createHash('sha256').update(input, 'ascii').digest('base64url');
}

/**
 * Verify a DPoP proof JWT. Throws DpopError on any failure; returns the bound
 * JWK thumbprint (jkt) and jti on success.
 */
export async function verifyDpopProof(
  proof: string,
  opts: DpopVerifyOptions
): Promise<DpopVerifyResult> {
  if (!proof || typeof proof !== 'string') {
    throw new DpopError('invalid_dpop_proof', 'Missing DPoP proof');
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw new DpopError('invalid_dpop_proof', 'Malformed DPoP proof header');
  }

  if (header.typ !== 'dpop+jwt') {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof typ must be dpop+jwt');
  }
  if (!header.alg || !DPOP_ALGS.includes(header.alg as (typeof DPOP_ALGS)[number])) {
    throw new DpopError('invalid_dpop_proof', `Unsupported DPoP alg: ${header.alg}`);
  }
  const jwk = header.jwk as JWK | undefined;
  if (!jwk || typeof jwk !== 'object') {
    throw new DpopError('invalid_dpop_proof', 'DPoP proof must embed a public jwk');
  }
  // The embedded JWK must be PUBLIC (no private material).
  if ('d' in jwk) {
    throw new DpopError('invalid_dpop_proof', 'DPoP jwk must not contain private key material');
  }

  const maxAgeSec = opts.maxAgeSec ?? 300;
  let key;
  try {
    key = await importJWK(jwk, header.alg);
  } catch {
    throw new DpopError('invalid_dpop_proof', 'DPoP jwk could not be imported');
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(proof, key, {
      algorithms: [...DPOP_ALGS],
      typ: 'dpop+jwt',
      maxTokenAge: `${maxAgeSec}s`,
      clockTolerance: `${maxAgeSec}s`,
    }));
  } catch (e) {
    throw new DpopError('invalid_dpop_proof', `DPoP signature/claims invalid: ${(e as Error).message}`);
  }

  // htm: HTTP method must match.
  if (typeof payload.htm !== 'string' || payload.htm.toUpperCase() !== opts.method.toUpperCase()) {
    throw new DpopError('invalid_dpop_proof', 'DPoP htm does not match request method');
  }
  // htu: HTTP URI must match (sans query/fragment).
  if (typeof payload.htu !== 'string') {
    throw new DpopError('invalid_dpop_proof', 'DPoP htu missing');
  }
  try {
    if (normalizeHtu(payload.htu) !== normalizeHtu(opts.url)) {
      throw new DpopError('invalid_dpop_proof', 'DPoP htu does not match request URL');
    }
  } catch (e) {
    if (e instanceof DpopError) throw e;
    throw new DpopError('invalid_dpop_proof', 'DPoP htu is not a valid URL');
  }
  // iat is enforced by maxTokenAge above; require it to be present.
  if (typeof payload.iat !== 'number') {
    throw new DpopError('invalid_dpop_proof', 'DPoP iat missing');
  }
  // jti: required + single-use (anti-replay).
  if (typeof payload.jti !== 'string' || payload.jti.length < 8) {
    throw new DpopError('invalid_dpop_proof', 'DPoP jti missing or too short');
  }
  if (opts.jtiGuard.seen(payload.jti)) {
    throw new DpopError('dpop_replay', 'DPoP proof replayed (jti already used)');
  }
  // Optional nonce binding.
  if (opts.expectedNonce && payload.nonce !== opts.expectedNonce) {
    throw new DpopError('use_dpop_nonce', 'DPoP nonce mismatch');
  }
  // ath: when bound to an access token, the hash must match.
  if (opts.accessToken) {
    const expectedAth = sha256Base64Url(opts.accessToken);
    if (payload.ath !== expectedAth) {
      throw new DpopError('invalid_dpop_proof', 'DPoP ath does not match access token');
    }
  }

  const jkt = await calculateJwkThumbprint(jwk, 'sha256');
  return { jkt, jti: payload.jti };
}

/** Compute the JWK thumbprint (jkt) for a public JWK — the value bound as cnf.jkt. */
export async function jwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, 'sha256');
}
