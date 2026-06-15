/**
 * Access tokens — short-lived, DPoP-bound, audience-bound JWTs.
 *
 * Each access token is:
 *  - signed by the relay AS (ES256),
 *  - bound to ONE vault via the `aud` / resource indicator (RFC 8707) so a token
 *    for vault A is rejected by vault B,
 *  - sender-constrained via `cnf.jkt` (the DPoP key thumbprint, RFC 9449),
 *  - short-lived (~10 min) — refresh tokens (rotating, reuse-detected) handle renewal.
 */

import { SignJWT, jwtVerify } from 'jose';
import { randomUUID } from 'crypto';
import type { RelayOAuthKeys } from './keys.js';

/** Default access-token lifetime: 10 minutes. */
export const DEFAULT_ACCESS_TOKEN_TTL_SEC = 10 * 60;

export interface IssueAccessTokenInput {
  keys: RelayOAuthKeys;
  issuer: string;
  /** Agent id (subject). */
  subject: string;
  /** Audience = the per-vault resource (e.g. https://relay/v/<vault_id>/mcp). RFC 8707. */
  audience: string;
  /** The vault this token may act on. */
  vaultId: string;
  /** Granted scope string (space-delimited). */
  scope: string;
  /**
   * DPoP JWK thumbprint to sender-bind the token (cnf.jkt, RFC 9449). OPTIONAL:
   * when the client supports DPoP we bind the token to its key (preferred —
   * stops token replay). When omitted (the client is Bearer-only, as most current
   * MCP clients are), we issue a plain Bearer token — still audience-bound, short-
   * lived, scoped, and revocable, with on-device consent gating every sensitive op.
   */
  jkt?: string;
  ttlSec?: number;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  vault_id: string;
  scope: string;
  /** Present only for DPoP-bound (sender-constrained) tokens. */
  cnf?: { jkt: string };
  jti: string;
  iat: number;
  exp: number;
}

/** Issue a signed, audience-bound access token (DPoP-bound when a jkt is given). */
export async function issueAccessToken(input: IssueAccessTokenInput): Promise<string> {
  const ttl = input.ttlSec ?? DEFAULT_ACCESS_TOKEN_TTL_SEC;
  const claims: Record<string, unknown> = {
    scope: input.scope,
    vault_id: input.vaultId,
  };
  if (input.jkt) claims.cnf = { jkt: input.jkt };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: input.keys.alg, kid: input.keys.kid, typ: 'at+jwt' })
    .setIssuer(input.issuer)
    .setSubject(input.subject)
    .setAudience(input.audience)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(`${ttl}s`)
    .sign(input.keys.privateKey);
}

export interface VerifyAccessTokenInput {
  keys: RelayOAuthKeys;
  token: string;
  issuer: string;
  /** The resource the token is being presented to — must equal `aud` (RFC 8707). */
  expectedAudience: string;
  /** DPoP thumbprint from the accompanying proof — must equal `cnf.jkt`. */
  expectedJkt?: string;
}

export class AccessTokenError extends Error {
  constructor(
    public code: string,
    message: string
  ) {
    super(message);
    this.name = 'AccessTokenError';
  }
}

/**
 * Verify an access token: signature, issuer, audience binding, and (when given)
 * the DPoP sender-binding. Throws AccessTokenError on any mismatch.
 */
export async function verifyAccessToken(
  input: VerifyAccessTokenInput
): Promise<AccessTokenClaims> {
  let payload;
  try {
    ({ payload } = await jwtVerify(input.token, input.keys.publicKey, {
      issuer: input.issuer,
      audience: input.expectedAudience,
      algorithms: [input.keys.alg],
      typ: 'at+jwt',
    }));
  } catch (e) {
    throw new AccessTokenError('invalid_token', `Access token invalid: ${(e as Error).message}`);
  }

  // DPoP-bound tokens carry cnf.jkt and MUST match the presented proof key. Bearer
  // tokens (no cnf) are accepted without a proof — the caller decides whether a
  // given resource requires sender-binding. A DPoP-bound token presented WITHOUT a
  // proof key (expectedJkt undefined) is rejected, so a stolen DPoP token can't be
  // downgraded to Bearer use.
  const cnf = payload.cnf as { jkt?: string } | undefined;
  if (cnf && typeof cnf.jkt === 'string') {
    if (input.expectedJkt === undefined) {
      throw new AccessTokenError('invalid_token', 'DPoP-bound token requires a DPoP proof');
    }
    if (cnf.jkt !== input.expectedJkt) {
      throw new AccessTokenError('invalid_token', 'DPoP key does not match token binding (cnf.jkt)');
    }
  }

  return payload as unknown as AccessTokenClaims;
}
