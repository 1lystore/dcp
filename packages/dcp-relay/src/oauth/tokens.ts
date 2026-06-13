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
  /** DPoP JWK thumbprint to sender-bind the token (cnf.jkt). */
  jkt: string;
  ttlSec?: number;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  vault_id: string;
  scope: string;
  cnf: { jkt: string };
  jti: string;
  iat: number;
  exp: number;
}

/** Issue a signed, DPoP-bound, audience-bound access token. */
export async function issueAccessToken(input: IssueAccessTokenInput): Promise<string> {
  const ttl = input.ttlSec ?? DEFAULT_ACCESS_TOKEN_TTL_SEC;
  return new SignJWT({
    scope: input.scope,
    vault_id: input.vaultId,
    cnf: { jkt: input.jkt },
  })
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

  const cnf = payload.cnf as { jkt?: string } | undefined;
  if (!cnf || typeof cnf.jkt !== 'string') {
    throw new AccessTokenError('invalid_token', 'Access token is not DPoP-bound (missing cnf.jkt)');
  }
  if (input.expectedJkt !== undefined && cnf.jkt !== input.expectedJkt) {
    throw new AccessTokenError('invalid_token', 'DPoP key does not match token binding (cnf.jkt)');
  }

  return payload as unknown as AccessTokenClaims;
}
