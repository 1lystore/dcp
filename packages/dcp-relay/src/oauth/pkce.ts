/**
 * PKCE (RFC 7636) — S256 only.
 *
 * OAuth 2.1 requires PKCE. We support ONLY the S256 method (never `plain`),
 * so a code challenge cannot be downgraded.
 */

import { createHash, timingSafeEqual } from 'crypto';

const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

/** Validate a code_verifier per RFC 7636 §4.1 (43–128 unreserved chars). */
export function isValidCodeVerifier(verifier: string): boolean {
  return typeof verifier === 'string' && VERIFIER_RE.test(verifier);
}

/** Compute the S256 code_challenge for a verifier: base64url(SHA-256(verifier)). */
export function computeS256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/**
 * Verify a code_verifier against a stored S256 code_challenge (constant-time).
 * Returns false for malformed input rather than throwing.
 */
export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  if (!isValidCodeVerifier(codeVerifier)) return false;
  if (typeof codeChallenge !== 'string' || codeChallenge.length === 0) return false;
  const expected = Buffer.from(computeS256Challenge(codeVerifier), 'utf8');
  const given = Buffer.from(codeChallenge, 'utf8');
  if (expected.length !== given.length) return false;
  try {
    return timingSafeEqual(expected, given);
  } catch {
    return false;
  }
}
