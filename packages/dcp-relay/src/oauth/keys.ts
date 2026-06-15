/**
 * Relay OAuth signing keys.
 *
 * The relay's OAuth 2.1 Authorization Server signs access tokens (JWTs) with an
 * ES256 (P-256) key. In production the key MUST be stable across restarts so
 * issued tokens stay valid — load it from the `DCP_RELAY_OAUTH_PRIVATE_JWK`
 * secret. If absent (dev/test), an ephemeral key is generated and a warning is
 * emitted. The public half is published at the JWKS endpoint for verification.
 *
 * NOTE: this key NEVER touches vault key material. It only authenticates which
 * agent/token may submit requests to a vault; the vault itself still enforces
 * per-action on-device consent. (Relay = untrusted availability infra.)
 */

import {
  generateKeyPair,
  exportJWK,
  importJWK,
  calculateJwkThumbprint,
  type JWK,
  type KeyLike,
} from 'jose';

export const OAUTH_SIGNING_ALG = 'ES256' as const;

export interface RelayOAuthKeys {
  alg: typeof OAUTH_SIGNING_ALG;
  /** Key id (JWK thumbprint) — set in JWT headers and the published JWK. */
  kid: string;
  /** Private signing key (never exported). */
  privateKey: KeyLike;
  /** Public verification key. */
  publicKey: KeyLike;
  /** Public JWK (with kid/alg/use) for the JWKS endpoint. */
  publicJwk: JWK;
  /** RFC 7517 JWK Set document. */
  jwks(): { keys: JWK[] };
}

/**
 * Initialise the relay OAuth signing keys.
 * @param opts.privateJwk - JSON string of a private JWK (from env secret) to reuse.
 * @param opts.warn - sink for the ephemeral-key warning (defaults to console.warn).
 */
export async function initOAuthKeys(opts?: {
  privateJwk?: string;
  warn?: (msg: string) => void;
}): Promise<RelayOAuthKeys> {
  let privateKey: KeyLike;
  let publicKey: KeyLike;

  if (opts?.privateJwk) {
    const jwk = JSON.parse(opts.privateJwk) as JWK;
    privateKey = (await importJWK(jwk, OAUTH_SIGNING_ALG)) as KeyLike;
    // Derive the public key by stripping the private component.
    const { d: _omit, ...pub } = jwk;
    publicKey = (await importJWK({ ...pub, alg: OAUTH_SIGNING_ALG }, OAUTH_SIGNING_ALG)) as KeyLike;
  } else {
    const warn = opts?.warn || ((m: string) => console.warn(m));
    warn(
      '[relay/oauth] No DCP_RELAY_OAUTH_PRIVATE_JWK set — generating an EPHEMERAL signing key. ' +
        'Access tokens will be invalidated on restart. Set the secret for production.'
    );
    const kp = await generateKeyPair(OAUTH_SIGNING_ALG, { extractable: true });
    privateKey = kp.privateKey as KeyLike;
    publicKey = kp.publicKey as KeyLike;
  }

  const publicJwkRaw = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwkRaw, 'sha256');
  const publicJwk: JWK = { ...publicJwkRaw, alg: OAUTH_SIGNING_ALG, use: 'sig', kid };

  return {
    alg: OAUTH_SIGNING_ALG,
    kid,
    privateKey,
    publicKey,
    publicJwk,
    jwks: () => ({ keys: [publicJwk] }),
  };
}

/** Export a freshly-generated private JWK string — helper for provisioning the secret. */
export async function generateOAuthPrivateJwk(): Promise<string> {
  const kp = await generateKeyPair(OAUTH_SIGNING_ALG, { extractable: true });
  const jwk = await exportJWK(kp.privateKey);
  return JSON.stringify({ ...jwk, alg: OAUTH_SIGNING_ALG, use: 'sig' });
}
