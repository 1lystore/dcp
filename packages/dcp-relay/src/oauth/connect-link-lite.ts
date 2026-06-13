/**
 * Minimal, UNTRUSTED connect-link parsing for routing only.
 *
 * The relay must not depend on the heavy @dcprotocol/core package, and it does
 * not need to: it only needs the `vault_id` (and `link_id`) to route the redeem
 * to the right vault. The VAULT performs full signature verification + decoding.
 * Never trust any field returned here for an authorization decision.
 */

const CONNECT_LINK_PREFIX = 'dcp_connect_v1_';

export interface ConnectLinkRouting {
  vault_id: string;
  link_id: string;
}

export function isConnectLinkToken(token: string): boolean {
  return typeof token === 'string' && token.startsWith(CONNECT_LINK_PREFIX);
}

/**
 * Extract routing fields from a connect-link token without verifying it.
 * Returns null if the token is not a well-formed connect-link envelope.
 */
export function parseConnectLinkRouting(token: string): ConnectLinkRouting | null {
  if (!isConnectLinkToken(token)) return null;
  try {
    const b64 = token.slice(CONNECT_LINK_PREFIX.length);
    const json = Buffer.from(b64, 'base64url').toString('utf8');
    const decoded = JSON.parse(json) as { payload?: { vault_id?: unknown; link_id?: unknown } };
    const vault_id = decoded?.payload?.vault_id;
    const link_id = decoded?.payload?.link_id;
    if (typeof vault_id !== 'string' || !vault_id) return null;
    if (typeof link_id !== 'string' || !link_id) return null;
    return { vault_id, link_id };
  } catch {
    return null;
  }
}
