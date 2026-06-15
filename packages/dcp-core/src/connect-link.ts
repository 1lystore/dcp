/**
 * Cloud-Connect Link (Cloud Agent Connect feature)
 *
 * A one-time, key-pinned bootstrap credential that a user pastes into a cloud
 * agent (OpenClaw / Hermes / Claude.ai / ChatGPT) to connect it to their
 * on-device vault. Encoded as: dcp_connect_v1_<base64url(JSON)>
 *
 * Security design (see docs/cloud-connect-prd.md §4):
 *  - The link PINS the vault's HPKE public key + fingerprint (out-of-band trust
 *    anchor) so a hostile relay cannot MITM the end-to-end channel. (Rule #1)
 *  - The link is a SINGLE-USE, short-lived (<=10 min) bootstrap only — never a
 *    standing credential. It is exchanged for a vault-issued session token only
 *    AFTER the user approves on-device. (Rule #8 — inert until human-approved)
 *  - Like the pairing grant, the link carries NO permission authority. Scopes
 *    and budget live ONLY in the vault policy DB; the link's `agent_name` is for
 *    display. The vault never trusts link-embedded strings as authority. (Rule #6)
 *  - The payload is signed by the vault's Ed25519 signing key so the pinned key
 *    and identifiers are tamper-evident.
 */

import { randomBytes, randomUUID, createHash, randomInt } from 'crypto';
import { signMessage, verifySignature, canonicalJson } from './crypto.js';
import { AgentConnectionMode } from './types.js';

// ============================================================================
// Constants
// ============================================================================

/** Connect-link token prefix */
export const CONNECT_LINK_PREFIX = 'dcp_connect_v1_';

/**
 * Default TTL for connect-links: 10 minutes.
 * Connect-links are bootstrap-only and MUST be short-lived (PRD §2, §4).
 */
export const DEFAULT_CONNECT_LINK_TTL_MS = 10 * 60 * 1000;

/** Number of random bytes in the single-use bootstrap secret. */
export const CONNECT_LINK_SECRET_BYTES = 32;

/**
 * Match-code alphabet — unambiguous (no 0/O/1/I/L) so the user can reliably
 * compare the code shown on the agent side against the code shown on-device.
 */
const MATCH_CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

/** Match-code length (characters). */
export const MATCH_CODE_LENGTH = 6;

// ============================================================================
// Types
// ============================================================================

/**
 * The signed portion of a connect-link.
 *
 * Carries identifiers + the PINNED vault HPKE key, but NO permission authority
 * (scopes/budget live only in the vault policy DB — mirrors SignedPairingGrant).
 */
export interface ConnectLinkPayload {
  version: 1;
  /** Connect-link id (also the DB row key). */
  link_id: string;
  /** Vault this link targets. */
  vault_id: string;
  /** Pre-allocated agent id this link will create/bind on redemption. */
  agent_id: string;
  /** Human display name for the agent (NOT authority). */
  agent_name: string;
  /** Connection mode (cloud agents use 'mcp'). */
  mode: AgentConnectionMode;
  /**
   * Where the agent connects (the relay per-vault MCP URL). May be '' in
   * vault-only flows where the relay facade is not yet configured.
   */
  relay_url: string;
  /** PINNED vault HPKE public key (base64) — out-of-band trust anchor (Rule #1). */
  vault_hpke_public_key: string;
  /** SHA-256 fingerprint (hex) of the pinned HPKE key, for display + pin checks. */
  vault_hpke_fingerprint: string;
  /** Vault Ed25519 signing public key (base64) — verifies this payload. */
  vault_signing_public_key: string;
  /** The single-use bootstrap secret (high entropy). Stored hashed by the vault. */
  secret: string;
  created_at: string;
  expires_at: string;
}

/** The full encoded connect-link envelope. */
export interface EncodedConnectLink {
  payload: ConnectLinkPayload;
  /** Base64 Ed25519 signature over canonicalJson(payload). */
  signature: string;
}

/** Input for issuing a connect-link. */
export interface CreateConnectLinkInput {
  vault_id: string;
  agent_id: string;
  agent_name: string;
  mode: AgentConnectionMode;
  relay_url: string;
  vault_hpke_public_key: string;
  vault_signing_public_key: string;
  /** Provide to override the generated id (otherwise auto-generated). */
  link_id?: string;
  /** Provide to override the generated secret (otherwise auto-generated). */
  secret?: string;
  ttl_ms?: number;
}

/** Result of issuing a connect-link. */
export interface CreateConnectLinkResult {
  /** The pasteable token: dcp_connect_v1_<base64url>. */
  token: string;
  link_id: string;
  agent_id: string;
  /** The single-use secret (also embedded in the token; returned for hashing). */
  secret: string;
  vault_hpke_fingerprint: string;
  created_at: string;
  expires_at: string;
}

// ============================================================================
// Fingerprint + match-code helpers
// ============================================================================

/**
 * Compute the SHA-256 fingerprint (hex) of an HPKE public key.
 * Hashes the raw key bytes (base64-decoded) so the fingerprint pins the key,
 * not its encoding.
 */
export function hpkeFingerprint(hpkePublicKeyBase64: string): string {
  const keyBytes = Buffer.from(hpkePublicKeyBase64, 'base64');
  return createHash('sha256').update(keyBytes).digest('hex');
}

/**
 * Format a fingerprint for human display (grouped, first 16 hex chars).
 * e.g. "a1b2 c3d4 e5f6 0718"
 */
export function formatFingerprint(fingerprintHex: string): string {
  return (fingerprintHex.slice(0, 16).match(/.{1,4}/g) || []).join(' ');
}

/**
 * Generate a phishing-resistant match-code using a CSPRNG (crypto.randomInt).
 * Shown on BOTH the agent side and the on-device approval so the user confirms
 * they match before approving (anti cross-device phishing — Rule #6).
 */
export function generateMatchCode(length: number = MATCH_CODE_LENGTH): string {
  let code = '';
  for (let i = 0; i < length; i++) {
    code += MATCH_CODE_ALPHABET[randomInt(MATCH_CODE_ALPHABET.length)];
  }
  return code;
}

/** Hash the bootstrap secret for at-rest storage (never store plaintext). */
export function hashConnectLinkSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

// ============================================================================
// Connect-link creation
// ============================================================================

/**
 * Create a signed, single-use connect-link.
 *
 * @param input - Link parameters (identifiers + pinned keys). NO scopes/budget.
 * @param signingPrivateKey - 64-byte Ed25519 vault signing private key.
 */
export function createConnectLink(
  input: CreateConnectLinkInput,
  signingPrivateKey: Buffer
): CreateConnectLinkResult {
  const now = new Date();
  const ttl = input.ttl_ms ?? DEFAULT_CONNECT_LINK_TTL_MS;
  const expiresAt = new Date(now.getTime() + ttl);

  const linkId = input.link_id || `cl_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const secret = input.secret || randomBytes(CONNECT_LINK_SECRET_BYTES).toString('base64url');
  const fingerprint = hpkeFingerprint(input.vault_hpke_public_key);

  const payload: ConnectLinkPayload = {
    version: 1,
    link_id: linkId,
    vault_id: input.vault_id,
    agent_id: input.agent_id,
    agent_name: input.agent_name,
    mode: input.mode,
    relay_url: input.relay_url,
    vault_hpke_public_key: input.vault_hpke_public_key,
    vault_hpke_fingerprint: fingerprint,
    vault_signing_public_key: input.vault_signing_public_key,
    secret,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };

  const canonicalPayload = canonicalJson(payload);
  const signature = signMessage(Buffer.from(canonicalPayload, 'utf8'), signingPrivateKey);

  const encoded: EncodedConnectLink = {
    payload,
    signature: signature.toString('base64'),
  };

  const base64url = Buffer.from(JSON.stringify(encoded), 'utf8').toString('base64url');

  return {
    token: CONNECT_LINK_PREFIX + base64url,
    link_id: linkId,
    agent_id: input.agent_id,
    secret,
    vault_hpke_fingerprint: fingerprint,
    created_at: payload.created_at,
    expires_at: payload.expires_at,
  };
}

// ============================================================================
// Connect-link decoding + verification
// ============================================================================

/**
 * Decode a connect-link token WITHOUT verifying the signature.
 * @returns The envelope, or null if the format is invalid.
 */
export function decodeConnectLink(token: string): EncodedConnectLink | null {
  if (!token.startsWith(CONNECT_LINK_PREFIX)) {
    return null;
  }
  try {
    const base64url = token.slice(CONNECT_LINK_PREFIX.length);
    const jsonStr = Buffer.from(base64url, 'base64url').toString('utf8');
    const decoded = JSON.parse(jsonStr) as EncodedConnectLink;

    if (!decoded.payload || !decoded.signature) {
      return null;
    }
    if (decoded.payload.version !== 1) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Verify a connect-link against a KNOWN vault signing public key.
 *
 * Use the vault's own key (not the embedded one) so a tampered link can't
 * self-certify. Checks signature + expiry.
 *
 * @returns The verified payload, or null if invalid/expired.
 */
export function verifyConnectLinkWithKey(
  token: string,
  vaultSigningPublicKey: Buffer
): ConnectLinkPayload | null {
  const decoded = decodeConnectLink(token);
  if (!decoded) {
    return null;
  }
  try {
    const signature = Buffer.from(decoded.signature, 'base64');
    const message = Buffer.from(canonicalJson(decoded.payload), 'utf8');
    if (!verifySignature(message, signature, vaultSigningPublicKey)) {
      return null;
    }
    if (new Date(decoded.payload.expires_at) < new Date()) {
      return null;
    }
    return decoded.payload;
  } catch {
    return null;
  }
}

/** Check whether a token looks like a connect-link. */
export function isConnectLink(token: string): boolean {
  return token.startsWith(CONNECT_LINK_PREFIX);
}
