/**
 * Signed Pairing Grant (protocol spec section 7.1)
 *
 * Self-describing, signed tokens for agent pairing.
 * Format: dcp_pair_v1_<base64url(JSON)>
 */

import { randomUUID, createHash } from 'crypto';
import * as bip39 from 'bip39';
import { signMessage, verifySignature, canonicalJson } from './crypto.js';
import {
  SignedPairingGrant,
  EncodedPairingGrant,
  SessionTokenPayload,
  EncodedSessionToken,
  AgentConnectionMode,
  AgentConnectionTier,
  VaultError,
} from './types.js';

// ============================================================================
// Constants
// ============================================================================

/** Pairing grant token prefix */
export const PAIRING_GRANT_PREFIX = 'dcp_pair_v1_';

/** Session token prefix */
export const SESSION_TOKEN_PREFIX = 'dcp_session_v1_';

/** Default TTL for pairing grants: 1 hour */
export const DEFAULT_PAIRING_TTL_MS = 60 * 60 * 1000;

/** Default TTL for session tokens: 24 hours */
export const DEFAULT_SESSION_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

// ============================================================================
// Pairing Grant Creation
// ============================================================================

/**
 * Input for creating a pairing grant.
 *
 * IMPORTANT: This is a REQUEST-ONLY invite for connection bootstrap.
 * Permissions are stored ONLY in the vault policy DB.
 */
export interface CreatePairingGrantInput {
  vault_id: string;
  agent_id: string;
  agent_name: string;
  mode: AgentConnectionMode;
  vault_hpke_public_key: string;
  vault_signing_public_key: string;
  relay_url: string;
  ttl_ms?: number;

  /**
   * @deprecated Permission scopes should be stored ONLY in vault policy DB.
   * These fields are ignored in new grants but kept for backward compatibility.
   */
  permission_scopes?: string[];
  /** @deprecated See permission_scopes */
  budget?: {
    daily: number;
    currency: string;
    auto_approve_under: number;
  };
  /** @deprecated See permission_scopes */
  tier?: AgentConnectionTier;
}

/**
 * Create a signed pairing grant
 *
 * IMPORTANT: This creates a REQUEST-ONLY invite for connection bootstrap.
 * The vault policy DB is the ONLY enforcement source for permissions.
 * The deprecated permission_scopes, budget, and tier fields are NOT included.
 *
 * @param input - Grant parameters
 * @param signingPrivateKey - 64-byte Ed25519 private key for signing
 * @returns Encoded grant string (dcp_pair_v1_<base64url>)
 */
export function createSignedPairingGrant(
  input: CreatePairingGrantInput,
  signingPrivateKey: Buffer
): string {
  const now = new Date();
  const ttl = input.ttl_ms ?? DEFAULT_PAIRING_TTL_MS;
  const expiresAt = new Date(now.getTime() + ttl);

  // Create request-only invite - NO permission authority
  // Permissions are stored ONLY in vault policy DB
  const payload: SignedPairingGrant = {
    version: 1,
    grant_id: `grant_${randomUUID().replace(/-/g, '').slice(0, 12)}`,
    vault_id: input.vault_id,
    agent_id: input.agent_id,
    agent_name: input.agent_name,
    mode: input.mode,
    vault_hpke_public_key: input.vault_hpke_public_key,
    vault_signing_public_key: input.vault_signing_public_key,
    relay_url: input.relay_url,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    // NOTE: permission_scopes, budget, and tier are intentionally NOT included
    // These are stored ONLY in the vault policy database
  };

  // Canonical JSON for signing (sorted keys)
  const canonicalPayload = canonicalJson(payload);
  const signature = signMessage(Buffer.from(canonicalPayload, 'utf8'), signingPrivateKey);

  const encoded: EncodedPairingGrant = {
    payload,
    signature: signature.toString('base64'),
  };

  // Encode to base64url
  const jsonStr = JSON.stringify(encoded);
  const base64url = Buffer.from(jsonStr, 'utf8').toString('base64url');

  return PAIRING_GRANT_PREFIX + base64url;
}

// ============================================================================
// Pairing Grant Decoding
// ============================================================================

/**
 * Decode a pairing grant token (without verification)
 *
 * @param token - Encoded token string (dcp_pair_v1_<base64url>)
 * @returns Decoded grant or null if invalid format
 */
export function decodePairingGrant(token: string): EncodedPairingGrant | null {
  if (!token.startsWith(PAIRING_GRANT_PREFIX)) {
    return null;
  }

  try {
    const base64url = token.slice(PAIRING_GRANT_PREFIX.length);
    const jsonStr = Buffer.from(base64url, 'base64url').toString('utf8');
    const decoded = JSON.parse(jsonStr) as EncodedPairingGrant;

    // Basic structure validation
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

// ============================================================================
// Pairing Grant Verification
// ============================================================================

/**
 * Verify and decode a pairing grant token
 *
 * Checks:
 * 1. Valid format (dcp_pair_v1_ prefix)
 * 2. Valid signature using vault's signing public key
 * 3. Not expired
 *
 * @param token - Encoded token string
 * @returns Verified payload or null if invalid
 */
export function verifyPairingGrant(token: string): SignedPairingGrant | null {
  const decoded = decodePairingGrant(token);
  if (!decoded) {
    return null;
  }

  try {
    // Verify signature using the public key embedded in the payload
    const publicKey = Buffer.from(decoded.payload.vault_signing_public_key, 'base64');
    const signature = Buffer.from(decoded.signature, 'base64');
    const canonicalPayload = canonicalJson(decoded.payload);
    const message = Buffer.from(canonicalPayload, 'utf8');

    if (!verifySignature(message, signature, publicKey)) {
      return null;
    }

    // Check expiration
    const expiresAt = new Date(decoded.payload.expires_at);
    if (expiresAt < new Date()) {
      return null;
    }

    return decoded.payload;
  } catch {
    return null;
  }
}

/**
 * Verify a pairing grant with a known public key
 *
 * Use this when you already have the vault's public key
 * (more secure than trusting the embedded key)
 *
 * @param token - Encoded token string
 * @param vaultSigningPublicKey - Known vault signing public key
 * @returns Verified payload or null if invalid
 */
export function verifyPairingGrantWithKey(
  token: string,
  vaultSigningPublicKey: Buffer
): SignedPairingGrant | null {
  const decoded = decodePairingGrant(token);
  if (!decoded) {
    return null;
  }

  try {
    const signature = Buffer.from(decoded.signature, 'base64');
    const canonicalPayload = canonicalJson(decoded.payload);
    const message = Buffer.from(canonicalPayload, 'utf8');

    if (!verifySignature(message, signature, vaultSigningPublicKey)) {
      return null;
    }

    // Check expiration
    const expiresAt = new Date(decoded.payload.expires_at);
    if (expiresAt < new Date()) {
      return null;
    }

    return decoded.payload;
  } catch {
    return null;
  }
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Check if a token looks like a pairing grant
 */
export function isPairingGrant(token: string): boolean {
  return token.startsWith(PAIRING_GRANT_PREFIX);
}

// ============================================================================
// VPS Pairing Invite (for remote agent pairing via relay)
// ============================================================================

/** VPS pairing invite prefix */
export const VPS_INVITE_PREFIX = 'dcp_vps_v1_';

/**
 * VPS pairing invite data
 *
 * This is a simpler invite format for VPS agents that only need to bootstrap
 * a connection via the relay. Unlike SignedPairingGrant, this does NOT carry
 * permission authority - permissions are stored only in the vault policy DB.
 *
 * Flow:
 * 1. Desktop creates invite with vault's public key
 * 2. VPS agent parses invite and generates its own keypair
 * 3. VPS submits signed pairing claim to relay
 * 4. Relay routes claim to vault (via invite_id)
 * 5. Desktop shows pending pairing with verification phrase
 * 6. User approves in Desktop, creates agent in vault policy DB
 * 7. VPS agent polls for approval, receives agent_id
 */
export interface VpsPairingInvite {
  version: number;
  invite_id: string;
  vault_id: string;
  relay_url: string;
  /** Vault's HPKE public key for encrypting messages (base64) */
  vault_public_key: string;
  /** Vault's Ed25519 signing public key for verifying responses (base64) */
  vault_signing_key: string;
  /** Expiration timestamp (ms since epoch) */
  expires_at: number;
}

/**
 * Create a VPS pairing invite
 *
 * @param vaultId - Vault ID
 * @param relayUrl - Relay server URL
 * @param vaultPublicKey - Vault's HPKE public key (base64)
 * @param vaultSigningKey - Vault's Ed25519 signing public key (base64)
 * @param ttlMs - Time-to-live in milliseconds (default: 1 hour)
 * @returns Encoded invite string (dcp_vps_v1_<base64url>)
 */
export function createVpsPairingInvite(
  vaultId: string,
  relayUrl: string,
  vaultPublicKey: string,
  vaultSigningKey: string,
  ttlMs: number = DEFAULT_PAIRING_TTL_MS
): string {
  const invite: VpsPairingInvite = {
    version: 1,
    invite_id: `inv_${randomUUID().replace(/-/g, '').slice(0, 16)}`,
    vault_id: vaultId,
    relay_url: relayUrl,
    vault_public_key: vaultPublicKey,
    vault_signing_key: vaultSigningKey,
    expires_at: Date.now() + ttlMs,
  };

  const json = JSON.stringify(invite);
  const base64url = Buffer.from(json, 'utf8').toString('base64url');

  return VPS_INVITE_PREFIX + base64url;
}

/**
 * Parse a VPS pairing invite
 *
 * @param invite - Encoded invite string
 * @returns Parsed invite data or null if invalid
 */
export function parseVpsPairingInvite(invite: string): VpsPairingInvite | null {
  if (!invite.startsWith(VPS_INVITE_PREFIX)) {
    return null;
  }

  try {
    const base64url = invite.slice(VPS_INVITE_PREFIX.length);
    const json = Buffer.from(base64url, 'base64url').toString('utf8');
    const data = JSON.parse(json) as VpsPairingInvite;

    // Validate required fields
    if (
      data.version !== 1 ||
      !data.invite_id ||
      !data.vault_id ||
      !data.relay_url ||
      !data.vault_public_key ||
      !data.vault_signing_key ||
      !data.expires_at
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

/**
 * Check if a VPS pairing invite is expired
 */
export function isVpsInviteExpired(invite: VpsPairingInvite): boolean {
  return Date.now() > invite.expires_at;
}

/**
 * Check if a token looks like a VPS pairing invite
 */
export function isVpsPairingInvite(token: string): boolean {
  return token.startsWith(VPS_INVITE_PREFIX);
}

// ============================================================================
// Session Token Creation (for Gateway Authentication)
// ============================================================================

export interface CreateSessionTokenInput {
  vault_id: string;
  agent_id: string;
  agent_name: string;
  tier: AgentConnectionTier;
  scopes: string[];
  ttl_ms?: number;
}

/**
 * Create a signed session token for relay authentication
 *
 * @param input - Token parameters
 * @param signingPrivateKey - 64-byte Ed25519 private key for signing
 * @returns Encoded token string (dcp_session_v1_<base64url>)
 */
export function createSessionToken(
  input: CreateSessionTokenInput,
  signingPrivateKey: Buffer
): string {
  const now = new Date();
  const ttl = input.ttl_ms ?? DEFAULT_SESSION_TOKEN_TTL_MS;
  const expiresAt = new Date(now.getTime() + ttl);

  const payload: SessionTokenPayload = {
    version: 1,
    token_id: `token_${randomUUID().replace(/-/g, '').slice(0, 12)}`,
    vault_id: input.vault_id,
    agent_id: input.agent_id,
    agent_name: input.agent_name,
    tier: input.tier,
    scopes: input.scopes,
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };

  // Canonical JSON for signing (sorted keys)
  const canonicalPayload = canonicalJson(payload);
  const signature = signMessage(Buffer.from(canonicalPayload, 'utf8'), signingPrivateKey);

  const encoded: EncodedSessionToken = {
    payload,
    signature: signature.toString('base64'),
  };

  // Encode to base64url
  const jsonStr = JSON.stringify(encoded);
  const base64url = Buffer.from(jsonStr, 'utf8').toString('base64url');

  return SESSION_TOKEN_PREFIX + base64url;
}

// ============================================================================
// Session Token Decoding
// ============================================================================

/**
 * Decode a session token (without verification)
 *
 * @param token - Encoded token string (dcp_session_v1_<base64url>)
 * @returns Decoded token or null if invalid format
 */
export function decodeSessionToken(token: string): EncodedSessionToken | null {
  if (!token.startsWith(SESSION_TOKEN_PREFIX)) {
    return null;
  }

  try {
    const base64url = token.slice(SESSION_TOKEN_PREFIX.length);
    const jsonStr = Buffer.from(base64url, 'base64url').toString('utf8');
    const decoded = JSON.parse(jsonStr) as EncodedSessionToken;

    // Basic structure validation
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

// ============================================================================
// Session Token Verification
// ============================================================================

/**
 * Verify a session token with a known public key
 *
 * @param token - Encoded token string
 * @param vaultSigningPublicKey - Known vault signing public key (32 bytes)
 * @returns Verified payload or null if invalid
 */
export function verifySessionToken(
  token: string,
  vaultSigningPublicKey: Buffer
): SessionTokenPayload | null {
  const decoded = decodeSessionToken(token);
  if (!decoded) {
    return null;
  }

  try {
    const signature = Buffer.from(decoded.signature, 'base64');
    const canonicalPayload = canonicalJson(decoded.payload);
    const message = Buffer.from(canonicalPayload, 'utf8');

    if (!verifySignature(message, signature, vaultSigningPublicKey)) {
      return null;
    }

    // Check expiration
    const expiresAt = new Date(decoded.payload.expires_at);
    if (expiresAt < new Date()) {
      return null;
    }

    return decoded.payload;
  } catch {
    return null;
  }
}

/**
 * Check if a token looks like a session token
 */
export function isSessionToken(token: string): boolean {
  return token.startsWith(SESSION_TOKEN_PREFIX);
}

// ============================================================================
// Verification Phrase (out-of-band MITM check for remote agent pairing)
// ============================================================================

/**
 * Wordlist and length for the pairing verification phrase.
 *
 * This is the SINGLE source of truth shared by the agent (which shows the phrase
 * on the VPS) and the relay/desktop (which recompute it from the agent's claimed
 * key). Both sides MUST import this — never re-implement it — or the phrases will
 * not match and pairing verification silently fails.
 *
 * Security: the phrase binds the agent's public key. A MITM that substitutes its
 * own key must find a key whose phrase COLLIDES with the legit one. With the
 * BIP-39 2048-word list and 4 words, the space is 2048^4 = 2^44 (~17.6 trillion),
 * making an offline grind within the 10-minute pairing window infeasible. The old
 * 32-word × 3 scheme was only ~2^15 (32k), which is trivially grindable.
 */
const VERIFICATION_PHRASE_WORDLIST = bip39.wordlists.english; // 2048 words = 11 bits each
const VERIFICATION_PHRASE_WORD_COUNT = 4; // 4 * 11 = 44 bits of collision resistance

/** Read `numBits` bits from `buf` starting at `bitOffset`, MSB-first. */
function readBitsBigEndian(buf: Buffer, bitOffset: number, numBits: number): number {
  let value = 0;
  for (let i = 0; i < numBits; i++) {
    const globalBit = bitOffset + i;
    const byteIndex = globalBit >> 3;
    const bitIndex = 7 - (globalBit & 7);
    const bit = (buf[byteIndex] >> bitIndex) & 1;
    value = (value << 1) | bit;
  }
  return value;
}

/**
 * Generate the deterministic verification phrase for a pairing claim.
 *
 * Same inputs (agent public key + invite_id) always produce the same phrase, so
 * the VPS-side and desktop-side displays can be compared by the human operator.
 *
 * @param publicKey - Agent's public key (raw bytes or base64 string)
 * @param inviteId - The invite ID string (e.g. "inv_abc123")
 * @returns A hyphenated 4-word phrase (e.g. "anchor-forest-tiger-ember")
 */
export function generateVerificationPhrase(
  publicKey: Uint8Array | string,
  inviteId: string
): string {
  const publicKeyBytes =
    typeof publicKey === 'string' ? Buffer.from(publicKey, 'base64') : Buffer.from(publicKey);

  const combined = Buffer.concat([publicKeyBytes, Buffer.from(inviteId)]);
  const hash = createHash('sha256').update(combined).digest(); // 32 bytes = 256 bits

  const words: string[] = [];
  for (let i = 0; i < VERIFICATION_PHRASE_WORD_COUNT; i++) {
    const index = readBitsBigEndian(hash, i * 11, 11) % VERIFICATION_PHRASE_WORDLIST.length;
    words.push(VERIFICATION_PHRASE_WORDLIST[index]);
  }
  return words.join('-');
}
