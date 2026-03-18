/**
 * Authentication for DCP Relay
 *
 * Implements defense-in-depth authentication:
 * 1. Ed25519 signature verification (proof of key possession)
 * 2. Pairing token validation (ties to OAuth flow)
 *
 * SECURITY NOTES:
 * - Timestamps must be within 5 minutes of server time
 * - Nonces are tracked to prevent replay attacks
 * - Signatures use Ed25519 (same curve as HPKE X25519)
 */

import { verify as nodeVerify } from 'crypto';
import type { RegisterPayload } from './types.js';
import { RelayError, MAX_CLOCK_SKEW_MS, MIN_NONCE_SIZE } from './types.js';

// ============================================================================
// Nonce Tracking (Replay Prevention)
// ============================================================================

/**
 * Nonce store with automatic expiry
 * Nonces are kept for 2x MAX_CLOCK_SKEW to cover edge cases
 */
class NonceStore {
  private nonces: Map<string, number> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    // Cleanup expired nonces every minute
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
  }

  /**
   * Check if nonce was already used, and mark it as used
   * @returns true if nonce is fresh, false if replay
   */
  checkAndMark(nonce: string): boolean {
    if (this.nonces.has(nonce)) {
      return false; // Replay detected
    }
    this.nonces.set(nonce, Date.now());
    return true;
  }

  private cleanup(): void {
    const cutoff = Date.now() - MAX_CLOCK_SKEW_MS * 2;
    for (const [nonce, timestamp] of this.nonces) {
      if (timestamp < cutoff) {
        this.nonces.delete(nonce);
      }
    }
  }

  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// Global nonce store
const nonceStore = new NonceStore();

// ============================================================================
// Signature Verification
// ============================================================================

/**
 * Verify registration signature
 *
 * The signed message is: vault_id || timestamp || nonce
 * This binds the registration to a specific vault, time, and prevents replay.
 */
export function verifyRegistrationSignature(payload: RegisterPayload): void {
  // 1. Validate timestamp (within clock skew)
  const timestamp = new Date(payload.timestamp).getTime();
  if (isNaN(timestamp)) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Invalid timestamp format');
  }

  const now = Date.now();
  const skew = Math.abs(now - timestamp);
  if (skew > MAX_CLOCK_SKEW_MS) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Timestamp too far from server time', {
      skew_ms: skew,
      max_skew_ms: MAX_CLOCK_SKEW_MS,
    });
  }

  // 2. Validate nonce (check size and replay)
  const nonceBuffer = Buffer.from(payload.nonce, 'base64');
  if (nonceBuffer.length < MIN_NONCE_SIZE) {
    throw new RelayError('RELAY_UNAUTHORIZED', `Nonce must be at least ${MIN_NONCE_SIZE} bytes`);
  }

  if (!nonceStore.checkAndMark(payload.nonce)) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Nonce already used (replay detected)');
  }

  // 3. Validate signing public key
  const signingKeyBuffer = Buffer.from(payload.signing_public_key, 'base64');
  if (signingKeyBuffer.length !== 32) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Invalid signing public key size');
  }

  // 4. Validate signature
  const signatureBuffer = Buffer.from(payload.signature, 'base64');
  if (signatureBuffer.length !== 64) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Invalid signature size');
  }

  // 5. Construct signed message: vault_id || timestamp || nonce
  const message = Buffer.concat([
    Buffer.from(payload.vault_id, 'utf8'),
    Buffer.from(payload.timestamp, 'utf8'),
    nonceBuffer,
  ]);

  // 6. Verify Ed25519 signature
  const isValid = verifyEd25519(message, signatureBuffer, signingKeyBuffer);
  if (!isValid) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Invalid signature');
  }
}

/**
 * Verify Ed25519 signature using Node.js crypto
 */
function verifyEd25519(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  try {
    // Node.js crypto expects the public key in specific format
    // For Ed25519, we need to wrap it in SPKI format
    const spkiPrefix = Buffer.from([
      0x30, 0x2a, // SEQUENCE, length 42
      0x30, 0x05, // SEQUENCE, length 5
      0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
      0x03, 0x21, 0x00, // BIT STRING, length 33, no unused bits
    ]);
    const spkiKey = Buffer.concat([spkiPrefix, publicKey]);

    return nodeVerify(
      null,
      message,
      { key: spkiKey, format: 'der', type: 'spki' },
      signature
    );
  } catch {
    return false;
  }
}

// ============================================================================
// Pairing Token Validation
// ============================================================================

/**
 * Token store for pairing tokens
 * In Phase 1, this is a simple in-memory store.
 * Sprint 3 will add proper token issuance via OAuth PKCE.
 */
class TokenStore {
  private tokens: Map<string, { vault_id: string; expires_at: number; scopes: string[] }> = new Map();

  /**
   * Register a pairing token (called during 'dcp connect' flow)
   */
  registerToken(token: string, vaultId: string, scopes: string[], expiresInMs: number): void {
    this.tokens.set(token, {
      vault_id: vaultId,
      expires_at: Date.now() + expiresInMs,
      scopes,
    });
  }

  /**
   * Validate a pairing token
   * @returns vault_id if valid, throws if invalid
   */
  validateToken(token: string, expectedVaultId: string): void {
    const entry = this.tokens.get(token);

    if (!entry) {
      throw new RelayError('RELAY_UNAUTHORIZED', 'Invalid pairing token');
    }

    if (Date.now() > entry.expires_at) {
      this.tokens.delete(token);
      throw new RelayError('RELAY_UNAUTHORIZED', 'Pairing token expired');
    }

    if (entry.vault_id !== expectedVaultId) {
      throw new RelayError('RELAY_UNAUTHORIZED', 'Pairing token does not match vault_id');
    }
  }

  /**
   * Revoke a pairing token
   */
  revokeToken(token: string): boolean {
    return this.tokens.delete(token);
  }

  /**
   * Check if any tokens exist (for determining if token validation is required)
   */
  hasTokens(): boolean {
    return this.tokens.size > 0;
  }
}

// Export singleton token store
export const tokenStore = new TokenStore();

// ============================================================================
// Combined Authentication
// ============================================================================

export interface AuthConfig {
  /** Require pairing token (should be true after Sprint 3) */
  requirePairingToken: boolean;
}

const DEFAULT_AUTH_CONFIG: AuthConfig = {
  requirePairingToken: false, // Will be true after Sprint 3
};

/**
 * Authenticate a registration request
 * Performs both signature verification and optional token validation
 */
export function authenticateRegistration(
  payload: RegisterPayload,
  config: AuthConfig = DEFAULT_AUTH_CONFIG
): void {
  // 1. Always verify signature (proof of key possession)
  verifyRegistrationSignature(payload);

  // 2. Validate pairing token if required or provided
  if (config.requirePairingToken || payload.pairing_token) {
    if (!payload.pairing_token) {
      throw new RelayError('RELAY_UNAUTHORIZED', 'Pairing token required');
    }
    tokenStore.validateToken(payload.pairing_token, payload.vault_id);
  }
}

/**
 * Authenticate a relay request (client -> vault)
 * Uses pairing token when required or available.
 */
export function authenticateRequest(
  token: string | undefined,
  vaultId: string,
  config: AuthConfig = DEFAULT_AUTH_CONFIG
): void {
  if (!config.requirePairingToken) {
    return;
  }

  if (!token) {
    throw new RelayError('RELAY_UNAUTHORIZED', 'Pairing token required');
  }

  tokenStore.validateToken(token, vaultId);
}

/**
 * Cleanup auth resources
 */
export function closeAuth(): void {
  nonceStore.close();
}
