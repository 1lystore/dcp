/**
 * Tests for Signed Pairing Grants (PRD Section 7.1)
 */

import { describe, it, expect } from 'vitest';
import {
  createSignedPairingGrant,
  decodePairingGrant,
  verifyPairingGrant,
  verifyPairingGrantWithKey,
  isPairingGrant,
  PAIRING_GRANT_PREFIX,
  // Session tokens
  createSessionToken,
  decodeSessionToken,
  verifySessionToken,
  isSessionToken,
  SESSION_TOKEN_PREFIX,
} from '../src/pairing.js';
import { generateSigningKeyPair, zeroize, canonicalJson } from '../src/crypto.js';

describe('Signed Pairing Grants', () => {
  const createTestInput = (signingPublicKey: Buffer) => ({
    vault_id: 'vault_test123',
    agent_id: 'agent_abc789',
    agent_name: 'test-agent',
    mode: 'proxy' as const,
    vault_hpke_public_key: Buffer.alloc(32).toString('base64'),
    vault_signing_public_key: signingPublicKey.toString('base64'),
    permission_scopes: ['sign:solana', 'read:credentials.api.*'],
    budget: { daily: 10, currency: 'USDC', auto_approve_under: 1 },
    tier: 'free' as const,
    relay_url: 'wss://relay.dcp.example.com',
  });

  describe('createSignedPairingGrant', () => {
    it('should create a grant with correct prefix', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      const token = createSignedPairingGrant(input, privateKey);

      expect(token.startsWith(PAIRING_GRANT_PREFIX)).toBe(true);
      expect(isPairingGrant(token)).toBe(true);

      zeroize(privateKey);
    });

    it('should include all required fields in payload', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      const token = createSignedPairingGrant(input, privateKey);
      const decoded = decodePairingGrant(token);

      expect(decoded).not.toBeNull();
      expect(decoded!.payload.version).toBe(1);
      expect(decoded!.payload.vault_id).toBe(input.vault_id);
      expect(decoded!.payload.agent_id).toBe(input.agent_id);
      expect(decoded!.payload.agent_name).toBe(input.agent_name);
      expect(decoded!.payload.mode).toBe(input.mode);
      expect(decoded!.payload.relay_url).toBe(input.relay_url);
      expect(decoded!.payload.grant_id).toMatch(/^grant_/);
      expect(decoded!.payload.created_at).toBeDefined();
      expect(decoded!.payload.expires_at).toBeDefined();

      // NOTE: permission_scopes, budget, and tier are DEPRECATED and NOT included
      // in new grants. The vault policy DB is the only enforcement source.
      expect(decoded!.payload.permission_scopes).toBeUndefined();
      expect(decoded!.payload.budget).toBeUndefined();
      expect(decoded!.payload.tier).toBeUndefined();

      zeroize(privateKey);
    });

    it('should respect custom TTL', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      const token = createSignedPairingGrant({ ...input, ttl_ms: 5 * 60 * 1000 }, privateKey);
      const decoded = decodePairingGrant(token);

      const created = new Date(decoded!.payload.created_at);
      const expires = new Date(decoded!.payload.expires_at);
      const diff = expires.getTime() - created.getTime();

      expect(diff).toBe(5 * 60 * 1000);

      zeroize(privateKey);
    });
  });

  describe('decodePairingGrant', () => {
    it('should return null for invalid prefix', () => {
      expect(decodePairingGrant('invalid_token')).toBeNull();
      expect(decodePairingGrant('dcp_v1_xxx')).toBeNull();
    });

    it('should return null for invalid base64', () => {
      expect(decodePairingGrant(PAIRING_GRANT_PREFIX + '!!!invalid!!!')).toBeNull();
    });

    it('should return null for invalid JSON', () => {
      const badBase64 = Buffer.from('not json').toString('base64url');
      expect(decodePairingGrant(PAIRING_GRANT_PREFIX + badBase64)).toBeNull();
    });
  });

  describe('verifyPairingGrant', () => {
    it('should verify a valid grant', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      const token = createSignedPairingGrant(input, privateKey);
      const verified = verifyPairingGrant(token);

      expect(verified).not.toBeNull();
      expect(verified!.vault_id).toBe(input.vault_id);

      zeroize(privateKey);
    });

    it('should reject tampered payload', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      const token = createSignedPairingGrant(input, privateKey);
      const decoded = decodePairingGrant(token);

      // Tamper with payload
      decoded!.payload.vault_id = 'tampered_vault';

      // Re-encode without valid signature
      const tamperedJson = JSON.stringify(decoded);
      const tamperedToken = PAIRING_GRANT_PREFIX + Buffer.from(tamperedJson).toString('base64url');

      expect(verifyPairingGrant(tamperedToken)).toBeNull();

      zeroize(privateKey);
    });

    it('should reject expired grant', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      // Create with 0 TTL (already expired)
      const token = createSignedPairingGrant({ ...input, ttl_ms: -1000 }, privateKey);

      expect(verifyPairingGrant(token)).toBeNull();

      zeroize(privateKey);
    });

    it('should reject wrong signature', () => {
      const kp1 = generateSigningKeyPair();
      const kp2 = generateSigningKeyPair();

      // Create with kp1's public key embedded but sign with kp2's private key
      const input = createTestInput(kp1.publicKey);
      const token = createSignedPairingGrant(input, kp2.privateKey);

      // Verification should fail because embedded public key doesn't match signature
      expect(verifyPairingGrant(token)).toBeNull();

      zeroize(kp1.privateKey);
      zeroize(kp2.privateKey);
    });
  });

  describe('verifyPairingGrantWithKey', () => {
    it('should verify with known public key', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestInput(publicKey);

      const token = createSignedPairingGrant(input, privateKey);
      const verified = verifyPairingGrantWithKey(token, publicKey);

      expect(verified).not.toBeNull();
      expect(verified!.vault_id).toBe(input.vault_id);

      zeroize(privateKey);
    });

    it('should reject wrong public key', () => {
      const kp1 = generateSigningKeyPair();
      const kp2 = generateSigningKeyPair();
      const input = createTestInput(kp1.publicKey);

      const token = createSignedPairingGrant(input, kp1.privateKey);

      // Verify with wrong key
      expect(verifyPairingGrantWithKey(token, kp2.publicKey)).toBeNull();

      zeroize(kp1.privateKey);
      zeroize(kp2.privateKey);
    });
  });

  describe('canonicalJson', () => {
    it('should sort keys alphabetically', () => {
      const obj = { z: 1, a: 2, m: 3 };
      const result = canonicalJson(obj);

      expect(result).toBe('{"a":2,"m":3,"z":1}');
    });

    it('should produce deterministic output', () => {
      const obj1 = { b: 1, a: 2 };
      const obj2 = { a: 2, b: 1 };

      expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
    });
  });

  describe('isPairingGrant', () => {
    it('should return true for valid prefix', () => {
      expect(isPairingGrant(PAIRING_GRANT_PREFIX + 'anything')).toBe(true);
    });

    it('should return false for invalid prefix', () => {
      expect(isPairingGrant('invalid')).toBe(false);
      expect(isPairingGrant('dcp_v1_xxx')).toBe(false);
    });
  });
});

// ============================================================================
// Session Token Tests (for Gateway Authentication)
// ============================================================================

describe('Session Tokens', () => {
  const createTestSessionInput = () => ({
    vault_id: 'vault_test123',
    agent_id: 'agent_abc789',
    agent_name: 'test-agent',
    tier: 'free' as const,
    scopes: ['sign:solana', 'read:credentials.api.*'],
  });

  describe('createSessionToken', () => {
    it('should create a token with correct prefix', () => {
      const { privateKey } = generateSigningKeyPair();
      const input = createTestSessionInput();

      const token = createSessionToken(input, privateKey);

      expect(token.startsWith(SESSION_TOKEN_PREFIX)).toBe(true);
      expect(isSessionToken(token)).toBe(true);

      zeroize(privateKey);
    });

    it('should include all required fields in payload', () => {
      const { privateKey } = generateSigningKeyPair();
      const input = createTestSessionInput();

      const token = createSessionToken(input, privateKey);
      const decoded = decodeSessionToken(token);

      expect(decoded).not.toBeNull();
      expect(decoded!.payload.version).toBe(1);
      expect(decoded!.payload.vault_id).toBe(input.vault_id);
      expect(decoded!.payload.agent_id).toBe(input.agent_id);
      expect(decoded!.payload.agent_name).toBe(input.agent_name);
      expect(decoded!.payload.tier).toBe(input.tier);
      expect(decoded!.payload.scopes).toEqual(input.scopes);
      expect(decoded!.payload.token_id).toMatch(/^token_/);
      expect(decoded!.payload.issued_at).toBeDefined();
      expect(decoded!.payload.expires_at).toBeDefined();

      zeroize(privateKey);
    });

    it('should respect custom TTL', () => {
      const { privateKey } = generateSigningKeyPair();
      const input = createTestSessionInput();

      const token = createSessionToken({ ...input, ttl_ms: 60 * 60 * 1000 }, privateKey);
      const decoded = decodeSessionToken(token);

      const issued = new Date(decoded!.payload.issued_at);
      const expires = new Date(decoded!.payload.expires_at);
      const diff = expires.getTime() - issued.getTime();

      expect(diff).toBe(60 * 60 * 1000);

      zeroize(privateKey);
    });
  });

  describe('decodeSessionToken', () => {
    it('should return null for invalid prefix', () => {
      expect(decodeSessionToken('invalid_token')).toBeNull();
      expect(decodeSessionToken('dcp_pair_v1_xxx')).toBeNull();
    });

    it('should return null for invalid base64', () => {
      expect(decodeSessionToken(SESSION_TOKEN_PREFIX + '!!!invalid!!!')).toBeNull();
    });

    it('should return null for invalid JSON', () => {
      const badBase64 = Buffer.from('not json').toString('base64url');
      expect(decodeSessionToken(SESSION_TOKEN_PREFIX + badBase64)).toBeNull();
    });
  });

  describe('verifySessionToken', () => {
    it('should verify a valid token', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestSessionInput();

      const token = createSessionToken(input, privateKey);
      const verified = verifySessionToken(token, publicKey);

      expect(verified).not.toBeNull();
      expect(verified!.vault_id).toBe(input.vault_id);
      expect(verified!.agent_id).toBe(input.agent_id);

      zeroize(privateKey);
    });

    it('should reject tampered payload', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestSessionInput();

      const token = createSessionToken(input, privateKey);
      const decoded = decodeSessionToken(token);

      // Tamper with payload
      decoded!.payload.vault_id = 'tampered_vault';

      // Re-encode without valid signature
      const tamperedJson = JSON.stringify(decoded);
      const tamperedToken = SESSION_TOKEN_PREFIX + Buffer.from(tamperedJson).toString('base64url');

      expect(verifySessionToken(tamperedToken, publicKey)).toBeNull();

      zeroize(privateKey);
    });

    it('should reject expired token', () => {
      const { publicKey, privateKey } = generateSigningKeyPair();
      const input = createTestSessionInput();

      // Create with negative TTL (already expired)
      const token = createSessionToken({ ...input, ttl_ms: -1000 }, privateKey);

      expect(verifySessionToken(token, publicKey)).toBeNull();

      zeroize(privateKey);
    });

    it('should reject wrong public key', () => {
      const kp1 = generateSigningKeyPair();
      const kp2 = generateSigningKeyPair();
      const input = createTestSessionInput();

      const token = createSessionToken(input, kp1.privateKey);

      // Verify with wrong key
      expect(verifySessionToken(token, kp2.publicKey)).toBeNull();

      zeroize(kp1.privateKey);
      zeroize(kp2.privateKey);
    });
  });

  describe('isSessionToken', () => {
    it('should return true for valid prefix', () => {
      expect(isSessionToken(SESSION_TOKEN_PREFIX + 'anything')).toBe(true);
    });

    it('should return false for invalid prefix', () => {
      expect(isSessionToken('invalid')).toBe(false);
      expect(isSessionToken('dcp_pair_v1_xxx')).toBe(false);
    });

    it('should distinguish session tokens from pairing grants', () => {
      const { privateKey } = generateSigningKeyPair();

      const sessionToken = createSessionToken(createTestSessionInput(), privateKey);

      expect(isSessionToken(sessionToken)).toBe(true);
      expect(isPairingGrant(sessionToken)).toBe(false);

      zeroize(privateKey);
    });
  });
});
