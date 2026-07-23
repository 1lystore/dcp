/**
 * Verification-phrase parity test.
 *
 * The relay and the agent (@dcprotocol/agent, via @dcprotocol/core) each compute
 * the pairing verification phrase independently and the human compares them. If
 * the two implementations drift, pairing silently fails. The relay deliberately
 * does not depend on @dcprotocol/core, so we pin the phrase to a known vector
 * that MUST equal core's `generateVerificationPhrase` output for the same inputs.
 *
 * Cross-checked value (core, same inputs): 'earn-bracket-valve-cousin'
 *   generateVerificationPhrase(new Uint8Array(32).fill(1), 'inv_test123')
 */

import { describe, it, expect } from 'vitest';
import { PairingClaimStore } from '../src/store.js';
import type { PairingClaim } from '../src/types.js';

describe('Pairing verification phrase (relay ↔ core parity)', () => {
  it('storeClaim returns the same 4-word BIP-39 phrase core computes', () => {
    const store = new PairingClaimStore();
    try {
      // base64 of 32 bytes all 0x01 — the exact input core's pinned test uses.
      const agentPublicKey = Buffer.alloc(32, 1).toString('base64');
      const claim: PairingClaim = {
        invite_id: 'inv_test123',
        agent_public_key: agentPublicKey,
        agent_hostname: 'test-host',
        agent_version: '3.0.0',
        timestamp: 1,
        nonce: 'n',
        signature: 'sig',
      };

      const { verification_phrase } = store.storeClaim(claim, 'vault_x');

      expect(verification_phrase.split('-')).toHaveLength(4);
      // Pinned to core's output — if this breaks, agent/relay have drifted.
      expect(verification_phrase).toBe('earn-bracket-valve-cousin');
    } finally {
      store.stop?.();
    }
  });
});
