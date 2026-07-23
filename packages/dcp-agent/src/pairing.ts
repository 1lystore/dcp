/**
 * Pairing Utilities
 *
 * Handles verification phrase generation and pairing claim flow
 * for secure agent-to-vault pairing.
 */

import { randomUUID } from 'node:crypto';
import {
  generateSigningKeyPair,
  parseVpsPairingInvite,
  isVpsInviteExpired,
  isVpsPairingInvite,
  signMessage,
  generateVerificationPhrase,
  VPS_INVITE_PREFIX,
  type VpsPairingInvite,
} from '@dcprotocol/core';

// ============================================================================
// Verification Phrase Generation
// ============================================================================

// The verification phrase algorithm lives in @dcprotocol/core as the single
// source of truth shared with the relay (they must produce identical phrases).
// Re-exported here to preserve the agent's existing import surface.
export { generateVerificationPhrase };

// ============================================================================
// Pairing Invite Parsing
// ============================================================================

/**
 * Parsed pairing invite data
 *
 * For VPS pairing, we use dcp_vps_v1_ format from @dcprotocol/core
 */
export interface PairingInviteData {
  version: number;
  invite_id: string;
  vault_id: string;
  relay_url: string;
  vault_public_key: string;
  vault_signing_key: string;
  expires_at: number;
}

// Re-export for convenience
export { isVpsPairingInvite, VPS_INVITE_PREFIX };

export function relayHttpUrl(relayUrl: string): string {
  let url = relayUrl.trim();
  if (url.startsWith('wss://')) {
    url = `https://${url.slice('wss://'.length)}`;
  } else if (url.startsWith('ws://')) {
    url = `http://${url.slice('ws://'.length)}`;
  }
  return url.replace(/\/ws\/?$/, '').replace(/\/$/, '');
}

/**
 * Parse a VPS pairing invite string
 *
 * Format: dcp_vps_v1_<base64url-encoded-json>
 *
 * @param invite - The pairing invite string
 * @returns Parsed invite data
 * @throws Error if invite is invalid
 */
export function parsePairingInvite(invite: string): PairingInviteData {
  // Check for VPS invite format
  if (!isVpsPairingInvite(invite)) {
    throw new Error(`Invalid pairing invite format: must start with ${VPS_INVITE_PREFIX}`);
  }

  const parsed = parseVpsPairingInvite(invite);
  if (!parsed) {
    throw new Error('Invalid pairing invite: malformed data');
  }

  // Check expiration
  if (isVpsInviteExpired(parsed)) {
    throw new Error('Pairing invite has expired');
  }

  return {
    version: parsed.version,
    invite_id: parsed.invite_id,
    vault_id: parsed.vault_id,
    relay_url: parsed.relay_url,
    vault_public_key: parsed.vault_public_key,
    vault_signing_key: parsed.vault_signing_key,
    expires_at: parsed.expires_at,
  };
}

// ============================================================================
// Pairing Claim
// ============================================================================

export interface PairingClaim {
  invite_id: string;
  vault_id?: string;
  agent_public_key: string;
  agent_hostname: string;
  agent_version: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

/**
 * Create a signed pairing claim
 *
 * @param invite - Parsed pairing invite
 * @param privateKey - Agent's private key
 * @param publicKey - Agent's public key
 * @param hostname - Agent's hostname
 * @param version - Agent version
 * @returns Signed pairing claim
 */
export function createPairingClaim(
  invite: PairingInviteData,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  hostname: string,
  version: string
): PairingClaim {
  const timestamp = Date.now();
  const nonce = randomUUID();

  // Create the claim payload
  // Include vault_id for self-routing (survives relay restarts)
  const payload = {
    invite_id: invite.invite_id,
    vault_id: invite.vault_id,
    agent_public_key: Buffer.from(publicKey).toString('base64'),
    agent_hostname: hostname,
    agent_version: version,
    timestamp,
    nonce,
  };

  // Sign the canonical JSON payload
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const message = Buffer.from(canonical, 'utf8');
  const signature = signMessage(message, Buffer.from(privateKey));

  return {
    ...payload,
    signature: Buffer.from(signature).toString('base64'),
  };
}

/**
 * Generate a new keypair for agent
 */
export function generateAgentKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const { privateKey, publicKey } = generateSigningKeyPair();
  return { privateKey, publicKey };
}

// ============================================================================
// Relay Pairing Claim Submission
// ============================================================================

export interface PairingClaimResult {
  success: boolean;
  claim_id?: string;
  verification_phrase?: string;
  error?: string;
}

export interface PairingApprovalStatus {
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'not_found';
  agent_id?: string;
  vault_id?: string;
  error?: string;
}

/**
 * Submit pairing claim to vault via relay
 *
 * Per protocol spec: VPS agent sends pairing claim through relay to vault.
 * The claim is signed with agent's private key and routed by invite_id.
 *
 * @param claim - Signed pairing claim
 * @param relayUrl - Relay server URL
 * @returns Result with claim_id for polling
 */
export async function submitPairingClaim(
  claim: PairingClaim,
  relayUrl: string
): Promise<PairingClaimResult> {
  try {
    // Submit claim to relay endpoint
    // Relay routes based on invite_id to the correct vault
    const response = await fetch(`${relayHttpUrl(relayUrl)}/v1/pairing-claims`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(claim),
    });

    if (!response.ok) {
      const error = (await response.json()) as { error?: { message?: string } };
      return {
        success: false,
        error: error.error?.message || `HTTP ${response.status}`,
      };
    }

    const result = (await response.json()) as {
      claim_id?: string;
      verification_phrase?: string;
    };

    return {
      success: true,
      claim_id: result.claim_id,
      verification_phrase: result.verification_phrase,
    };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : 'Network error',
    };
  }
}

/**
 * Poll for pairing approval status
 *
 * Agent calls this periodically to check if the user has approved
 * the pairing claim in the desktop app.
 *
 * @param claimId - Claim ID from submitPairingClaim
 * @param relayUrl - Relay server URL
 * @returns Approval status
 */
export async function pollPairingApproval(
  claimId: string,
  relayUrl: string
): Promise<PairingApprovalStatus> {
  try {
    const response = await fetch(`${relayHttpUrl(relayUrl)}/v1/pairing-claims/${claimId}/status`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return { status: 'not_found' };
      }
      return {
        status: 'pending',
        error: `HTTP ${response.status}`,
      };
    }

    const result = (await response.json()) as PairingApprovalStatus;
    return result;
  } catch (err) {
    return {
      status: 'pending',
      error: err instanceof Error ? err.message : 'Network error',
    };
  }
}

/**
 * Wait for pairing approval with polling
 *
 * Polls the relay for approval status until approved, denied, or timeout.
 *
 * @param claimId - Claim ID from submitPairingClaim
 * @param relayUrl - Relay server URL
 * @param timeoutMs - Maximum time to wait (default: 5 minutes)
 * @param pollIntervalMs - Poll interval (default: 2 seconds)
 * @returns Final approval status
 */
export async function waitForPairingApproval(
  claimId: string,
  relayUrl: string,
  timeoutMs = 5 * 60 * 1000,
  pollIntervalMs = 2000
): Promise<PairingApprovalStatus> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    const status = await pollPairingApproval(claimId, relayUrl);

    if (status.status === 'approved' || status.status === 'denied' || status.status === 'expired') {
      return status;
    }

    if (status.status === 'not_found') {
      return status;
    }

    // Wait before next poll
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  return { status: 'expired', error: 'Polling timeout' };
}
