/**
 * DCP Agent Types
 *
 * Types for agent configuration, state, and errors.
 */

import type { AgentConnectionMode, AgentConnectionTier } from '@dcprotocol/core';

// ============================================================================
// Agent Configuration
// ============================================================================

/**
 * Stored agent configuration (from pairing grant)
 *
 * Saved to ~/.dcp/agents/<agent_id>.json
 *
 * IMPORTANT: permission_scopes, budget, and tier are DEPRECATED in pairing grants.
 * The vault policy DB is the ONLY enforcement source for permissions.
 * These fields are optional for backward compatibility with existing configs.
 */
export interface AgentConfig {
  agent_id: string;
  agent_name: string;
  vault_id: string;
  mode: AgentConnectionMode;
  vault_hpke_public_key: string;
  vault_signing_public_key: string;
  relay_url: string;
  /**
   * Agent's own Ed25519 keypair for signing relay requests
   * Generated during pairing per protocol spec section 7.3
   */
  service_keypair: {
    public: string;  // base64 encoded
    private: string; // base64 encoded
  };
  session_token?: string;
  paired_at: string;
  grant_expires_at: string;

  /**
   * @deprecated Permission scopes are stored ONLY in vault policy DB.
   * These fields are for backward compatibility only.
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
 * Agent runtime state
 */
export interface AgentState {
  connected: boolean;
  session_valid: boolean;
  last_request_at?: string;
  request_count: number;
}

// ============================================================================
// VPS Pending Config (before approval)
// ============================================================================

/**
 * VPS pending configuration (before pairing is approved)
 *
 * Written by install-service command. Not yet a full AgentConfig because:
 * - No agent_id (assigned by vault after approval)
 * - No agent_name (assigned by user in Desktop)
 * - No service_keypair private key in this file (stored separately)
 *
 * The agent runtime should poll for approval and convert to AgentConfig once approved.
 */
export interface VpsPendingConfig {
  // Invite data
  invite_id: string;
  vault_id: string;
  relay_url: string;
  vault_public_key: string;
  vault_signing_key: string;
  // Agent public key (private stored separately in service.key)
  public_key: string;
  // Metadata
  hostname: string;
  version: string;
  mcp_host: string;
  mcp_port: number;
  environment: 'vps';
  created_at: string;
  // Pairing claim status
  claim_id?: string;
  pairing_status: 'pending_approval' | 'claim_failed' | 'approved';
  // Set after approval
  agent_id?: string;
  agent_name?: string;
}

export type MobileAgentClient =
  | 'claude-desktop'
  | 'cursor'
  | 'vscode'
  | 'hermes'
  | 'openclaw'
  | 'mcp'
  | 'custom'
  | 'hosted';

export type MobileAgentEnvironment = 'local' | 'vps' | 'hosted' | 'dev';

export type MobileDcpScope =
  | 'read:wallet.address'
  | 'sign:solana'
  | 'vault_get_address'
  | 'vault_budget_check'
  | 'vault_sign_tx'
  | 'vault_sign_message';

export interface MobilePairingBudget {
  daily: number;
  currency: 'SOL' | 'USDC';
  approval_threshold: number;
}

export interface MobilePairingInvite {
  type: 'dcp_agent_pairing';
  version: '1.0';
  relay_url: string;
  invite_id: string;
  agent_public_key: string;
  agent_name: string;
  agent_client: MobileAgentClient;
  environment: MobileAgentEnvironment;
  requested_scopes: MobileDcpScope[];
  requested_budget: MobilePairingBudget;
  created_at: string;
  expires_at: string;
  nonce: string;
  signature?: string;
}

export interface MobilePendingConfig {
  invite_id: string;
  invite_url: string;
  invite: MobilePairingInvite;
  service_keypair: {
    public: string;
    private: string;
  };
  pairing_status: 'pending_mobile_approval';
  created_at: string;
}

export interface MobilePairingApprovalStatus {
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'not_found';
  invite_id?: string;
  agent_id?: string;
  vault_id?: string;
  vault_hpke_public_key?: string;
  vault_signing_public_key?: string;
  approved_scopes?: MobileDcpScope[];
  approved_budget?: MobilePairingBudget;
  error?: string;
}

/**
 * Check if a config is a VPS pending config (not yet approved)
 */
export function isVpsPendingConfig(config: unknown): config is VpsPendingConfig {
  const c = config as VpsPendingConfig;
  return (
    c.environment === 'vps' &&
    c.pairing_status !== undefined &&
    c.pairing_status !== 'approved'
  );
}

/**
 * Check if a VPS config is approved and ready to run
 */
export function isVpsConfigApproved(config: VpsPendingConfig): boolean {
  return config.pairing_status === 'approved' && !!config.agent_id;
}

// ============================================================================
// Agent Run Options
// ============================================================================

export type AgentRunMode = 'mcp' | 'proxy' | 'sdk' | 'oneshot';

export interface AgentRunOptions {
  mode: AgentRunMode;
  port?: number;
  debug?: boolean;
}

// ============================================================================
// CLI Options
// ============================================================================

export interface PairOptions {
  grant: string;
  name?: string;
}

export interface RunOptions {
  mode?: string;
  port?: string;
  host?: string;
  debug?: boolean;
  daemon?: boolean;
  forceRelay?: boolean;
  agent?: string;
}

export interface StatusOptions {
  json?: boolean;
}

// ============================================================================
// Error Types
// ============================================================================

export type AgentErrorCode =
  | 'INVALID_GRANT'
  | 'GRANT_EXPIRED'
  | 'CONFIG_NOT_FOUND'
  | 'CONNECTION_FAILED'
  | 'SESSION_EXPIRED'
  | 'RATE_LIMITED'
  | 'UNAUTHORIZED'
  | 'INTERNAL_ERROR';

export class AgentError extends Error {
  constructor(
    public code: AgentErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AgentError';
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
      },
    };
  }
}
