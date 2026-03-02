/**
 * Types for DCP Vault MCP Server
 *
 * These types define the MCP tool inputs/outputs as per PRD Section 3.1.3
 */

import { Chain, SensitivityLevel, ItemType } from '@dcprotocol/core';

// ============================================================================
// MCP Tool Inputs (from PRD Section 3.1.3)
// ============================================================================

/** Input for vault_get_address tool */
export interface GetAddressInput {
  chain: Chain;
}

/** Input for vault_budget_check tool */
export interface BudgetCheckInput {
  amount: number;
  currency: string;
}

/** Input for vault_read tool */
export interface ReadInput {
  scope: string;
  fields?: string[];
}

/** Input for vault_sign_tx tool */
export interface SignTxInput {
  chain: Chain;
  unsigned_tx: string; // base64 for Solana, JSON for EVM
  description?: string;
  amount?: number; // For budget tracking
  currency?: string;
  destination?: string;
  idempotency_key?: string;
}

// ============================================================================
// MCP Tool Outputs (from PRD Section 3.1.3)
// ============================================================================

/** Scope info returned by vault_list_scopes */
export interface ScopeInfo {
  scope: string;
  type: ItemType;
  sensitivity: SensitivityLevel;
  operations: string[];
  chain?: Chain;
  public_address?: string;
}

/** Output for vault_list_scopes tool */
export interface ListScopesOutput {
  scopes: ScopeInfo[];
}

/** Output for vault_get_address tool */
export interface GetAddressOutput {
  chain: Chain;
  address: string;
}

/** Output for vault_budget_check tool */
export interface BudgetCheckOutput {
  allowed: boolean;
  limits: {
    per_tx: number;
    daily: number;
    approval_threshold: number;
  };
  remaining: {
    daily: number;
    per_tx: number;
  };
  requires_approval: boolean;
  reason?: string;
}

/** Output for vault_read tool */
export interface ReadOutput {
  scope: string;
  data: Record<string, unknown> | null;
  sensitivity: SensitivityLevel;
  is_reference: boolean; // True for CRITICAL data
  reference_id?: string; // For CRITICAL data only
}

/** Output for vault_sign_tx tool */
export interface SignTxOutput {
  signed_tx: string;
  signature: string;
  chain: Chain;
  budget_remaining: {
    daily: number;
    per_tx: number;
  };
}

// ============================================================================
// Consent Types (from PRD Section 3.1.6)
// ============================================================================

export type ConsentAction = 'read' | 'sign_tx' | 'sign_message';

export interface ConsentRequest {
  id: string;
  agent_name: string;
  action: ConsentAction;
  scope: string;
  description?: string;
  amount?: number;
  currency?: string;
  chain?: Chain;
  expires_at: string;
}

export interface ConsentResponse {
  approved: boolean;
  mode?: 'once' | 'session' | 'always';
  session_id?: string;
}

// ============================================================================
// Error Response (from PRD Section 7)
// ============================================================================

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

// ============================================================================
// Session Context
// ============================================================================

export interface SessionContext {
  agent_name: string;
  session_id?: string;
  granted_scopes: string[];
  consent_mode: 'once' | 'session' | 'always';
  created_at: string;
  expires_at: string;
}
