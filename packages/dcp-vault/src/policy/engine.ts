/**
 * Centralized Policy Engine
 *
 * Evaluates all access requests against:
 * 1. Replay protection (nonce/timestamp)
 * 2. Agent authentication and status
 * 3. Permission grants
 * 4. Budget limits
 * 5. Idempotency keys
 */

import { nonceStore } from './nonce-store.js';
import { verifySignature, canonicalJson } from '@dcprotocol/core';

// ============================================================================
// Types
// ============================================================================

export type PolicyResult =
  | { status: 'allow' }
  | { status: 'deny'; reason: string }
  | { status: 'approval_required'; approval_id: string }
  | { status: 'budget_exceeded'; limit: number; requested: number }
  | { status: 'agent_revoked' }
  | { status: 'vault_locked' };

export interface PolicyRequest {
  agent_id: string;
  request_id: string;
  action: string;
  resource: string;
  access_mode: 'reveal' | 'use';
  params?: Record<string, unknown>;
  amount?: number;
  currency?: string;
  destination?: string;
  idempotency_key?: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

export interface AgentInfo {
  agent_id: string;
  public_key: string;
  status: 'pending' | 'connected' | 'stale' | 'revoked';
}

export interface PermissionGrant {
  resource_pattern: string;
  access_mode: 'reveal' | 'use';
  approval_mode: 'approve_once' | 'approve_session' | 'always_allow' | 'always_deny';
}

export interface BudgetCheckResult {
  allowed: boolean;
  limit: number;
  remaining: number;
}

// ============================================================================
// Policy Engine Interfaces (for dependency injection)
// ============================================================================

export interface AgentRegistryInterface {
  get(agentId: string): Promise<AgentInfo | null>;
}

export interface PermissionStoreInterface {
  check(agentId: string, resource: string, mode: 'reveal' | 'use'): Promise<PermissionGrant | null>;
}

export interface BudgetStoreInterface {
  check(agentId: string, amount: number, currency: string): Promise<BudgetCheckResult>;
}

export interface ApprovalStoreInterface {
  create(request: PolicyRequest): Promise<string>;
}

export interface IdempotencyStoreInterface {
  check(key: string): Promise<boolean>;
  set(key: string, result: unknown): Promise<void>;
}

// ============================================================================
// Policy Engine Implementation
// ============================================================================

export class PolicyEngine {
  constructor(
    private readonly agentRegistry: AgentRegistryInterface,
    private readonly permissionStore: PermissionStoreInterface,
    private readonly budgetStore: BudgetStoreInterface,
    private readonly approvalStore: ApprovalStoreInterface,
    private readonly idempotencyStore: IdempotencyStoreInterface,
  ) {}

  /**
   * Evaluate a policy request
   */
  async evaluate(request: PolicyRequest): Promise<PolicyResult> {
    // 1. Validate timestamp and nonce (replay protection)
    try {
      nonceStore.validateRequest(request.agent_id, request.nonce, request.timestamp);
    } catch (error) {
      return { status: 'deny', reason: (error as Error).message };
    }

    // 2. Check agent exists and not revoked
    const agent = await this.agentRegistry.get(request.agent_id);
    if (!agent) {
      return { status: 'deny', reason: 'UNKNOWN_AGENT' };
    }
    if (agent.status === 'revoked') {
      return { status: 'agent_revoked' };
    }

    // 3. Verify signature
    const isValid = await this.verifyRequestSignature(request, agent.public_key);
    if (!isValid) {
      return { status: 'deny', reason: 'INVALID_SIGNATURE' };
    }

    // 4. Check permissions
    const permission = await this.permissionStore.check(
      request.agent_id,
      request.resource,
      request.access_mode,
    );

    if (!permission) {
      // No permission - needs approval
      const approval_id = await this.approvalStore.create(request);
      return { status: 'approval_required', approval_id };
    }

    if (permission.approval_mode === 'always_deny') {
      return { status: 'deny', reason: 'PERMISSION_DENIED' };
    }

    // 5. Check budget (for use/sign actions with amounts)
    if (request.amount !== undefined && request.currency) {
      const budget = await this.budgetStore.check(
        request.agent_id,
        request.amount,
        request.currency,
      );

      if (!budget.allowed) {
        return {
          status: 'budget_exceeded',
          limit: budget.limit,
          requested: request.amount,
        };
      }
    }

    // 6. Check idempotency
    if (request.idempotency_key) {
      const existing = await this.idempotencyStore.check(request.idempotency_key);
      if (existing) {
        // Already processed - return cached result
        return { status: 'allow' };
      }
    }

    return { status: 'allow' };
  }

  /**
   * Verify the request signature
   */
  private async verifyRequestSignature(request: PolicyRequest, publicKey: string): Promise<boolean> {
    try {
      // Create canonical payload without signature
      const { signature, ...payload } = request;
      const canonical = canonicalJson(payload);
      const message = Buffer.from(canonical, 'utf8');
      const sig = Buffer.from(signature, 'base64');
      const pubKey = Buffer.from(publicKey, 'base64');

      return verifySignature(message, sig, pubKey);
    } catch {
      return false;
    }
  }
}
