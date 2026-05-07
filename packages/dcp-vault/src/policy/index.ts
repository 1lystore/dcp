/**
 * Policy Module
 *
 * Centralized policy enforcement for the DCP Vault.
 * Handles:
 * - Replay protection (nonce tracking)
 * - Input validation (Zod schemas)
 * - Agent management
 * - Permission grants
 * - Budget enforcement
 */

export { NonceStore, nonceStore } from './nonce-store.js';
export { PolicyEngine, type PolicyResult, type PolicyRequest } from './engine.js';
export {
  AgentRegistry,
  InMemoryAgentRegistry,
  type AgentRecord,
  type NewAgentRecord,
  type AgentStatus,
  type AgentEnvironment,
} from './agent-registry.js';
export {
  PermissionStore,
  InMemoryPermissionStore,
  type Permission,
  type NewPermission,
  type AccessMode,
  type ApprovalMode,
  type BudgetCheckResult,
} from './permission-store.js';
export * from './schemas.js';
