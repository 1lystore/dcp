/**
 * Permission Store
 *
 * Manages permission grants for agents.
 * Supports pattern matching, expiry, and budgets.
 */

import type Database from 'better-sqlite3';
import { randomUUID } from 'crypto';

// ============================================================================
// Types
// ============================================================================

export type AccessMode = 'reveal' | 'use';
export type ApprovalMode = 'approve_once' | 'approve_session' | 'always_allow' | 'always_deny';

export interface Permission {
  id: string;
  agent_id: string;
  access_mode: AccessMode;
  resource_pattern: string;
  action_pattern: string;
  approval_mode: ApprovalMode;
  budget_daily?: number;
  budget_spent?: number;
  budget_currency?: string;
  budget_reset_at?: string;
  expires_at?: string;
  created_at: string;
  created_by: string;
}

export type NewPermission = Omit<Permission, 'id' | 'created_at' | 'budget_spent' | 'budget_reset_at'>;

export interface BudgetCheckResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  spent: number;
}

// ============================================================================
// Permission Store Implementation
// ============================================================================

export class PermissionStore {
  constructor(private readonly db: Database.Database) {
    this.ensureTable();
  }

  /**
   * Ensure the permissions table exists
   */
  private ensureTable(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS permissions (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        access_mode TEXT NOT NULL CHECK (access_mode IN ('reveal', 'use')),
        resource_pattern TEXT NOT NULL,
        action_pattern TEXT NOT NULL DEFAULT '*',
        approval_mode TEXT NOT NULL CHECK (approval_mode IN ('approve_once', 'approve_session', 'always_allow', 'always_deny')),
        budget_daily REAL,
        budget_spent REAL DEFAULT 0,
        budget_currency TEXT,
        budget_reset_at TEXT,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
      );

      CREATE INDEX IF NOT EXISTS idx_permissions_agent ON permissions(agent_id);
      CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource_pattern);
    `);
  }

  /**
   * Grant a new permission
   */
  async grant(permission: NewPermission): Promise<string> {
    const id = randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO permissions (
        id, agent_id, access_mode, resource_pattern, action_pattern,
        approval_mode, budget_daily, budget_spent, budget_currency,
        budget_reset_at, expires_at, created_at, created_by
      ) VALUES (
        @id, @agent_id, @access_mode, @resource_pattern, @action_pattern,
        @approval_mode, @budget_daily, 0, @budget_currency,
        @budget_reset_at, @expires_at, @created_at, @created_by
      )
    `);

    stmt.run({
      id,
      agent_id: permission.agent_id,
      access_mode: permission.access_mode,
      resource_pattern: permission.resource_pattern,
      action_pattern: permission.action_pattern,
      approval_mode: permission.approval_mode,
      budget_daily: permission.budget_daily ?? null,
      budget_currency: permission.budget_currency ?? null,
      budget_reset_at: permission.budget_daily ? now : null,
      expires_at: permission.expires_at ?? null,
      created_at: now,
      created_by: permission.created_by,
    });

    return id;
  }

  /**
   * Check if a permission exists for a given agent, resource, and mode
   * Returns the matching permission or null
   */
  async check(agentId: string, resource: string, mode: AccessMode): Promise<Permission | null> {
    // Get all active permissions for this agent and mode
    const permissions = await this.listForAgent(agentId, mode);

    // Find matching permission using pattern matching
    for (const perm of permissions) {
      if (this.matchesPattern(resource, perm.resource_pattern)) {
        // Check if expired
        if (perm.expires_at && new Date(perm.expires_at) < new Date()) {
          continue;
        }
        return perm;
      }
    }

    return null;
  }

  /**
   * Check budget for an agent
   */
  async checkBudget(agentId: string, amount: number, currency: string): Promise<BudgetCheckResult> {
    // First, reset any stale budgets
    await this.resetStaleBudgets();

    // Get all permissions with budgets for this agent
    const stmt = this.db.prepare(`
      SELECT * FROM permissions
      WHERE agent_id = ?
        AND budget_daily IS NOT NULL
        AND budget_currency = ?
        AND approval_mode != 'always_deny'
    `);

    const permissions = stmt.all(agentId, currency) as Permission[];

    if (permissions.length === 0) {
      // No budget configured - allow by default
      return { allowed: true, limit: Infinity, remaining: Infinity, spent: 0 };
    }

    // Aggregate budgets
    let totalLimit = 0;
    let totalSpent = 0;

    for (const perm of permissions) {
      totalLimit += perm.budget_daily ?? 0;
      totalSpent += perm.budget_spent ?? 0;
    }

    const remaining = totalLimit - totalSpent;
    const allowed = remaining >= amount;

    return {
      allowed,
      limit: totalLimit,
      remaining: Math.max(0, remaining),
      spent: totalSpent,
    };
  }

  /**
   * Record budget spending
   */
  async recordSpend(agentId: string, amount: number, currency: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE permissions
      SET budget_spent = budget_spent + ?
      WHERE agent_id = ?
        AND budget_currency = ?
        AND budget_daily IS NOT NULL
    `);

    stmt.run(amount, agentId, currency);
  }

  /**
   * Reset stale budgets (older than 24 hours)
   */
  private async resetStaleBudgets(): Promise<void> {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      UPDATE permissions
      SET budget_spent = 0, budget_reset_at = ?
      WHERE budget_reset_at IS NOT NULL
        AND budget_reset_at < ?
    `);

    stmt.run(now, cutoff);
  }

  /**
   * Revoke a permission by ID
   */
  async revoke(permissionId: string): Promise<void> {
    const stmt = this.db.prepare(`
      DELETE FROM permissions WHERE id = ?
    `);
    stmt.run(permissionId);
  }

  /**
   * Revoke all permissions for an agent
   */
  async revokeAllForAgent(agentId: string): Promise<number> {
    const stmt = this.db.prepare(`
      DELETE FROM permissions WHERE agent_id = ?
    `);
    const result = stmt.run(agentId);
    return result.changes;
  }

  /**
   * List permissions for an agent
   */
  async listForAgent(agentId: string, mode?: AccessMode): Promise<Permission[]> {
    if (mode) {
      const stmt = this.db.prepare(`
        SELECT * FROM permissions WHERE agent_id = ? AND access_mode = ? ORDER BY created_at DESC
      `);
      return stmt.all(agentId, mode) as Permission[];
    }

    const stmt = this.db.prepare(`
      SELECT * FROM permissions WHERE agent_id = ? ORDER BY created_at DESC
    `);
    return stmt.all(agentId) as Permission[];
  }

  /**
   * Get a permission by ID
   */
  async get(permissionId: string): Promise<Permission | null> {
    const stmt = this.db.prepare(`
      SELECT * FROM permissions WHERE id = ?
    `);
    const row = stmt.get(permissionId) as Permission | undefined;
    return row || null;
  }

  /**
   * Check if a resource matches a pattern
   * Supports wildcards: * matches any segment, ** matches multiple segments
   */
  private matchesPattern(resource: string, pattern: string): boolean {
    // Exact match
    if (pattern === resource) return true;

    // Wildcard for everything
    if (pattern === '*' || pattern === '**') return true;

    // Pattern matching with wildcards
    const patternParts = pattern.split('.');
    const resourceParts = resource.split('.');

    let patternIdx = 0;
    let resourceIdx = 0;

    while (patternIdx < patternParts.length && resourceIdx < resourceParts.length) {
      const patternPart = patternParts[patternIdx];

      if (patternPart === '**') {
        // ** matches zero or more segments
        if (patternIdx === patternParts.length - 1) {
          // ** at end matches everything
          return true;
        }
        // Try to match the rest of the pattern
        const nextPattern = patternParts[patternIdx + 1];
        while (resourceIdx < resourceParts.length) {
          if (resourceParts[resourceIdx] === nextPattern || nextPattern === '*') {
            break;
          }
          resourceIdx++;
        }
        patternIdx++;
      } else if (patternPart === '*') {
        // * matches exactly one segment
        patternIdx++;
        resourceIdx++;
      } else if (patternPart === resourceParts[resourceIdx]) {
        // Exact segment match
        patternIdx++;
        resourceIdx++;
      } else {
        // No match
        return false;
      }
    }

    // Check if we consumed all parts
    return patternIdx >= patternParts.length && resourceIdx >= resourceParts.length;
  }

  /**
   * Delete expired permissions
   */
  async deleteExpired(): Promise<number> {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      DELETE FROM permissions WHERE expires_at IS NOT NULL AND expires_at < ?
    `);
    const result = stmt.run(now);
    return result.changes;
  }
}

// ============================================================================
// In-Memory Implementation (for testing)
// ============================================================================

export class InMemoryPermissionStore {
  private permissions = new Map<string, Permission>();

  async grant(permission: NewPermission): Promise<string> {
    const id = randomUUID();
    const now = new Date().toISOString();

    this.permissions.set(id, {
      ...permission,
      id,
      created_at: now,
      budget_spent: 0,
      budget_reset_at: permission.budget_daily ? now : undefined,
    });

    return id;
  }

  async check(agentId: string, resource: string, mode: AccessMode): Promise<Permission | null> {
    for (const perm of this.permissions.values()) {
      if (perm.agent_id === agentId && perm.access_mode === mode) {
        if (this.matchesPattern(resource, perm.resource_pattern)) {
          if (perm.expires_at && new Date(perm.expires_at) < new Date()) {
            continue;
          }
          return perm;
        }
      }
    }
    return null;
  }

  async checkBudget(agentId: string, amount: number, currency: string): Promise<BudgetCheckResult> {
    let totalLimit = 0;
    let totalSpent = 0;
    let hasBudget = false;

    for (const perm of this.permissions.values()) {
      if (
        perm.agent_id === agentId &&
        perm.budget_daily !== undefined &&
        perm.budget_currency === currency
      ) {
        hasBudget = true;
        totalLimit += perm.budget_daily;
        totalSpent += perm.budget_spent ?? 0;
      }
    }

    if (!hasBudget) {
      return { allowed: true, limit: Infinity, remaining: Infinity, spent: 0 };
    }

    const remaining = totalLimit - totalSpent;
    return {
      allowed: remaining >= amount,
      limit: totalLimit,
      remaining: Math.max(0, remaining),
      spent: totalSpent,
    };
  }

  async recordSpend(agentId: string, amount: number, currency: string): Promise<void> {
    for (const perm of this.permissions.values()) {
      if (
        perm.agent_id === agentId &&
        perm.budget_currency === currency &&
        perm.budget_daily !== undefined
      ) {
        perm.budget_spent = (perm.budget_spent ?? 0) + amount;
      }
    }
  }

  async revoke(permissionId: string): Promise<void> {
    this.permissions.delete(permissionId);
  }

  async revokeAllForAgent(agentId: string): Promise<number> {
    let count = 0;
    for (const [id, perm] of this.permissions) {
      if (perm.agent_id === agentId) {
        this.permissions.delete(id);
        count++;
      }
    }
    return count;
  }

  async listForAgent(agentId: string, mode?: AccessMode): Promise<Permission[]> {
    const result: Permission[] = [];
    for (const perm of this.permissions.values()) {
      if (perm.agent_id === agentId && (!mode || perm.access_mode === mode)) {
        result.push(perm);
      }
    }
    return result;
  }

  async get(permissionId: string): Promise<Permission | null> {
    return this.permissions.get(permissionId) || null;
  }

  private matchesPattern(resource: string, pattern: string): boolean {
    if (pattern === resource) return true;
    if (pattern === '*' || pattern === '**') return true;

    const patternParts = pattern.split('.');
    const resourceParts = resource.split('.');

    let patternIdx = 0;
    let resourceIdx = 0;

    while (patternIdx < patternParts.length && resourceIdx < resourceParts.length) {
      const patternPart = patternParts[patternIdx];

      if (patternPart === '**') {
        if (patternIdx === patternParts.length - 1) return true;
        const nextPattern = patternParts[patternIdx + 1];
        while (resourceIdx < resourceParts.length) {
          if (resourceParts[resourceIdx] === nextPattern || nextPattern === '*') break;
          resourceIdx++;
        }
        patternIdx++;
      } else if (patternPart === '*') {
        patternIdx++;
        resourceIdx++;
      } else if (patternPart === resourceParts[resourceIdx]) {
        patternIdx++;
        resourceIdx++;
      } else {
        return false;
      }
    }

    return patternIdx >= patternParts.length && resourceIdx >= resourceParts.length;
  }

  clear(): void {
    this.permissions.clear();
  }
}
