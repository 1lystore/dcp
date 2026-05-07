/**
 * Agent Registry
 *
 * Manages registered agents and their status.
 * Provides CRUD operations and status tracking.
 */

import type Database from 'better-sqlite3';

// ============================================================================
// Types
// ============================================================================

export type AgentStatus = 'pending' | 'connected' | 'stale' | 'revoked';
export type AgentEnvironment = 'local' | 'vps' | 'sandbox';

export interface AgentRecord {
  agent_id: string;
  display_name: string;
  environment: AgentEnvironment;
  public_key: string;
  fingerprint: string;
  status: AgentStatus;
  created_at: string;
  paired_at: string | null;
  revoked_at: string | null;
  last_seen: string | null;
  request_count: number;
}

export type NewAgentRecord = Omit<AgentRecord, 'request_count' | 'last_seen' | 'revoked_at'>;

// ============================================================================
// Agent Registry Implementation
// ============================================================================

export class AgentRegistry {
  constructor(private readonly db: Database.Database) {
    this.ensureTable();
  }

  /**
   * Ensure the agents table exists
   */
  private ensureTable(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        environment TEXT NOT NULL CHECK (environment IN ('local', 'vps', 'sandbox')),
        public_key TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connected', 'stale', 'revoked')),
        created_at TEXT NOT NULL,
        paired_at TEXT,
        revoked_at TEXT,
        last_seen TEXT,
        request_count INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
      CREATE INDEX IF NOT EXISTS idx_agents_fingerprint ON agents(fingerprint);
    `);
  }

  /**
   * Register a new agent
   */
  async register(agent: NewAgentRecord): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO agents (
        agent_id, display_name, environment, public_key, fingerprint,
        status, created_at, paired_at, revoked_at, last_seen, request_count
      ) VALUES (
        @agent_id, @display_name, @environment, @public_key, @fingerprint,
        @status, @created_at, @paired_at, NULL, NULL, 0
      )
    `);

    stmt.run(agent);
  }

  /**
   * Get an agent by ID
   */
  async get(agentId: string): Promise<AgentRecord | null> {
    const stmt = this.db.prepare(`
      SELECT * FROM agents WHERE agent_id = ?
    `);

    const row = stmt.get(agentId) as AgentRecord | undefined;
    return row || null;
  }

  /**
   * Get an agent by public key fingerprint
   */
  async getByFingerprint(fingerprint: string): Promise<AgentRecord | null> {
    const stmt = this.db.prepare(`
      SELECT * FROM agents WHERE fingerprint = ?
    `);

    const row = stmt.get(fingerprint) as AgentRecord | undefined;
    return row || null;
  }

  /**
   * Update agent status
   */
  async updateStatus(agentId: string, status: AgentStatus): Promise<void> {
    const now = new Date().toISOString();
    let stmt;

    if (status === 'revoked') {
      stmt = this.db.prepare(`
        UPDATE agents SET status = ?, revoked_at = ? WHERE agent_id = ?
      `);
      stmt.run(status, now, agentId);
    } else if (status === 'connected') {
      stmt = this.db.prepare(`
        UPDATE agents SET status = ?, paired_at = COALESCE(paired_at, ?) WHERE agent_id = ?
      `);
      stmt.run(status, now, agentId);
    } else {
      stmt = this.db.prepare(`
        UPDATE agents SET status = ? WHERE agent_id = ?
      `);
      stmt.run(status, agentId);
    }
  }

  /**
   * Revoke an agent
   */
  async revoke(agentId: string): Promise<void> {
    await this.updateStatus(agentId, 'revoked');
  }

  /**
   * Update last seen timestamp
   */
  async updateLastSeen(agentId: string): Promise<void> {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE agents SET last_seen = ? WHERE agent_id = ?
    `);
    stmt.run(now, agentId);
  }

  /**
   * Increment request count
   */
  async incrementRequestCount(agentId: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE agents SET request_count = request_count + 1 WHERE agent_id = ?
    `);
    stmt.run(agentId);
  }

  /**
   * List all agents (optionally filtered by status)
   */
  async list(status?: AgentStatus): Promise<AgentRecord[]> {
    if (status) {
      const stmt = this.db.prepare(`
        SELECT * FROM agents WHERE status = ? ORDER BY created_at DESC
      `);
      return stmt.all(status) as AgentRecord[];
    }

    const stmt = this.db.prepare(`
      SELECT * FROM agents ORDER BY created_at DESC
    `);
    return stmt.all() as AgentRecord[];
  }

  /**
   * List active (non-revoked) agents
   */
  async listActive(): Promise<AgentRecord[]> {
    const stmt = this.db.prepare(`
      SELECT * FROM agents WHERE status != 'revoked' ORDER BY created_at DESC
    `);
    return stmt.all() as AgentRecord[];
  }

  /**
   * Mark stale agents (not seen within timeout)
   */
  async markStaleAgents(timeoutMs: number): Promise<number> {
    const cutoff = new Date(Date.now() - timeoutMs).toISOString();
    const stmt = this.db.prepare(`
      UPDATE agents
      SET status = 'stale'
      WHERE status = 'connected'
        AND last_seen IS NOT NULL
        AND last_seen < ?
    `);
    const result = stmt.run(cutoff);
    return result.changes;
  }

  /**
   * Delete an agent permanently (use with caution)
   */
  async delete(agentId: string): Promise<void> {
    const stmt = this.db.prepare(`
      DELETE FROM agents WHERE agent_id = ?
    `);
    stmt.run(agentId);
  }

  /**
   * Check if an agent exists
   */
  async exists(agentId: string): Promise<boolean> {
    const stmt = this.db.prepare(`
      SELECT 1 FROM agents WHERE agent_id = ?
    `);
    return stmt.get(agentId) !== undefined;
  }

  /**
   * Count agents by status
   */
  async countByStatus(): Promise<Record<AgentStatus, number>> {
    const stmt = this.db.prepare(`
      SELECT status, COUNT(*) as count FROM agents GROUP BY status
    `);
    const rows = stmt.all() as Array<{ status: AgentStatus; count: number }>;

    const counts: Record<AgentStatus, number> = {
      pending: 0,
      connected: 0,
      stale: 0,
      revoked: 0,
    };

    for (const row of rows) {
      counts[row.status] = row.count;
    }

    return counts;
  }
}

// ============================================================================
// In-Memory Implementation (for testing)
// ============================================================================

export class InMemoryAgentRegistry {
  private agents = new Map<string, AgentRecord>();

  async register(agent: NewAgentRecord): Promise<void> {
    this.agents.set(agent.agent_id, {
      ...agent,
      revoked_at: null,
      last_seen: null,
      request_count: 0,
    });
  }

  async get(agentId: string): Promise<AgentRecord | null> {
    return this.agents.get(agentId) || null;
  }

  async getByFingerprint(fingerprint: string): Promise<AgentRecord | null> {
    for (const agent of this.agents.values()) {
      if (agent.fingerprint === fingerprint) {
        return agent;
      }
    }
    return null;
  }

  async updateStatus(agentId: string, status: AgentStatus): Promise<void> {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.status = status;
      if (status === 'revoked') {
        agent.revoked_at = new Date().toISOString();
      } else if (status === 'connected' && !agent.paired_at) {
        agent.paired_at = new Date().toISOString();
      }
    }
  }

  async revoke(agentId: string): Promise<void> {
    await this.updateStatus(agentId, 'revoked');
  }

  async updateLastSeen(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.last_seen = new Date().toISOString();
    }
  }

  async incrementRequestCount(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.request_count++;
    }
  }

  async list(status?: AgentStatus): Promise<AgentRecord[]> {
    const all = Array.from(this.agents.values());
    if (status) {
      return all.filter(a => a.status === status);
    }
    return all;
  }

  async listActive(): Promise<AgentRecord[]> {
    return Array.from(this.agents.values()).filter(a => a.status !== 'revoked');
  }

  async delete(agentId: string): Promise<void> {
    this.agents.delete(agentId);
  }

  async exists(agentId: string): Promise<boolean> {
    return this.agents.has(agentId);
  }

  clear(): void {
    this.agents.clear();
  }
}
