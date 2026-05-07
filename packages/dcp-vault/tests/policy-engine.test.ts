import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the @dcprotocol/core module to skip signature verification in tests
vi.mock('@dcprotocol/core', () => ({
  verifySignature: vi.fn(() => true),
  canonicalJson: vi.fn((obj: unknown) => JSON.stringify(obj)),
}));

import { PolicyEngine, type PolicyRequest } from '../src/policy/engine.js';
import { nonceStore, NonceStore } from '../src/policy/nonce-store.js';
import type {
  AgentRegistryInterface,
  PermissionStoreInterface,
  BudgetStoreInterface,
  ApprovalStoreInterface,
  IdempotencyStoreInterface,
  AgentInfo,
  PermissionGrant,
  BudgetCheckResult,
} from '../src/policy/engine.js';

// Mock implementations
class MockAgentRegistry implements AgentRegistryInterface {
  private agents = new Map<string, AgentInfo>();

  addAgent(agent: AgentInfo): void {
    this.agents.set(agent.agent_id, agent);
  }

  async get(agentId: string): Promise<AgentInfo | null> {
    return this.agents.get(agentId) || null;
  }

  clear(): void {
    this.agents.clear();
  }
}

class MockPermissionStore implements PermissionStoreInterface {
  private permissions = new Map<string, PermissionGrant>();

  addPermission(agentId: string, resource: string, mode: 'reveal' | 'use', grant: PermissionGrant): void {
    const key = `${agentId}:${resource}:${mode}`;
    this.permissions.set(key, grant);
  }

  async check(agentId: string, resource: string, mode: 'reveal' | 'use'): Promise<PermissionGrant | null> {
    // Check exact match
    const exactKey = `${agentId}:${resource}:${mode}`;
    if (this.permissions.has(exactKey)) {
      return this.permissions.get(exactKey)!;
    }

    // Check wildcard patterns
    for (const [key, grant] of this.permissions) {
      const [id, pattern, m] = key.split(':');
      if (id === agentId && m === mode && this.matchesPattern(resource, pattern)) {
        return grant;
      }
    }

    return null;
  }

  private matchesPattern(resource: string, pattern: string): boolean {
    if (pattern === '*' || pattern === '**') return true;
    if (pattern === resource) return true;
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      return resource.startsWith(prefix);
    }
    return false;
  }

  clear(): void {
    this.permissions.clear();
  }
}

class MockBudgetStore implements BudgetStoreInterface {
  private budgets = new Map<string, BudgetCheckResult>();

  setBudget(agentId: string, currency: string, result: BudgetCheckResult): void {
    this.budgets.set(`${agentId}:${currency}`, result);
  }

  async check(agentId: string, amount: number, currency: string): Promise<BudgetCheckResult> {
    const key = `${agentId}:${currency}`;
    return this.budgets.get(key) || { allowed: true, limit: Infinity, remaining: Infinity };
  }

  clear(): void {
    this.budgets.clear();
  }
}

class MockApprovalStore implements ApprovalStoreInterface {
  async create(request: PolicyRequest): Promise<string> {
    return `approval_${request.request_id}`;
  }
}

class MockIdempotencyStore implements IdempotencyStoreInterface {
  private keys = new Set<string>();

  addKey(key: string): void {
    this.keys.add(key);
  }

  async check(key: string): Promise<boolean> {
    return this.keys.has(key);
  }

  async set(key: string, _result: unknown): Promise<void> {
    this.keys.add(key);
  }

  clear(): void {
    this.keys.clear();
  }
}

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  let agentRegistry: MockAgentRegistry;
  let permissionStore: MockPermissionStore;
  let budgetStore: MockBudgetStore;
  let approvalStore: MockApprovalStore;
  let idempotencyStore: MockIdempotencyStore;
  let testNonceStore: NonceStore;

  beforeEach(() => {
    agentRegistry = new MockAgentRegistry();
    permissionStore = new MockPermissionStore();
    budgetStore = new MockBudgetStore();
    approvalStore = new MockApprovalStore();
    idempotencyStore = new MockIdempotencyStore();

    engine = new PolicyEngine(
      agentRegistry,
      permissionStore,
      budgetStore,
      approvalStore,
      idempotencyStore,
    );

    testNonceStore = new NonceStore();
  });

  afterEach(() => {
    agentRegistry.clear();
    permissionStore.clear();
    budgetStore.clear();
    idempotencyStore.clear();
    testNonceStore.destroy();
  });

  const createTestRequest = (overrides: Partial<PolicyRequest> = {}): PolicyRequest => ({
    agent_id: 'test-agent-123',
    request_id: 'req-' + Math.random().toString(36).slice(2),
    action: 'read',
    resource: 'wallet.solana.primary',
    access_mode: 'reveal',
    timestamp: Date.now(),
    nonce: 'nonce-' + Math.random().toString(36).slice(2),
    signature: 'dGVzdC1zaWduYXR1cmU=', // base64 "test-signature"
    ...overrides,
  });

  const setupValidAgent = (agentId = 'test-agent-123') => {
    agentRegistry.addAgent({
      agent_id: agentId,
      public_key: 'dGVzdC1wdWJsaWMta2V5', // base64 "test-public-key"
      status: 'connected',
    });
  };

  describe('replay protection', () => {
    it('should deny requests with invalid timestamp (too old)', async () => {
      setupValidAgent();
      const request = createTestRequest({
        timestamp: Date.now() - 60000, // 60 seconds ago
      });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('deny');
      expect((result as { reason: string }).reason).toContain('INVALID_TIMESTAMP');
    });

    it('should deny requests with invalid timestamp (too far in future)', async () => {
      setupValidAgent();
      const request = createTestRequest({
        timestamp: Date.now() + 60000, // 60 seconds in future
      });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('deny');
      expect((result as { reason: string }).reason).toContain('INVALID_TIMESTAMP');
    });

    it('should deny replay attempts (duplicate nonce)', async () => {
      setupValidAgent();
      permissionStore.addPermission('test-agent-123', 'wallet.solana.primary', 'reveal', {
        resource_pattern: 'wallet.solana.primary',
        access_mode: 'reveal',
        approval_mode: 'always_allow',
      });

      const nonce = 'unique-nonce-123';
      const request1 = createTestRequest({ nonce });
      const request2 = createTestRequest({ nonce }); // Same nonce

      // First request should succeed
      const result1 = await engine.evaluate(request1);
      expect(result1.status).toBe('allow');

      // Second request with same nonce should fail
      const result2 = await engine.evaluate(request2);
      expect(result2.status).toBe('deny');
      expect((result2 as { reason: string }).reason).toContain('REPLAY_DETECTED');
    });
  });

  describe('agent verification', () => {
    it('should deny unknown agent', async () => {
      const request = createTestRequest({ agent_id: 'unknown-agent' });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('deny');
      expect((result as { reason: string }).reason).toBe('UNKNOWN_AGENT');
    });

    it('should return agent_revoked for revoked agent', async () => {
      agentRegistry.addAgent({
        agent_id: 'revoked-agent',
        public_key: 'dGVzdC1wdWJsaWMta2V5',
        status: 'revoked',
      });

      const request = createTestRequest({ agent_id: 'revoked-agent' });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('agent_revoked');
    });
  });

  describe('permission checking', () => {
    beforeEach(() => {
      setupValidAgent();
    });

    it('should require approval when no permission exists', async () => {
      const request = createTestRequest();

      const result = await engine.evaluate(request);
      expect(result.status).toBe('approval_required');
      expect((result as { approval_id: string }).approval_id).toBeDefined();
    });

    it('should allow when permission exists', async () => {
      permissionStore.addPermission('test-agent-123', 'wallet.solana.primary', 'reveal', {
        resource_pattern: 'wallet.solana.primary',
        access_mode: 'reveal',
        approval_mode: 'always_allow',
      });

      const request = createTestRequest();

      const result = await engine.evaluate(request);
      expect(result.status).toBe('allow');
    });

    it('should deny when permission is always_deny', async () => {
      permissionStore.addPermission('test-agent-123', 'wallet.solana.primary', 'reveal', {
        resource_pattern: 'wallet.solana.primary',
        access_mode: 'reveal',
        approval_mode: 'always_deny',
      });

      const request = createTestRequest();

      const result = await engine.evaluate(request);
      expect(result.status).toBe('deny');
      expect((result as { reason: string }).reason).toBe('PERMISSION_DENIED');
    });
  });

  describe('budget checking', () => {
    beforeEach(() => {
      setupValidAgent();
      permissionStore.addPermission('test-agent-123', 'wallet.solana.primary', 'use', {
        resource_pattern: 'wallet.solana.primary',
        access_mode: 'use',
        approval_mode: 'always_allow',
      });
    });

    it('should allow when within budget', async () => {
      budgetStore.setBudget('test-agent-123', 'USD', {
        allowed: true,
        limit: 1000,
        remaining: 500,
      });

      const request = createTestRequest({
        access_mode: 'use',
        amount: 100,
        currency: 'USD',
      });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('allow');
    });

    it('should return budget_exceeded when over limit', async () => {
      budgetStore.setBudget('test-agent-123', 'USD', {
        allowed: false,
        limit: 100,
        remaining: 50,
      });

      const request = createTestRequest({
        access_mode: 'use',
        amount: 200,
        currency: 'USD',
      });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('budget_exceeded');
      expect((result as { limit: number }).limit).toBe(100);
      expect((result as { requested: number }).requested).toBe(200);
    });
  });

  describe('idempotency', () => {
    beforeEach(() => {
      setupValidAgent();
      permissionStore.addPermission('test-agent-123', 'wallet.solana.primary', 'use', {
        resource_pattern: 'wallet.solana.primary',
        access_mode: 'use',
        approval_mode: 'always_allow',
      });
    });

    it('should allow cached idempotent request', async () => {
      const idempotencyKey = 'idem-key-123';
      idempotencyStore.addKey(idempotencyKey);

      const request = createTestRequest({
        access_mode: 'use',
        idempotency_key: idempotencyKey,
      });

      const result = await engine.evaluate(request);
      expect(result.status).toBe('allow');
    });
  });
});
