import { describe, it, expect, beforeEach } from 'vitest';
import { InMemoryPermissionStore, type NewPermission } from '../src/policy/permission-store.js';

describe('PermissionStore', () => {
  let store: InMemoryPermissionStore;
  const testAgentId = 'test-agent-123';

  beforeEach(() => {
    store = new InMemoryPermissionStore();
  });

  const createTestPermission = (overrides: Partial<NewPermission> = {}): NewPermission => ({
    agent_id: testAgentId,
    access_mode: 'reveal',
    resource_pattern: 'wallet.solana.*',
    action_pattern: '*',
    approval_mode: 'always_allow',
    created_by: 'test-user',
    ...overrides,
  });

  describe('grant', () => {
    it('should create a permission and return an ID', async () => {
      const perm = createTestPermission();
      const id = await store.grant(perm);

      expect(id).toBeDefined();
      expect(typeof id).toBe('string');
    });

    it('should store the permission', async () => {
      const perm = createTestPermission();
      const id = await store.grant(perm);

      const retrieved = await store.get(id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.agent_id).toBe(testAgentId);
      expect(retrieved?.resource_pattern).toBe('wallet.solana.*');
    });
  });

  describe('check', () => {
    it('should find matching permission for exact resource', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.primary',
        access_mode: 'reveal',
      }));

      const result = await store.check(testAgentId, 'wallet.solana.primary', 'reveal');
      expect(result).not.toBeNull();
    });

    it('should find matching permission with wildcard', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        access_mode: 'reveal',
      }));

      const result = await store.check(testAgentId, 'wallet.solana.primary', 'reveal');
      expect(result).not.toBeNull();
    });

    it('should find matching permission with double wildcard', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.**',
        access_mode: 'reveal',
      }));

      const result = await store.check(testAgentId, 'wallet.solana.primary.address', 'reveal');
      expect(result).not.toBeNull();
    });

    it('should return null for non-matching resource', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        access_mode: 'reveal',
      }));

      const result = await store.check(testAgentId, 'wallet.ethereum.primary', 'reveal');
      expect(result).toBeNull();
    });

    it('should return null for non-matching mode', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        access_mode: 'reveal',
      }));

      const result = await store.check(testAgentId, 'wallet.solana.primary', 'use');
      expect(result).toBeNull();
    });

    it('should return null for different agent', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        access_mode: 'reveal',
      }));

      const result = await store.check('other-agent', 'wallet.solana.primary', 'reveal');
      expect(result).toBeNull();
    });

    it('should return null for expired permission', async () => {
      const pastDate = new Date(Date.now() - 1000).toISOString();
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        access_mode: 'reveal',
        expires_at: pastDate,
      }));

      const result = await store.check(testAgentId, 'wallet.solana.primary', 'reveal');
      expect(result).toBeNull();
    });

    it('should find non-expired permission', async () => {
      const futureDate = new Date(Date.now() + 60000).toISOString();
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        access_mode: 'reveal',
        expires_at: futureDate,
      }));

      const result = await store.check(testAgentId, 'wallet.solana.primary', 'reveal');
      expect(result).not.toBeNull();
    });
  });

  describe('pattern matching', () => {
    it('should match * at end of pattern', async () => {
      await store.grant(createTestPermission({ resource_pattern: 'data.*' }));
      expect(await store.check(testAgentId, 'data.personal', 'reveal')).not.toBeNull();
      expect(await store.check(testAgentId, 'data.work', 'reveal')).not.toBeNull();
    });

    it('should match * in middle of pattern', async () => {
      await store.grant(createTestPermission({ resource_pattern: 'wallet.*.primary' }));
      expect(await store.check(testAgentId, 'wallet.solana.primary', 'reveal')).not.toBeNull();
      expect(await store.check(testAgentId, 'wallet.ethereum.primary', 'reveal')).not.toBeNull();
      expect(await store.check(testAgentId, 'wallet.solana.secondary', 'reveal')).toBeNull();
    });

    it('should match ** for multiple segments', async () => {
      await store.grant(createTestPermission({ resource_pattern: 'config.**' }));
      expect(await store.check(testAgentId, 'config.a', 'reveal')).not.toBeNull();
      expect(await store.check(testAgentId, 'config.a.b', 'reveal')).not.toBeNull();
      expect(await store.check(testAgentId, 'config.a.b.c.d', 'reveal')).not.toBeNull();
    });

    it('should match global wildcard', async () => {
      await store.grant(createTestPermission({ resource_pattern: '*' }));
      expect(await store.check(testAgentId, 'anything', 'reveal')).not.toBeNull();
    });

    it('should match global double wildcard', async () => {
      await store.grant(createTestPermission({ resource_pattern: '**' }));
      expect(await store.check(testAgentId, 'anything.here.too', 'reveal')).not.toBeNull();
    });
  });

  describe('checkBudget', () => {
    it('should allow when no budget is configured', async () => {
      await store.grant(createTestPermission());

      const result = await store.checkBudget(testAgentId, 100, 'USD');
      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(Infinity);
    });

    it('should allow when within budget', async () => {
      await store.grant(createTestPermission({
        budget_daily: 1000,
        budget_currency: 'USD',
      }));

      const result = await store.checkBudget(testAgentId, 500, 'USD');
      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(1000);
      expect(result.remaining).toBe(1000);
    });

    it('should deny when exceeding budget', async () => {
      await store.grant(createTestPermission({
        budget_daily: 100,
        budget_currency: 'USD',
      }));

      // Record some spending
      await store.recordSpend(testAgentId, 80, 'USD');

      const result = await store.checkBudget(testAgentId, 50, 'USD');
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(20);
      expect(result.spent).toBe(80);
    });

    it('should aggregate budgets across permissions', async () => {
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.solana.*',
        budget_daily: 500,
        budget_currency: 'USD',
      }));
      await store.grant(createTestPermission({
        resource_pattern: 'wallet.ethereum.*',
        budget_daily: 500,
        budget_currency: 'USD',
      }));

      const result = await store.checkBudget(testAgentId, 800, 'USD');
      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(1000);
    });

    it('should check correct currency', async () => {
      await store.grant(createTestPermission({
        budget_daily: 1000,
        budget_currency: 'USD',
      }));

      const usdResult = await store.checkBudget(testAgentId, 500, 'USD');
      expect(usdResult.allowed).toBe(true);
      expect(usdResult.limit).toBe(1000);

      // No EUR budget configured, so unlimited
      const eurResult = await store.checkBudget(testAgentId, 999999, 'EUR');
      expect(eurResult.allowed).toBe(true);
      expect(eurResult.limit).toBe(Infinity);
    });
  });

  describe('recordSpend', () => {
    it('should track spending against budget', async () => {
      await store.grant(createTestPermission({
        budget_daily: 1000,
        budget_currency: 'USD',
      }));

      await store.recordSpend(testAgentId, 200, 'USD');
      await store.recordSpend(testAgentId, 300, 'USD');

      const result = await store.checkBudget(testAgentId, 100, 'USD');
      expect(result.spent).toBe(500);
      expect(result.remaining).toBe(500);
    });
  });

  describe('revoke', () => {
    it('should remove a permission', async () => {
      const id = await store.grant(createTestPermission());
      expect(await store.get(id)).not.toBeNull();

      await store.revoke(id);
      expect(await store.get(id)).toBeNull();
    });
  });

  describe('revokeAllForAgent', () => {
    it('should remove all permissions for an agent', async () => {
      await store.grant(createTestPermission());
      await store.grant(createTestPermission({ resource_pattern: 'data.*' }));
      await store.grant(createTestPermission({ resource_pattern: 'config.*' }));

      const count = await store.revokeAllForAgent(testAgentId);
      expect(count).toBe(3);

      const remaining = await store.listForAgent(testAgentId);
      expect(remaining).toHaveLength(0);
    });

    it('should not affect other agents', async () => {
      await store.grant(createTestPermission());
      await store.grant(createTestPermission({ agent_id: 'other-agent' }));

      await store.revokeAllForAgent(testAgentId);

      const testAgentPerms = await store.listForAgent(testAgentId);
      expect(testAgentPerms).toHaveLength(0);

      const otherAgentPerms = await store.listForAgent('other-agent');
      expect(otherAgentPerms).toHaveLength(1);
    });
  });

  describe('listForAgent', () => {
    it('should list all permissions for an agent', async () => {
      await store.grant(createTestPermission({ access_mode: 'reveal' }));
      await store.grant(createTestPermission({ access_mode: 'use' }));
      await store.grant(createTestPermission({ access_mode: 'reveal' }));

      const all = await store.listForAgent(testAgentId);
      expect(all).toHaveLength(3);
    });

    it('should filter by access mode', async () => {
      await store.grant(createTestPermission({ access_mode: 'reveal' }));
      await store.grant(createTestPermission({ access_mode: 'use' }));
      await store.grant(createTestPermission({ access_mode: 'reveal' }));

      const reveal = await store.listForAgent(testAgentId, 'reveal');
      expect(reveal).toHaveLength(2);

      const use = await store.listForAgent(testAgentId, 'use');
      expect(use).toHaveLength(1);
    });
  });
});
