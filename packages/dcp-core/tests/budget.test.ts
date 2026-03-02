/**
 * Tests for Budget & Policy Engine
 *
 * These tests verify:
 * - Budget configuration management
 * - Per-transaction limit enforcement (B1)
 * - Daily limit enforcement (B2)
 * - Approval threshold detection (B3)
 * - Rate limiting (B5)
 * - Currency mapping
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { VaultStorage } from '../src/storage.js';
import {
  BudgetEngine,
  DEFAULT_BUDGET_CONFIG,
  DEFAULT_VAULT_CONFIG,
  RATE_LIMIT_PER_MINUTE,
} from '../src/budget.js';
import { VaultError } from '../src/types.js';

describe('Budget Engine', () => {
  let storage: VaultStorage;
  let budget: BudgetEngine;
  let testVaultDir: string;

  beforeEach(() => {
    // Create a unique temp directory for each test
    testVaultDir = path.join(os.tmpdir(), `dcp-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();
    budget = new BudgetEngine(storage, testVaultDir);
  });

  afterEach(() => {
    // Cleanup
    storage.close();

    // Remove test directory
    if (fs.existsSync(testVaultDir)) {
      fs.rmSync(testVaultDir, { recursive: true, force: true });
    }
  });

  describe('Configuration Management', () => {
    it('should return default configuration', () => {
      const config = budget.getConfig();

      expect(config.version).toBe('1.0.0');
      expect(config.server_port).toBe(8420);
      expect(config.default_chain).toBe('solana');
      expect(config.daily_budget.SOL).toBe(20);
      expect(config.tx_limit.SOL).toBe(5);
      expect(config.approval_threshold.SOL).toBe(2);
    });

    it('should save and load configuration', () => {
      budget.setConfig('server_port', 9999);
      budget.saveConfig();

      // Create new budget engine to reload config
      const budget2 = new BudgetEngine(storage, testVaultDir);
      const config = budget2.getConfig();

      expect(config.server_port).toBe(9999);
    });

    it('should set individual limits', () => {
      budget.setLimit('daily_budget', 'SOL', 100);
      budget.setLimit('tx_limit', 'SOL', 25);
      budget.setLimit('approval_threshold', 'SOL', 10);

      const limits = budget.getLimits('SOL');

      expect(limits.daily_budget).toBe(100);
      expect(limits.tx_limit).toBe(25);
      expect(limits.approval_threshold).toBe(10);
    });

    it('should reject negative limits', () => {
      expect(() => {
        budget.setLimit('daily_budget', 'SOL', -10);
      }).toThrow();
    });

    it('should return zero for unknown currencies', () => {
      const limits = budget.getLimits('UNKNOWN_CURRENCY');

      expect(limits.daily_budget).toBe(0);
      expect(limits.tx_limit).toBe(0);
      expect(limits.approval_threshold).toBe(0);
    });

    it('should list supported currencies', () => {
      const currencies = budget.getSupportedCurrencies();

      expect(currencies).toContain('SOL');
      expect(currencies).toContain('ETH');
      expect(currencies).toContain('USDC');
      expect(currencies).toContain('BASE_ETH');
    });

    it('should return deep clone from getConfig to prevent external mutation', () => {
      const config1 = budget.getConfig();
      const originalSolLimit = config1.daily_budget.SOL;

      // Try to mutate the returned config externally
      config1.daily_budget.SOL = 9999;

      // Get config again - should NOT reflect the mutation
      const config2 = budget.getConfig();
      expect(config2.daily_budget.SOL).toBe(originalSolLimit);
      expect(config2.daily_budget.SOL).not.toBe(9999);
    });
  });

  describe('Budget Check - Per-Transaction Limit (B1)', () => {
    it('should allow transactions within limit', () => {
      // Default tx_limit.SOL = 5
      const result = budget.checkBudget(3, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
      expect(result.remaining_tx).toBe(2); // 5 - 3
    });

    it('should reject transactions exceeding limit', () => {
      // Default tx_limit.SOL = 5
      const result = budget.checkBudget(10, 'SOL', 'solana');

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('BUDGET_EXCEEDED_TX');
    });

    it('should allow exactly at limit', () => {
      // Default tx_limit.SOL = 5
      const result = budget.checkBudget(5, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
    });

    it('should never return negative remaining values', () => {
      // Test with amount exceeding tx_limit
      const result1 = budget.checkBudget(10, 'SOL', 'solana');
      expect(result1.remaining_tx).toBeGreaterThanOrEqual(0);
      expect(result1.remaining_daily).toBeGreaterThanOrEqual(0);

      // Test with unknown currency (limits are 0)
      const result2 = budget.checkBudget(100, 'UNKNOWN', 'solana');
      expect(result2.remaining_tx).toBeGreaterThanOrEqual(0);
      expect(result2.remaining_daily).toBeGreaterThanOrEqual(0);
    });

    it('should enforce budget and throw on exceeded', () => {
      expect(() => {
        budget.enforceBudget(10, 'SOL', 'solana');
      }).toThrow(VaultError);

      try {
        budget.enforceBudget(10, 'SOL', 'solana');
      } catch (error) {
        expect(error).toBeInstanceOf(VaultError);
        expect((error as VaultError).code).toBe('BUDGET_EXCEEDED_TX');
      }
    });
  });

  describe('Budget Check - Daily Limit (B2)', () => {
    it('should track daily spending', async () => {
      // Create a session for spend events
      const session = storage.createSession(
        'TestAgent',
        ['wallet.sign'],
        'session',
        new Date(Date.now() + 30 * 60 * 1000)
      );

      // Record some spending
      storage.recordSpend(session.id, 10, 'SOL', 'solana', 'sign_tx', 'committed');
      storage.recordSpend(session.id, 5, 'SOL', 'solana', 'sign_tx', 'committed');

      // Check budget - daily_budget.SOL = 20, spent = 15
      const result = budget.checkBudget(3, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
      expect(result.remaining_daily).toBe(2); // 20 - 15 - 3
    });

    it('should reject when daily limit exceeded', async () => {
      const session = storage.createSession(
        'TestAgent',
        ['wallet.sign'],
        'session',
        new Date(Date.now() + 30 * 60 * 1000)
      );

      // Spend up to limit: 18 SOL
      storage.recordSpend(session.id, 18, 'SOL', 'solana', 'sign_tx', 'committed');

      // Try to spend 5 more (18 + 5 = 23 > 20)
      const result = budget.checkBudget(5, 'SOL', 'solana');

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('BUDGET_EXCEEDED_DAILY');
    });

    it('should not count pending or failed transactions', async () => {
      const session = storage.createSession(
        'TestAgent',
        ['wallet.sign'],
        'session',
        new Date(Date.now() + 30 * 60 * 1000)
      );

      // Record pending and failed spends - these should NOT count
      storage.recordSpend(session.id, 10, 'SOL', 'solana', 'sign_tx', 'pending');
      storage.recordSpend(session.id, 10, 'SOL', 'solana', 'sign_tx', 'failed');

      // Also record a committed spend to verify only committed counts
      storage.recordSpend(session.id, 5, 'SOL', 'solana', 'sign_tx', 'committed');

      // Try to spend 4 SOL (within tx_limit of 5)
      // Daily spent = 5 (only committed counts, not pending/failed)
      // 5 + 4 = 9 <= 20 (daily_budget), so should be allowed
      const result = budget.checkBudget(4, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
      expect(result.remaining_daily).toBe(11); // 20 - 5 - 4 = 11
    });
  });

  describe('Budget Check - Approval Threshold (B3)', () => {
    it('should require approval above threshold', () => {
      // Default approval_threshold.SOL = 2
      const result = budget.checkBudget(3, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
      expect(result.requires_approval).toBe(true);
      expect(result.reason).toContain('APPROVAL_REQUIRED');
    });

    it('should not require approval at or below threshold', () => {
      // Default approval_threshold.SOL = 2
      const result = budget.checkBudget(2, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
      expect(result.requires_approval).toBe(false);
    });

    it('should not require approval for small amounts', () => {
      const result = budget.checkBudget(0.5, 'SOL', 'solana');

      expect(result.allowed).toBe(true);
      expect(result.requires_approval).toBe(false);
    });
  });

  describe('Rate Limiting (B5)', () => {
    it('should allow requests within limit', () => {
      const sessionId = 'test-session-1';

      // Record 4 executions (under limit of 5)
      for (let i = 0; i < 4; i++) {
        budget.recordExecution(sessionId);
      }

      expect(budget.isRateLimited(sessionId)).toBe(false);
      expect(budget.getRemainingExecutions(sessionId)).toBe(1);
    });

    it('should block requests over limit', () => {
      const sessionId = 'test-session-2';

      // Record 5 executions (at limit)
      for (let i = 0; i < 5; i++) {
        budget.recordExecution(sessionId);
      }

      expect(budget.isRateLimited(sessionId)).toBe(true);
      expect(budget.getRemainingExecutions(sessionId)).toBe(0);
    });

    it('should throw on rate limit exceeded', () => {
      const sessionId = 'test-session-3';

      // Record 5 executions
      for (let i = 0; i < 5; i++) {
        budget.recordExecution(sessionId);
      }

      // 6th execution should throw
      expect(() => {
        budget.recordExecution(sessionId);
      }).toThrow(VaultError);

      try {
        budget.recordExecution(sessionId);
      } catch (error) {
        expect(error).toBeInstanceOf(VaultError);
        expect((error as VaultError).code).toBe('RATE_LIMITED');
      }
    });

    it('should track sessions independently', () => {
      const session1 = 'session-a';
      const session2 = 'session-b';

      // Record 5 for session1
      for (let i = 0; i < 5; i++) {
        budget.recordExecution(session1);
      }

      // Session2 should still be allowed
      expect(budget.isRateLimited(session2)).toBe(false);
      expect(budget.getRemainingExecutions(session2)).toBe(5);
    });

    it('should clear rate limit data', () => {
      const sessionId = 'test-session-4';

      // Record some executions
      budget.recordExecution(sessionId);
      budget.recordExecution(sessionId);

      expect(budget.getRemainingExecutions(sessionId)).toBe(3);

      // Clear rate limit
      budget.clearRateLimit(sessionId);

      expect(budget.getRemainingExecutions(sessionId)).toBe(5);
    });
  });

  describe('Currency Mapping', () => {
    it('should map solana to SOL', () => {
      expect(BudgetEngine.getCurrencyForChain('solana')).toBe('SOL');
    });

    it('should map base to BASE_ETH', () => {
      expect(BudgetEngine.getCurrencyForChain('base')).toBe('BASE_ETH');
    });

    it('should map ethereum to ETH', () => {
      expect(BudgetEngine.getCurrencyForChain('ethereum')).toBe('ETH');
    });
  });

  describe('Default Values', () => {
    it('should have correct default budget config', () => {
      expect(DEFAULT_BUDGET_CONFIG.daily_budget.SOL).toBe(20);
      expect(DEFAULT_BUDGET_CONFIG.daily_budget.ETH).toBe(1);
      expect(DEFAULT_BUDGET_CONFIG.daily_budget.USDC).toBe(500);

      expect(DEFAULT_BUDGET_CONFIG.tx_limit.SOL).toBe(5);
      expect(DEFAULT_BUDGET_CONFIG.tx_limit.ETH).toBe(0.5);
      expect(DEFAULT_BUDGET_CONFIG.tx_limit.USDC).toBe(200);

      expect(DEFAULT_BUDGET_CONFIG.approval_threshold.SOL).toBe(2);
      expect(DEFAULT_BUDGET_CONFIG.approval_threshold.ETH).toBe(0.1);
      expect(DEFAULT_BUDGET_CONFIG.approval_threshold.USDC).toBe(100);
    });

    it('should have correct default vault config', () => {
      expect(DEFAULT_VAULT_CONFIG.server_port).toBe(8420);
      expect(DEFAULT_VAULT_CONFIG.session_timeout_minutes).toBe(30);
      expect(DEFAULT_VAULT_CONFIG.session_max_hours).toBe(4);
      expect(DEFAULT_VAULT_CONFIG.consent_timeout_seconds).toBe(300);
      expect(DEFAULT_VAULT_CONFIG.rate_limit_per_minute).toBe(5);
    });

    it('should have correct rate limit constant', () => {
      expect(RATE_LIMIT_PER_MINUTE).toBe(5);
    });
  });

  describe('Audit Integration', () => {
    it('should log config changes to audit', () => {
      budget.setLimit('daily_budget', 'SOL', 50);

      const events = storage.getAuditEvents(10);
      const configEvent = events.find(
        (e) => e.event_type === 'CONFIG' && e.operation === 'set_limit'
      );

      expect(configEvent).toBeDefined();
      expect(configEvent!.details).toContain('SOL');
      expect(configEvent!.details).toContain('50');
    });
  });
});
