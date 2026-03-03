/**
 * Tests for MCP Tools
 *
 * These tests verify:
 * - vault_list_scopes returns correct structure
 * - vault_get_address returns public address
 * - vault_budget_check returns budget info
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  VaultStorage,
  BudgetEngine,
  createWallet,
  VaultError,
} from '@dcprotocol/core';
import {
  vault_list_scopes,
  vault_get_address,
  vault_budget_check,
  vault_unlock,
  vault_lock,
  ToolContext,
} from '../src/tools.js';

describe('MCP Tools', () => {
  let storage: VaultStorage;
  let budget: BudgetEngine;
  let testVaultDir: string;
  let masterKey: Buffer;

  beforeEach(async () => {
    // Create a unique temp directory for each test
    testVaultDir = path.join(os.tmpdir(), `dcp-mcp-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();

    // Initialize master key
    masterKey = await storage.initializeMasterKey('test-passphrase');

    // Create a test wallet using correct API: createWallet(chain, masterKey)
    const { encrypted, info } = createWallet('solana', masterKey);

    // Store the wallet record
    storage.createRecord({
      scope: 'crypto.wallet.sol',
      item_type: 'WALLET_KEY',
      sensitivity: 'critical',
      data: encrypted,
      chain: 'solana',
      public_address: info.public_address,
    });

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

  describe('vault_list_scopes', () => {
    it('should return wallet in scopes', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const result = await vault_list_scopes(ctx);

      expect(result.scopes).toBeDefined();
      expect(result.scopes.length).toBeGreaterThan(0);

      // Find the wallet scope
      const walletScope = result.scopes.find((s) => s.type === 'WALLET_KEY');
      expect(walletScope).toBeDefined();
      expect(walletScope?.chain).toBe('solana');
      expect(walletScope?.public_address).toBeDefined();
      expect(walletScope?.operations).toContain('sign_tx');
      expect(walletScope?.operations).toContain('get_address');
    });

    it('should log audit event', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      await vault_list_scopes(ctx);

      const events = storage.getAuditEvents(10);
      const listEvent = events.find(
        (e) => e.event_type === 'READ' && e.operation === 'list_scopes'
      );

      expect(listEvent).toBeDefined();
    });
  });

  describe('vault_get_address', () => {
    it('should return wallet address for chain', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const result = await vault_get_address(ctx, { chain: 'solana' });

      expect(result.chain).toBe('solana');
      expect(result.address).toBeDefined();
      expect(result.address.length).toBeGreaterThan(0);
    });

    it('should throw for unknown chain', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      await expect(
        vault_get_address(ctx, { chain: 'ethereum' })
      ).rejects.toThrow(VaultError);
    });
  });

  describe('vault_budget_check', () => {
    it('should return budget info for SOL', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const result = await vault_budget_check(ctx, {
        amount: 1,
        currency: 'SOL',
      });

      expect(result.allowed).toBe(true);
      expect(result.limits.per_tx).toBe(5); // Default tx_limit
      expect(result.limits.daily).toBe(20); // Default daily_budget
      expect(result.limits.approval_threshold).toBe(2); // Default threshold
      expect(result.requires_approval).toBe(false); // 1 < 2
    });

    it('should require approval above threshold', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const result = await vault_budget_check(ctx, {
        amount: 3, // Above 2 SOL threshold
        currency: 'SOL',
      });

      expect(result.allowed).toBe(true);
      expect(result.requires_approval).toBe(true);
    });

    it('should deny above tx limit', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const result = await vault_budget_check(ctx, {
        amount: 10, // Above 5 SOL tx_limit
        currency: 'SOL',
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('BUDGET_EXCEEDED_TX');
    });
  });

  describe('vault_unlock / vault_lock', () => {
    it('should unlock and lock the vault', async () => {
      // Lock first
      storage.lock();
      expect(storage.isUnlocked()).toBe(false);

      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const unlockResult = await vault_unlock(ctx, { passphrase: 'test-passphrase' });
      expect(unlockResult.unlocked).toBe(true);
      expect(storage.isUnlocked()).toBe(true);

      const lockResult = await vault_lock(ctx);
      expect(lockResult.locked).toBe(true);
      expect(storage.isUnlocked()).toBe(false);
    });
  });
});
