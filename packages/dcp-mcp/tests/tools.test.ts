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
  envelopeDecrypt,
} from '@dcprotocol/core';
import {
  vault_list_scopes,
  vault_get_address,
  vault_budget_check,
  vault_sign_message,
  vault_sign_typed_data,
  vault_sign_x402,
  vault_write,
  vault_unlock,
  vault_lock,
  ToolContext,
} from '../src/tools.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { verifyTypedData } from 'ethers';

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
      scope: 'crypto.wallet.solana',
      item_type: 'WALLET_KEY',
      sensitivity: 'critical',
      data: encrypted,
      chain: 'solana',
      public_address: info.public_address,
    });

    const { encrypted: baseEncrypted, info: baseInfo } = createWallet('base', masterKey);
    storage.createRecord({
      scope: 'crypto.wallet.base',
      item_type: 'WALLET_KEY',
      sensitivity: 'critical',
      data: baseEncrypted,
      chain: 'base',
      public_address: baseInfo.public_address,
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
      const solanaWallet = result.scopes.find(
        (s) => s.type === 'WALLET_KEY' && s.chain === 'solana'
      );
      expect(solanaWallet).toBeDefined();
      expect(solanaWallet?.public_address).toBeDefined();
      expect(solanaWallet?.operations).toContain('sign_tx');
      expect(solanaWallet?.operations).toContain('get_address');
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

  describe('vault_sign_message', () => {
    it('should sign a message and return a valid signature', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const walletScope = 'crypto.wallet.solana';
      const session = storage.createSession(
        'TestAgent',
        [walletScope],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      ctx.sessionId = session.id;

      const message = 'hello world';
      const result = await vault_sign_message(ctx, {
        chain: 'solana',
        message,
        encoding: 'utf8',
      });

      expect(result.signature).toBeDefined();
      expect(result.public_key).toBeDefined();
      expect(result.chain).toBe('solana');

      const signatureBytes = bs58.decode(result.signature);
      const publicKeyBytes = bs58.decode(result.public_key);
      const ok = nacl.sign.detached.verify(
        Buffer.from(message, 'utf8'),
        signatureBytes,
        publicKeyBytes
      );
      expect(ok).toBe(true);
    });
  });

  describe('vault_sign_typed_data', () => {
    it('should sign typed data and verify signer', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const walletScope = 'crypto.wallet.base';
      const session = storage.createSession(
        'TestAgent',
        [walletScope],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      ctx.sessionId = session.id;

      const typedData = {
        domain: {
          name: 'TestApp',
          version: '1',
          chainId: 8453,
          verifyingContract: '0x0000000000000000000000000000000000000000',
        },
        types: {
          Message: [
            { name: 'contents', type: 'string' },
          ],
        },
        message: {
          contents: 'Hello DCP',
        },
      };

      const result = await vault_sign_typed_data(ctx, {
        chain: 'base',
        typed_data: typedData,
      });

      expect(result.signature).toBeDefined();
      expect(result.public_key).toBeDefined();
      const recovered = verifyTypedData(
        typedData.domain,
        typedData.types,
        typedData.message,
        result.signature
      );
      expect(recovered.toLowerCase()).toBe(result.public_key.toLowerCase());
    });
  });

  describe('vault_sign_x402', () => {
    it('should sign x402 payload on solana', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const walletScope = 'crypto.wallet.solana';
      const session = storage.createSession(
        'TestAgent',
        [walletScope],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      ctx.sessionId = session.id;

      const payload = Buffer.from('x402-payload', 'utf8').toString('base64');
      const result = await vault_sign_x402(ctx, {
        network: 'solana',
        payload,
        amount: '0.05',
        currency: 'USDC',
        recipient: 'joe/weather',
        purpose: 'Pay for joe/weather API',
      });

      const signatureBytes = bs58.decode(result.signature);
      const publicKeyBytes = bs58.decode(result.public_key);
      const ok = nacl.sign.detached.verify(
        Buffer.from('x402-payload', 'utf8'),
        signatureBytes,
        publicKeyBytes
      );
      expect(ok).toBe(true);
    });

    it('should sign x402 payload on base with typed data', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      const walletScope = 'crypto.wallet.base';
      const session = storage.createSession(
        'TestAgent',
        [walletScope],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      ctx.sessionId = session.id;

      const typedData = {
        domain: {
          name: 'TestApp',
          version: '1',
          chainId: 8453,
          verifyingContract: '0x0000000000000000000000000000000000000000',
        },
        types: {
          Message: [
            { name: 'contents', type: 'string' },
          ],
        },
        message: {
          contents: 'Hello DCP',
        },
      };

      const payload = Buffer.from('x402-payload', 'utf8').toString('base64');
      const result = await vault_sign_x402(ctx, {
        network: 'base',
        payload,
        typed_data: typedData,
        amount: '0.05',
        currency: 'USDC',
        recipient: 'joe/weather',
        purpose: 'Pay for joe/weather API',
      });

      const recovered = verifyTypedData(
        typedData.domain,
        typedData.types,
        typedData.message,
        result.signature
      );
      expect(recovered.toLowerCase()).toBe(result.public_key.toLowerCase());
    });
  });

  describe('vault_write', () => {
    it('should write data with consented session and return created', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      budget.setConfig('write_permissions', {
        TestAgent: ['credentials.api.1ly'],
      });

      const session = storage.createSession(
        'TestAgent',
        ['credentials.api.1ly'],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      ctx.sessionId = session.id;

      const result = await vault_write(ctx, {
        scope: 'credentials.api.1ly',
        data: {
          schema_version: '1.0',
          label: null,
          service: '1ly',
          key: 'abc123',
          base_url: null,
          auth_type: 'bearer',
          headers: null,
        },
      });

      expect(result.created).toBe(true);
      expect(result.updated).toBe(false);
      expect(result.sensitivity).toBe('sensitive');

      const payload = storage.getEncryptedPayload('credentials.api.1ly');
      expect(payload).toBeDefined();
      const masterKey = storage.getMasterKey();
      const decrypted = envelopeDecrypt(payload!, masterKey);
      const data = JSON.parse(decrypted.toString('utf8'));
      expect(data.key).toBe('abc123');
      expect(data.schema_version).toBe('1.0');
    });

    it('should reject writes outside allowed scopes', async () => {
      const ctx: ToolContext = {
        storage,
        budget,
        agentName: 'TestAgent',
      };

      budget.setConfig('write_permissions', {
        TestAgent: ['credentials.api.1ly'],
      });

      await expect(
        vault_write(ctx, {
          scope: 'credentials.api.openai',
          data: { api_key: 'nope' },
        })
      ).rejects.toThrow(VaultError);
    });
  });
});
