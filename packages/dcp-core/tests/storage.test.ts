/**
 * Tests for Storage Layer
 *
 * These tests verify:
 * - Database initialization
 * - Vault records CRUD
 * - Agent sessions management
 * - Spend events tracking
 * - Audit logging
 * - Pending consents
 * - Master key management
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { VaultStorage } from '../src/storage.js';
import { generateKey, zeroize, envelopeEncrypt } from '../src/crypto.js';

describe('Storage Layer', () => {
  let storage: VaultStorage;
  let testVaultDir: string;

  beforeEach(() => {
    // Create a unique temp directory for each test
    testVaultDir = path.join(os.tmpdir(), `dcp-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();
  });

  afterEach(() => {
    // Cleanup
    storage.close();

    // Remove test directory
    if (fs.existsSync(testVaultDir)) {
      fs.rmSync(testVaultDir, { recursive: true, force: true });
    }
  });

  describe('Database Initialization', () => {
    it('should create vault directory', () => {
      expect(fs.existsSync(testVaultDir)).toBe(true);
    });

    it('should create vault.db file', () => {
      const dbPath = path.join(testVaultDir, 'vault.db');
      expect(fs.existsSync(dbPath)).toBe(true);
    });

    it('should report as initialized after schema creation', () => {
      expect(storage.isInitialized()).toBe(true);
    });

    it('should return correct vault directory', () => {
      expect(storage.getVaultDir()).toBe(testVaultDir);
    });
  });

  describe('Vault Records CRUD', () => {
    it('should store and retrieve a wallet record', () => {
      const masterKey = generateKey();
      const plaintext = Buffer.from('test-private-key');
      const encrypted = envelopeEncrypt(plaintext, masterKey);

      const record = storage.storeRecord(
        'crypto.wallet.sol',
        'WALLET_KEY',
        'critical',
        encrypted,
        'solana',
        '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU'
      );

      expect(record.id).toBeTruthy();
      expect(record.scope).toBe('crypto.wallet.sol');
      expect(record.item_type).toBe('WALLET_KEY');
      expect(record.sensitivity).toBe('critical');
      expect(record.chain).toBe('solana');
      expect(record.public_address).toBe('7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU');

      // Retrieve the record
      const retrieved = storage.getRecord('crypto.wallet.sol');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.scope).toBe('crypto.wallet.sol');
      expect(retrieved!.ciphertext.equals(encrypted.ciphertext)).toBe(true);

      zeroize(masterKey);
    });

    it('should store and retrieve personal data record', () => {
      const masterKey = generateKey();
      const plaintext = Buffer.from(JSON.stringify({ street: '123 Main St', city: 'NYC' }));
      const encrypted = envelopeEncrypt(plaintext, masterKey);

      storage.storeRecord('address.home', 'ADDRESS', 'sensitive', encrypted);

      const retrieved = storage.getRecord('address.home');
      expect(retrieved).not.toBeNull();
      expect(retrieved!.item_type).toBe('ADDRESS');
      expect(retrieved!.sensitivity).toBe('sensitive');

      zeroize(masterKey);
    });

    it('should get encrypted payload', () => {
      const masterKey = generateKey();
      const plaintext = Buffer.from('secret');
      const encrypted = envelopeEncrypt(plaintext, masterKey);

      storage.storeRecord('test.scope', 'PREFERENCES', 'standard', encrypted);

      const payload = storage.getEncryptedPayload('test.scope');
      expect(payload).not.toBeNull();
      expect(payload!.ciphertext.equals(encrypted.ciphertext)).toBe(true);
      expect(payload!.nonce.equals(encrypted.nonce)).toBe(true);

      zeroize(masterKey);
    });

    it('should list all scopes', () => {
      const masterKey = generateKey();
      const encrypted = envelopeEncrypt(Buffer.from('data'), masterKey);

      storage.storeRecord('crypto.wallet.sol', 'WALLET_KEY', 'critical', encrypted, 'solana', 'addr1');
      storage.storeRecord('address.home', 'ADDRESS', 'sensitive', encrypted);
      storage.storeRecord('preferences.sizes', 'PREFERENCES', 'standard', encrypted);

      const scopes = storage.listScopes();

      expect(scopes.length).toBe(3);
      expect(scopes.map((s) => s.scope)).toContain('crypto.wallet.sol');
      expect(scopes.map((s) => s.scope)).toContain('address.home');
      expect(scopes.map((s) => s.scope)).toContain('preferences.sizes');

      zeroize(masterKey);
    });

    it('should get wallets by chain', () => {
      const masterKey = generateKey();
      const encrypted = envelopeEncrypt(Buffer.from('key'), masterKey);

      storage.storeRecord('crypto.wallet.sol.1', 'WALLET_KEY', 'critical', encrypted, 'solana', 'sol1');
      storage.storeRecord('crypto.wallet.sol.2', 'WALLET_KEY', 'critical', encrypted, 'solana', 'sol2');
      storage.storeRecord('crypto.wallet.base', 'WALLET_KEY', 'critical', encrypted, 'base', 'base1');

      const solanaWallets = storage.getWalletsByChain('solana');
      expect(solanaWallets.length).toBe(2);

      const baseWallets = storage.getWalletsByChain('base');
      expect(baseWallets.length).toBe(1);

      zeroize(masterKey);
    });

    it('should delete a record', () => {
      const masterKey = generateKey();
      const encrypted = envelopeEncrypt(Buffer.from('data'), masterKey);

      storage.storeRecord('to.delete', 'PREFERENCES', 'standard', encrypted);
      expect(storage.getRecord('to.delete')).not.toBeNull();

      const deleted = storage.deleteRecord('to.delete');
      expect(deleted).toBe(true);
      expect(storage.getRecord('to.delete')).toBeNull();

      zeroize(masterKey);
    });

    it('should enforce unique scopes', () => {
      const masterKey = generateKey();
      const encrypted = envelopeEncrypt(Buffer.from('data'), masterKey);

      storage.storeRecord('unique.scope', 'PREFERENCES', 'standard', encrypted);

      // Trying to store same scope should throw
      expect(() => {
        storage.storeRecord('unique.scope', 'PREFERENCES', 'standard', encrypted);
      }).toThrow();

      zeroize(masterKey);
    });
  });

  describe('Agent Sessions', () => {
    it('should create a session', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 min
      const session = storage.createSession('Claude', ['address.read', 'wallet.sign'], 'session', expiresAt, {
        purpose: 'shopping',
        trustTier: 'verified',
      });

      expect(session.id).toBeTruthy();
      expect(session.agent_name).toBe('Claude');
      expect(session.granted_scopes).toContain('address.read');
      expect(session.consent_mode).toBe('session');
      expect(session.purpose).toBe('shopping');
      expect(session.trust_tier).toBe('verified');
    });

    it('should get active session', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      storage.createSession('TestAgent', ['scope1'], 'session', expiresAt);

      const active = storage.getActiveSession('TestAgent');
      expect(active).not.toBeNull();
      expect(active!.agent_name).toBe('TestAgent');
    });

    it('should not return expired session', () => {
      const expiresAt = new Date(Date.now() - 1000); // Already expired
      storage.createSession('ExpiredAgent', ['scope1'], 'session', expiresAt);

      const active = storage.getActiveSession('ExpiredAgent');
      expect(active).toBeNull();
    });

    it('should revoke a session', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      const session = storage.createSession('RevokeMe', ['scope1'], 'session', expiresAt);

      const revoked = storage.revokeSession(session.id);
      expect(revoked).toBe(true);

      const active = storage.getActiveSession('RevokeMe');
      expect(active).toBeNull();
    });

    it('should revoke all agent sessions', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      storage.createSession('MultiSession', ['scope1'], 'session', expiresAt);
      storage.createSession('MultiSession', ['scope2'], 'session', expiresAt);

      const count = storage.revokeAgentSessions('MultiSession');
      expect(count).toBe(2);

      const active = storage.getActiveSession('MultiSession');
      expect(active).toBeNull();
    });

    it('should list active sessions', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      storage.createSession('Agent1', ['scope1'], 'session', expiresAt);
      storage.createSession('Agent2', ['scope2'], 'session', expiresAt);

      const sessions = storage.listActiveSessions();
      expect(sessions.length).toBe(2);
    });
  });

  describe('Spend Events', () => {
    it('should record a spend event', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      const session = storage.createSession('Spender', ['wallet.sign'], 'session', expiresAt);

      const spend = storage.recordSpend(session.id, 1.5, 'SOL', 'solana', 'sign_tx', 'committed', {
        destination: 'recipient_address',
        txSignature: 'sig123',
      });

      expect(spend.id).toBeTruthy();
      expect(spend.amount).toBe(1.5);
      expect(spend.currency).toBe('SOL');
      expect(spend.status).toBe('committed');
    });

    it('should get daily spend total', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      const session = storage.createSession('DailySpender', ['wallet.sign'], 'session', expiresAt);

      storage.recordSpend(session.id, 2.0, 'SOL', 'solana', 'sign_tx', 'committed');
      storage.recordSpend(session.id, 3.5, 'SOL', 'solana', 'sign_tx', 'committed');
      storage.recordSpend(session.id, 1.0, 'SOL', 'solana', 'sign_tx', 'pending'); // Should not count

      const daily = storage.getDailySpend('SOL', 'solana');
      expect(daily).toBe(5.5); // Only committed
    });

    it('should enforce idempotency key uniqueness', () => {
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      const session = storage.createSession('IdempotentSpender', ['wallet.sign'], 'session', expiresAt);

      storage.recordSpend(session.id, 1.0, 'SOL', 'solana', 'sign_tx', 'committed', {
        idempotencyKey: 'unique-key-123',
      });

      expect(() => {
        storage.recordSpend(session.id, 1.0, 'SOL', 'solana', 'sign_tx', 'committed', {
          idempotencyKey: 'unique-key-123',
        });
      }).toThrow(/idempotency/i);
    });
  });

  describe('Audit Events', () => {
    it('should log an audit event', () => {
      const event = storage.logAudit('GRANT', 'success', {
        agentName: 'Claude',
        scope: 'address.home',
        operation: 'read',
        details: 'Session consent granted',
      });

      expect(event.id).toBeTruthy();
      expect(event.event_type).toBe('GRANT');
      expect(event.outcome).toBe('success');
      expect(event.agent_name).toBe('Claude');
    });

    it('should get recent audit events', () => {
      storage.logAudit('GRANT', 'success', { agentName: 'Agent1' });
      storage.logAudit('READ', 'success', { agentName: 'Agent1' });
      storage.logAudit('DENY', 'denied', { agentName: 'Agent2' });

      const events = storage.getAuditEvents(10);
      expect(events.length).toBe(3);
    });

    it('should filter audit events by type', () => {
      storage.logAudit('GRANT', 'success');
      storage.logAudit('READ', 'success');
      storage.logAudit('DENY', 'denied');

      const denies = storage.getAuditEvents(10, { eventType: 'DENY' });
      expect(denies.length).toBe(1);
      expect(denies[0].event_type).toBe('DENY');
    });

    it('should filter audit events by agent', () => {
      storage.logAudit('GRANT', 'success', { agentName: 'Agent1' });
      storage.logAudit('READ', 'success', { agentName: 'Agent1' });
      storage.logAudit('DENY', 'denied', { agentName: 'Agent2' });

      const agent1Events = storage.getAuditEvents(10, { agentName: 'Agent1' });
      expect(agent1Events.length).toBe(2);
    });
  });

  describe('Pending Consents', () => {
    it('should create a pending consent', () => {
      const consent = storage.createPendingConsent('Claude', 'sign_tx', 'crypto.wallet.sol', 'Sign 1.5 SOL tx');

      expect(consent.id).toBeTruthy();
      expect(consent.agent_name).toBe('Claude');
      expect(consent.action).toBe('sign_tx');
      expect(consent.scope).toBe('crypto.wallet.sol');
      expect(consent.status).toBe('pending');
    });

    it('should get pending consent by ID', () => {
      const consent = storage.createPendingConsent('Claude', 'read', 'address.home');

      const retrieved = storage.getPendingConsent(consent.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.id).toBe(consent.id);
    });

    it('should resolve consent as approved', () => {
      const consent = storage.createPendingConsent('Claude', 'read', 'address.home');

      const resolved = storage.resolveConsent(consent.id, 'approved');
      expect(resolved).toBe(true);

      const retrieved = storage.getPendingConsent(consent.id);
      expect(retrieved!.status).toBe('approved');
      expect(retrieved!.resolved_at).toBeTruthy();
    });

    it('should resolve consent as denied', () => {
      const consent = storage.createPendingConsent('Claude', 'sign_tx', 'crypto.wallet.sol');

      const resolved = storage.resolveConsent(consent.id, 'denied');
      expect(resolved).toBe(true);

      const retrieved = storage.getPendingConsent(consent.id);
      expect(retrieved!.status).toBe('denied');
    });

    it('should list pending consents', () => {
      storage.createPendingConsent('Agent1', 'read', 'scope1');
      storage.createPendingConsent('Agent2', 'sign_tx', 'scope2');

      const pending = storage.getPendingConsents();
      expect(pending.length).toBe(2);
    });

    it('should not resolve already resolved consent', () => {
      const consent = storage.createPendingConsent('Claude', 'read', 'address.home');
      storage.resolveConsent(consent.id, 'approved');

      // Try to resolve again
      const resolved = storage.resolveConsent(consent.id, 'denied');
      expect(resolved).toBe(false);
    });
  });

  describe('Master Key Management', () => {
    it('should report locked when no master key', () => {
      expect(storage.isUnlocked()).toBe(false);
    });

    it('should throw when getting master key while locked', () => {
      expect(() => storage.getMasterKey()).toThrow(/locked/i);
    });

    it('should initialize and unlock with passphrase', async () => {
      const passphrase = 'test-passphrase-123';

      // Initialize
      const masterKey = await storage.initializeMasterKey(passphrase);
      expect(masterKey).toBeTruthy();
      expect(masterKey.length).toBe(32);
      expect(storage.isUnlocked()).toBe(true);

      // Copy master key before locking (lock() zeroizes the internal buffer)
      const masterKeyCopy = Buffer.from(masterKey);

      // Lock
      storage.lock();
      expect(storage.isUnlocked()).toBe(false);

      // Unlock
      const unlocked = await storage.unlock(passphrase);
      expect(unlocked.equals(masterKeyCopy)).toBe(true);
      expect(storage.isUnlocked()).toBe(true);

      zeroize(masterKeyCopy);
      zeroize(unlocked);
    });

    it('should fail unlock with wrong passphrase', async () => {
      const passphrase = 'correct-passphrase';
      await storage.initializeMasterKey(passphrase);
      storage.lock();

      // Wrong passphrase should throw error due to AEAD authentication failure
      await expect(storage.unlock('wrong-passphrase')).rejects.toThrow(/wrong passphrase/i);

      // Correct passphrase should work
      const correctKey = await storage.unlock(passphrase);
      expect(correctKey).toBeTruthy();
      expect(storage.isUnlocked()).toBe(true);

      zeroize(correctKey);
    });
  });
});
