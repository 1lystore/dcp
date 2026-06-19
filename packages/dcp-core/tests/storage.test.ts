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
      storage.storeRecord('crypto.wallet.sol.3', 'WALLET_KEY', 'critical', encrypted, 'solana', 'sol3');

      const solanaWallets = storage.getWalletsByChain('solana');
      expect(solanaWallets.length).toBe(3);

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

  describe('Agent Connections', () => {
    it('should create and retrieve an agent connection', () => {
      const connection = storage.createAgentConnection({
        name: 'vps-trading-bot',
        mode: 'proxy',
        service_id: 'vps-trading-bot',
        permission_scopes: ['sign:solana', 'budget:check'],
        budget: {
          daily: 10,
          currency: 'USDC',
          auto_approve_under: 1,
        },
        tier: 'free',
        token_hash: 'token-hash',
      });

      expect(connection.agent_id).toMatch(/^agent_/);
      expect(connection.status).toBe('pending');
      expect(connection.request_count).toBe(0);

      const retrieved = storage.getAgentConnection(connection.agent_id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.name).toBe('vps-trading-bot');
      expect(retrieved!.mode).toBe('proxy');
      expect(retrieved!.service_id).toBe('vps-trading-bot');
      expect(retrieved!.permission_scopes).toEqual(['sign:solana', 'budget:check']);
      expect(retrieved!.budget.currency).toBe('USDC');
      expect(retrieved!.token_hash).toBe('token-hash');
    });

    it('should mark paired, heartbeat, request, and revoke an agent connection', () => {
      const connection = storage.createAgentConnection({
        name: 'hosted-research',
        mode: 'proxy',
        permission_scopes: ['read:credentials.api.*'],
        budget: {
          daily: 0,
          currency: 'USDC',
          auto_approve_under: 0,
        },
      });

      expect(storage.markAgentPaired(connection.agent_id, 'session-token-hash')).toBe(true);

      let updated = storage.getAgentConnection(connection.agent_id);
      expect(updated!.status).toBe('active');
      expect(updated!.paired_at).toBeTruthy();
      expect(updated!.last_seen_at).toBeTruthy();
      expect(updated!.token_hash).toBe('session-token-hash');

      expect(storage.recordAgentHeartbeat(connection.agent_id)).toBe(true);
      expect(storage.recordAgentRequest(connection.agent_id)).toBe(true);

      updated = storage.getAgentConnection(connection.agent_id);
      expect(updated!.request_count).toBe(1);
      expect(updated!.last_request_at).toBeTruthy();

      expect(storage.revokeAgentConnection(connection.agent_id)).toBe(true);

      updated = storage.getAgentConnection(connection.agent_id);
      expect(updated!.status).toBe('revoked');
      expect(updated!.revoked_at).toBeTruthy();
      expect(updated!.token_hash).toBeUndefined();
    });

    it('should list agent connections', () => {
      storage.createAgentConnection({
        name: 'agent-one',
        mode: 'sdk',
        permission_scopes: ['read:identity.*'],
        budget: { daily: 0, currency: 'USDC', auto_approve_under: 0 },
      });
      storage.createAgentConnection({
        name: 'agent-two',
        mode: 'mcp',
        permission_scopes: ['read:identity.*'],
        budget: { daily: 0, currency: 'USDC', auto_approve_under: 0 },
      });

      const connections = storage.listAgentConnections();
      expect(connections).toHaveLength(2);
      expect(connections.map((c) => c.name).sort()).toEqual(['agent-one', 'agent-two']);
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

    it('verifyPassphrase validates without changing lock state or corrupting the key', async () => {
      const passphrase = 'verify-pass-123';
      await storage.initializeMasterKey(passphrase);

      // Correct + wrong passphrase results.
      expect(await storage.verifyPassphrase(passphrase)).toBe(true);
      expect(await storage.verifyPassphrase('nope')).toBe(false);

      // Critical regression: verifyPassphrase must NOT zeroize/replace the cached
      // master key (the original bug). The vault stays usable after verification.
      expect(storage.isUnlocked()).toBe(true);
      const key = storage.getMasterKey();
      expect(key.length).toBe(32);
      expect(key.every((b) => b === 0)).toBe(false); // not all-zero (not corrupted)

      // While locked, verifyPassphrase still works and does not unlock the vault.
      storage.lock();
      expect(await storage.verifyPassphrase(passphrase)).toBe(true);
      expect(storage.isUnlocked()).toBe(false);
    });
  });

  describe('Telegram Configuration', () => {
    const passphrase = 'telegram-test-passphrase';

    beforeEach(async () => {
      // Initialize and unlock vault for telegram tests
      await storage.initializeMasterKey(passphrase);
    });

    afterEach(() => {
      // Clean up telegram config between tests
      try {
        storage.deleteTelegramConfig();
      } catch {
        // Ignore if not exists
      }
      storage.lock();
    });

    it('should create and retrieve Telegram config', () => {
      const config = storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'test-bot-token',
      });

      expect(config.id).toBeTruthy();
      expect(config.chat_id).toBe('123456789');
      expect(config.enabled).toBe(true);
      expect(config.notify_consent).toBe(true);
      expect(config.rate_limit_per_hour).toBe(30);

      const retrieved = storage.getTelegramConfig();
      expect(retrieved).not.toBeNull();
      expect(retrieved!.chat_id).toBe('123456789');
    });

    it('should retrieve encrypted bot token', () => {
      storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'my-secret-bot-token',
      });

      const token = storage.getTelegramBotToken();
      expect(token).toBe('my-secret-bot-token');
    });

    it('should update Telegram config', () => {
      storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'test-token',
      });

      const updated = storage.updateTelegramConfig({
        enabled: false,
        rate_limit_per_hour: 60,
      });

      expect(updated).toBe(true);

      const config = storage.getTelegramConfig();
      expect(config!.enabled).toBe(false);
      expect(config!.rate_limit_per_hour).toBe(60);
    });

    it('should delete Telegram config', () => {
      storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'test-token',
      });

      expect(storage.getTelegramConfig()).not.toBeNull();

      const deleted = storage.deleteTelegramConfig();
      expect(deleted).toBe(true);

      expect(storage.getTelegramConfig()).toBeNull();
    });

    it('should not create duplicate chat_id configs', () => {
      storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'test-token',
      });

      // Same chat_id should fail due to UNIQUE constraint
      expect(() => {
        storage.createTelegramConfig({
          chat_id: '123456789',
          bot_token: 'another-token',
        });
      }).toThrow();
    });

    it('should handle muted_until timestamp', () => {
      storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'test-token',
      });

      const mutedUntil = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      storage.updateTelegramConfig({ muted_until: mutedUntil });

      const config = storage.getTelegramConfig();
      expect(config!.muted_until).toBe(mutedUntil);
    });
  });

  describe('Telegram Pairing Codes', () => {
    it('should create and validate pairing code', () => {
      const code = storage.createTelegramPairingCode('test-vault-id');

      expect(code.code).toMatch(/^\d{6}$/);
      expect(code.expires_at).toBeTruthy();

      const validation = storage.validateTelegramPairingCode(code.code);
      expect(validation.valid).toBe(true);
      expect(validation.vault_id).toBe('test-vault-id');
    });

    it('should reject invalid pairing code', () => {
      const validation = storage.validateTelegramPairingCode('000000');
      expect(validation.valid).toBe(false);
      expect(validation.vault_id).toBeUndefined();
    });

    it('should reject used pairing code', () => {
      const code = storage.createTelegramPairingCode('test-vault-id');

      // First validation should succeed
      const first = storage.validateTelegramPairingCode(code.code);
      expect(first.valid).toBe(true);

      // Mark as used
      storage.markTelegramPairingCodeUsed(code.code);

      // Second validation should fail (code already used)
      const second = storage.validateTelegramPairingCode(code.code);
      expect(second.valid).toBe(false);
    });

    it('should reject expired pairing code', () => {
      // Create a code with expired timestamp (we'll need to mock this)
      const code = storage.createTelegramPairingCode('test-vault-id');

      // Manually expire the code by updating the database
      const db = (storage as unknown as { db: { prepare: (sql: string) => { run: (...args: unknown[]) => void } } }).db;
      db.prepare(`UPDATE telegram_pairing_codes SET expires_at = ? WHERE code = ?`).run(
        new Date(Date.now() - 1000).toISOString(),
        code.code
      );

      const validation = storage.validateTelegramPairingCode(code.code);
      expect(validation.valid).toBe(false);
    });
  });

  describe('Telegram Rate Limiting', () => {
    const passphrase = 'rate-limit-test-passphrase';

    beforeEach(async () => {
      await storage.initializeMasterKey(passphrase);
      storage.createTelegramConfig({
        chat_id: '123456789',
        bot_token: 'test-token',
      });
    });

    afterEach(() => {
      storage.deleteTelegramConfig();
      storage.lock();
    });

    it('should allow notifications under rate limit', () => {
      // Default rate limit is 30/hour
      // checkTelegramRateLimit returns false when NOT rate limited (can send)
      for (let i = 0; i < 5; i++) {
        expect(storage.checkTelegramRateLimit()).toBe(false);
        storage.recordTelegramNotification();
      }
    });

    it('should block notifications over rate limit', () => {
      // Set a low rate limit
      storage.updateTelegramConfig({ rate_limit_per_hour: 3 });

      // First 3 should pass (not rate limited = false)
      for (let i = 0; i < 3; i++) {
        expect(storage.checkTelegramRateLimit()).toBe(false);
        storage.recordTelegramNotification();
      }

      // 4th should be blocked (rate limited = true)
      expect(storage.checkTelegramRateLimit()).toBe(true);
    });

    it('should record and retrieve notification logs', () => {
      storage.logTelegramNotification({
        chat_id: '123456789',
        notification_type: 'consent_request',
        consent_id: 'consent_123',
      });
      storage.logTelegramNotification({
        chat_id: '123456789',
        notification_type: 'consent_request',
        consent_id: 'consent_456',
        error: 'Rate limited',
      });

      const logs = storage.getTelegramNotificationLogs(10);
      expect(logs.length).toBe(2);

      const failedLog = logs.find(l => l.error);
      expect(failedLog).toBeTruthy();
      expect(failedLog!.error).toBe('Rate limited');
    });

    it('should log notification via logTelegramNotification', () => {
      storage.logTelegramNotification({
        chat_id: '123456789',
        notification_type: 'test',
        consent_id: 'consent_test',
      });

      const logs = storage.getTelegramNotificationLogs(10);
      expect(logs.length).toBe(1);
      expect(logs[0].notification_type).toBe('test');
    });
  });

  describe('Retention pruning', () => {
    // Insert a backdated spend row directly (FK off, test-only) so we can exercise
    // pruning at arbitrary ages without standing up sessions.
    function insertSpend(id: string, key: string, createdAt: string): void {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const db = (storage as any).db;
      db.pragma('foreign_keys = OFF');
      db.prepare(
        'INSERT INTO spend_events (id, agent_session_id, amount, currency, chain, operation, destination, idempotency_key, status, tx_signature, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
      ).run(id, 'sess', 0.01, 'SOL', 'solana', 'transfer', null, key, 'committed', null, createdAt);
    }

    it('prunes old rows, keeps recent ones', () => {
      const old = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString();
      insertSpend('recent', 'recent-key', new Date().toISOString());
      insertSpend('old', 'old-key', old);
      storage.logAudit('EXECUTE', 'success', { operation: 'transfer' });

      const res = storage.pruneOldEvents({ auditRetentionDays: 90, spendRetentionDays: 90 });
      expect(res.spendDeleted).toBe(1);
      expect(storage.getSpendByIdempotencyKey('recent-key')).toBeTruthy();
      expect(storage.getSpendByIdempotencyKey('old-key')).toBeFalsy(); // removed
    });

    it('NEVER prunes within the budget window even if asked to (2-day floor)', () => {
      const twelveHoursAgo = new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString();
      insertSpend('r12h', 'r12h-key', twelveHoursAgo);
      // Aggressive 0-day retention is clamped to a 2-day floor inside storage.
      storage.pruneOldEvents({ spendRetentionDays: 0, auditRetentionDays: 0 });
      expect(storage.getSpendByIdempotencyKey('r12h-key')).toBeTruthy(); // budget data safe
    });

    it('vacuum runs without error', () => {
      expect(() => storage.vacuum()).not.toThrow();
    });
  });
});
