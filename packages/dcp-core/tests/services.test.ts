/**
 * Tests for Trusted Services (Sprint 2)
 *
 * These tests verify:
 * - Trusted services CRUD operations
 * - Service authorization checks
 * - Known services registry
 * - Service scope matching
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { VaultStorage } from '../src/storage.js';
import {
  KNOWN_SERVICES,
  getKnownService,
  listKnownServices,
  isKnownService,
  parsePublicKey,
  isValidPublicKey,
  DEFAULT_RELAY_URL,
} from '../src/services.js';
import type { TrustedService } from '../src/types.js';

describe('Trusted Services', () => {
  let storage: VaultStorage;
  let testVaultDir: string;

  beforeEach(() => {
    testVaultDir = path.join(os.tmpdir(), `dcp-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    storage = new VaultStorage(testVaultDir);
    storage.initializeSchema();
  });

  afterEach(() => {
    storage.close();
    if (fs.existsSync(testVaultDir)) {
      fs.rmSync(testVaultDir, { recursive: true, force: true });
    }
  });

  describe('addTrustedService', () => {
    it('should add a trusted service', () => {
      const service = storage.addTrustedService({
        service_id: 'test-service',
        name: 'Test Service',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz', // 32 bytes base64
        scopes: ['sign:solana', 'read:credentials.api.test'],
        budget: {
          daily: 10,
          currency: 'USDC',
          auto_approve_under: 1,
        },
        verified: false,
      });

      expect(service.service_id).toBe('test-service');
      expect(service.name).toBe('Test Service');
      expect(service.scopes).toEqual(['sign:solana', 'read:credentials.api.test']);
      expect(service.budget.daily).toBe(10);
      expect(service.budget.auto_approve_under).toBe(1);
      expect(service.enabled).toBe(true);
      expect(service.trusted_at).toBeTruthy();
    });

    it('should throw when adding duplicate service', () => {
      storage.addTrustedService({
        service_id: 'dup-service',
        name: 'Dup Service',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      expect(() => {
        storage.addTrustedService({
          service_id: 'dup-service',
          name: 'Dup Service 2',
          public_key: 'ed25519:different-key',
          scopes: ['sign:solana'],
          budget: { daily: 20, currency: 'USDC', auto_approve_under: 0 },
          verified: false,
        });
      }).toThrow('already trusted');
    });
  });

  describe('getTrustedService', () => {
    it('should retrieve a trusted service by ID', () => {
      storage.addTrustedService({
        service_id: 'retrieve-test',
        name: 'Retrieve Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 1 },
        verified: true,
      });

      const service = storage.getTrustedService('retrieve-test');
      expect(service).not.toBeNull();
      expect(service!.service_id).toBe('retrieve-test');
      expect(service!.verified).toBe(true);
    });

    it('should return null for non-existent service', () => {
      const service = storage.getTrustedService('non-existent');
      expect(service).toBeNull();
    });
  });

  describe('listTrustedServices', () => {
    it('should list all trusted services', () => {
      storage.addTrustedService({
        service_id: 'service-1',
        name: 'Service 1',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: true,
      });

      storage.addTrustedService({
        service_id: 'service-2',
        name: 'Service 2',
        public_key: 'ed25519:b3RoZXItcHVibGljLWtleS10aGlydHl0d29ieXRlcw==',
        scopes: ['sign:solana'],
        budget: { daily: 20, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      const services = storage.listTrustedServices();
      expect(services.length).toBe(2);
    });

    it('should list only enabled services when specified', () => {
      storage.addTrustedService({
        service_id: 'enabled-service',
        name: 'Enabled Service',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: true,
      });

      storage.addTrustedService({
        service_id: 'disabled-service',
        name: 'Disabled Service',
        public_key: 'ed25519:b3RoZXItcHVibGljLWtleS10aGlydHl0d29ieXRlcw==',
        scopes: ['sign:solana'],
        budget: { daily: 20, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      // Disable one service
      storage.updateTrustedService('disabled-service', { enabled: false });

      const enabledOnly = storage.listTrustedServices(true);
      expect(enabledOnly.length).toBe(1);
      expect(enabledOnly[0].service_id).toBe('enabled-service');
    });
  });

  describe('updateTrustedService', () => {
    it('should update service scopes', () => {
      storage.addTrustedService({
        service_id: 'update-test',
        name: 'Update Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      storage.updateTrustedService('update-test', {
        scopes: ['sign:solana', 'sign:solana', 'read:credentials.api.test'],
      });

      const service = storage.getTrustedService('update-test');
      expect(service!.scopes).toEqual(['sign:solana', 'sign:solana', 'read:credentials.api.test']);
    });

    it('should update service budget', () => {
      storage.addTrustedService({
        service_id: 'budget-test',
        name: 'Budget Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      storage.updateTrustedService('budget-test', {
        budget: { daily: 50, currency: 'USDC', auto_approve_under: 5 },
      });

      const service = storage.getTrustedService('budget-test');
      expect(service!.budget.daily).toBe(50);
      expect(service!.budget.auto_approve_under).toBe(5);
    });

    it('should throw when updating non-existent service', () => {
      expect(() => {
        storage.updateTrustedService('non-existent', { scopes: ['sign:solana'] });
      }).toThrow('not found');
    });
  });

  describe('markServiceConnected', () => {
    it('should mark service as connected', () => {
      storage.addTrustedService({
        service_id: 'connect-test',
        name: 'Connect Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      expect(storage.getTrustedService('connect-test')!.connected_at).toBeUndefined();

      storage.markServiceConnected('connect-test');

      const service = storage.getTrustedService('connect-test');
      expect(service!.connected_at).toBeTruthy();
    });
  });

  describe('revokeTrustedService', () => {
    it('should revoke a trusted service', () => {
      storage.addTrustedService({
        service_id: 'revoke-test',
        name: 'Revoke Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: false,
      });

      const revoked = storage.revokeTrustedService('revoke-test');
      expect(revoked).toBe(true);

      const service = storage.getTrustedService('revoke-test');
      expect(service).toBeNull();
    });

    it('should return false for non-existent service', () => {
      const revoked = storage.revokeTrustedService('non-existent');
      expect(revoked).toBe(false);
    });
  });

  describe('isServiceAuthorized', () => {
    beforeEach(() => {
      storage.addTrustedService({
        service_id: 'auth-test',
        name: 'Auth Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:solana', 'sign:solana', 'read:credentials.api.test'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: true,
      });
    });

    it('should authorize exact scope match', () => {
      const result = storage.isServiceAuthorized('auth-test', 'sign:solana');
      expect(result.authorized).toBe(true);
      expect(result.service).toBeTruthy();
    });

    it('should authorize prefix scope match', () => {
      // 'read:credentials.api.test' should allow 'read:credentials.api.test.key'
      const result = storage.isServiceAuthorized('auth-test', 'read:credentials.api.test.key');
      expect(result.authorized).toBe(true);
    });

    it('should deny unauthorized scope', () => {
      const result = storage.isServiceAuthorized('auth-test', 'sign:bitcoin');
      expect(result.authorized).toBe(false);
      expect(result.reason).toBeTruthy();
    });

    it('should deny non-existent service', () => {
      const result = storage.isServiceAuthorized('non-existent', 'sign:solana');
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Service not trusted');
    });

    it('should deny disabled service', () => {
      storage.updateTrustedService('auth-test', { enabled: false });

      const result = storage.isServiceAuthorized('auth-test', 'sign:solana');
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Service is disabled');
    });

    it('should authorize wildcard scope match', () => {
      storage.addTrustedService({
        service_id: 'wildcard-test',
        name: 'Wildcard Test',
        public_key: 'ed25519:dGVzdC1wdWJsaWMta2V5LXRoaXJ0eXR3b2J5dGVz',
        scopes: ['sign:*', 'read:credentials.api.*'],
        budget: { daily: 10, currency: 'USDC', auto_approve_under: 0 },
        verified: true,
      });

      // 'sign:*' should match 'sign:solana'
      const result1 = storage.isServiceAuthorized('wildcard-test', 'sign:solana');
      expect(result1.authorized).toBe(true);

      // 'sign:*' should match 'sign:solana'
      const result2 = storage.isServiceAuthorized('wildcard-test', 'sign:solana');
      expect(result2.authorized).toBe(true);

      // 'read:credentials.api.*' should match 'read:credentials.api.openai'
      const result3 = storage.isServiceAuthorized('wildcard-test', 'read:credentials.api.openai');
      expect(result3.authorized).toBe(true);
    });
  });
});

describe('Known Services Registry', () => {
  describe('KNOWN_SERVICES', () => {
    it('should have 1ly as a known service', () => {
      expect(KNOWN_SERVICES['1ly']).toBeDefined();
      expect(KNOWN_SERVICES['1ly'].verified).toBe(true);
    });

    it('should have valid service structure', () => {
      const onelyService = KNOWN_SERVICES['1ly'];
      expect(onelyService.service_id).toBe('1ly');
      expect(onelyService.name).toBe('1ly.store');
      expect(onelyService.connect_url).toContain('/api/dcp/connect');
      expect(onelyService.auth_url).toContain('/auth/dcp');
      expect(onelyService.public_key).toMatch(/^ed25519:/);
      expect(onelyService.default_scopes.length).toBeGreaterThan(0);
    });
  });

  describe('getKnownService', () => {
    it('should return known service by ID', () => {
      const service = getKnownService('1ly');
      expect(service).toBeDefined();
      expect(service!.service_id).toBe('1ly');
    });

    it('should be case-insensitive', () => {
      const service1 = getKnownService('1LY');
      const service2 = getKnownService('1ly');
      expect(service1).toBeDefined();
      expect(service2).toBeDefined();
    });

    it('should return undefined for unknown service', () => {
      const service = getKnownService('unknown-service');
      expect(service).toBeUndefined();
    });
  });

  describe('listKnownServices', () => {
    it('should return all known services', () => {
      const services = listKnownServices();
      expect(services.length).toBeGreaterThan(0);
      expect(services.some(s => s.service_id === '1ly')).toBe(true);
    });
  });

  describe('isKnownService', () => {
    it('should return true for known services', () => {
      expect(isKnownService('1ly')).toBe(true);
    });

    it('should return false for unknown services', () => {
      expect(isKnownService('my-custom-service')).toBe(false);
    });
  });
});

describe('Public Key Utilities', () => {
  describe('parsePublicKey', () => {
    it('should parse ed25519: prefixed key', () => {
      const result = parsePublicKey('ed25519:dGVzdC1rZXk=');
      expect(result.algorithm).toBe('ed25519');
      expect(result.keyData).toBe('dGVzdC1rZXk=');
    });

    it('should parse raw base64 key as ed25519', () => {
      const result = parsePublicKey('dGVzdC1rZXk=');
      expect(result.algorithm).toBe('ed25519');
      expect(result.keyData).toBe('dGVzdC1rZXk=');
    });
  });

  describe('isValidPublicKey', () => {
    it('should validate 32-byte ed25519 key', () => {
      // 32 bytes in base64
      const validKey = 'ed25519:' + Buffer.alloc(32).toString('base64');
      expect(isValidPublicKey(validKey)).toBe(true);
    });

    it('should reject invalid length key', () => {
      const invalidKey = 'ed25519:' + Buffer.alloc(16).toString('base64'); // 16 bytes
      expect(isValidPublicKey(invalidKey)).toBe(false);
    });

    it('should reject invalid base64', () => {
      expect(isValidPublicKey('ed25519:not-valid-base64!!!')).toBe(false);
    });
  });
});

describe('Relay Constants', () => {
  it('should have default relay URL', () => {
    expect(DEFAULT_RELAY_URL).toBe('wss://relay.dcp.1ly.store');
  });
});
