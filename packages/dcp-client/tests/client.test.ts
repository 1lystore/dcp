/**
 * DCP Client SDK Tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  DcpClient,
  createDcpClient,
  DcpError,
  vaultOffline,
  vaultLocked,
  consentRequired,
  invalidConfig,
  parseErrorResponse,
  DEFAULT_LOCAL_URL,
  DEFAULT_RELAY_URL,
} from '../src/index.js';

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('DcpClient', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(async () => {
    // Clean up any open clients
  });

  describe('Configuration', () => {
    it('should use default values when no config provided', () => {
      const client = new DcpClient();
      expect(client.getMode()).toBe('unknown'); // Not resolved yet
    });

    it('should respect explicit mode config', () => {
      const client = new DcpClient({ mode: 'local' });
      expect(client.getMode()).toBe('unknown'); // Not resolved until first call
    });

    it('should use provided agent name', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'ok', unlocked: true, version: '1.0.0' }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ chain: 'solana', address: '5abc...' }),
      });

      const client = new DcpClient({
        mode: 'local',
        agentName: 'test-agent',
      });

      await client.getAddress('solana');
      await client.close();
    });
  });

  describe('Local Transport', () => {
    it('should call health endpoint on isAvailable', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'ok', initialized: true, unlocked: true, version: '0.1.0' }),
      });

      const client = new DcpClient({ mode: 'local' });
      const result = await client.isAvailable();

      expect(result.available).toBe(true);
      expect(result.unlocked).toBe(true);
      expect(result.version).toBe('0.1.0');
      expect(result.mode).toBe('local');

      expect(mockFetch).toHaveBeenCalledWith(
        `${DEFAULT_LOCAL_URL}/health`,
        expect.objectContaining({ method: 'GET' })
      );

      await client.close();
    });

    it('should call address endpoint on getAddress', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ chain: 'solana', address: '5abc123...' }),
      });

      const client = new DcpClient({ mode: 'local' });
      const result = await client.getAddress('solana');

      expect(result.chain).toBe('solana');
      expect(result.address).toBe('5abc123...');

      expect(mockFetch).toHaveBeenCalledWith(
        `${DEFAULT_LOCAL_URL}/address/solana`,
        expect.objectContaining({ method: 'GET' })
      );

      await client.close();
    });

    it('should call sign endpoint on signTx', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          signed_tx: 'base64signedtx...',
          signature: 'sig123',
          chain: 'solana',
          remaining_daily: 9.5,
        }),
      });

      const client = new DcpClient({ mode: 'local' });
      const result = await client.signTx({
        chain: 'solana',
        unsignedTx: 'base64unsignedtx...',
        amount: 0.5,
        currency: 'USDC',
      });

      expect(result.signedTx).toBe('base64signedtx...');
      expect(result.signature).toBe('sig123');
      expect(result.chain).toBe('solana');
      expect(result.remainingDaily).toBe(9.5);

      expect(mockFetch).toHaveBeenCalledWith(
        `${DEFAULT_LOCAL_URL}/v1/vault/sign`,
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"chain":"solana"'),
        })
      );

      await client.close();
    });

    it('should handle consent required response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          requires_consent: true,
          consent_id: 'consent_123',
          expires_at: '2026-03-06T12:00:00Z',
          message: 'Consent required',
        }),
      });

      const client = new DcpClient({ mode: 'local' });

      try {
        await client.signTx({
          chain: 'solana',
          unsignedTx: 'base64unsignedtx...',
        });
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(DcpError);
        const dcpError = err as DcpError;
        expect(dcpError.code).toBe('CONSENT_REQUIRED');
        expect(dcpError.details.consent_id).toBe('consent_123');
        expect(dcpError.action).toBe('approve_in_dcp_app');
      }

      await client.close();
    });

    it('should handle vault locked error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({
          error: {
            code: 'VAULT_LOCKED',
            message: 'Vault is locked',
          },
        }),
      });

      const client = new DcpClient({ mode: 'local' });

      try {
        await client.getAddress('solana');
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(DcpError);
        const dcpError = err as DcpError;
        expect(dcpError.code).toBe('VAULT_LOCKED');
        expect(dcpError.action).toBe('open_dcp_app');
      }

      await client.close();
    });

    it('should call budget check endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          allowed: true,
          limits: { per_tx: 100, daily: 1000, approval_threshold: 10 },
          remaining: { daily: 950, per_tx: 100 },
          requires_approval: false,
        }),
      });

      const client = new DcpClient({ mode: 'local' });
      const result = await client.budgetCheck({
        amount: 5,
        currency: 'USDC',
        chain: 'solana',
      });

      expect(result.allowed).toBe(true);
      expect(result.requiresApproval).toBe(false);
      expect(result.remainingDaily).toBe(950);
      expect(result.limits?.perTx).toBe(100);

      await client.close();
    });

    it('should call read endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scope: 'credentials.api.openai',
          data: { key: 'sk-123...' },
          sensitivity: 'sensitive',
        }),
      });

      const client = new DcpClient({ mode: 'local' });
      const result = await client.readCredential('credentials.api.openai');

      expect(result.scope).toBe('credentials.api.openai');
      expect(result.data).toEqual({ key: 'sk-123...' });
      expect(result.sensitivity).toBe('sensitive');

      await client.close();
    });

    it('should call write endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scope: 'credentials.api.openai',
          created: true,
          updated: false,
          sensitivity: 'sensitive',
        }),
      });

      const client = new DcpClient({ mode: 'local' });
      const result = await client.writeCredential('credentials.api.openai', {
        key: 'sk-new123...',
      });

      expect(result.scope).toBe('credentials.api.openai');
      expect(result.created).toBe(true);
      expect(result.updated).toBe(false);

      await client.close();
    });
  });

  describe('Auto Mode', () => {
    it('should use local transport when vault is available and unlocked', async () => {
      // Health check success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'ok', unlocked: true }),
      });
      // Address request
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ chain: 'solana', address: '5abc...' }),
      });

      const client = new DcpClient({ mode: 'auto' });
      await client.getAddress('solana');

      expect(client.getMode()).toBe('local');
      await client.close();
    });

    it('should throw VAULT_LOCKED when vault is available but locked', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'ok', unlocked: false }),
      });

      const client = new DcpClient({ mode: 'auto' });

      try {
        await client.getAddress('solana');
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(DcpError);
        const dcpError = err as DcpError;
        expect(dcpError.code).toBe('VAULT_LOCKED');
      }

      await client.close();
    });

    it('should throw VAULT_OFFLINE when local unavailable and no relay config', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const client = new DcpClient({ mode: 'auto' });

      try {
        await client.getAddress('solana');
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(DcpError);
        const dcpError = err as DcpError;
        expect(dcpError.code).toBe('VAULT_OFFLINE');
      }

      await client.close();
    });
  });

  describe('Session Caching', () => {
    it('should cache session ID from responses', async () => {
      // First request - returns session_id
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          signed_tx: 'tx1',
          signature: 'sig1',
          chain: 'solana',
          session_id: 'session_123',
        }),
      });
      // Second request - should include cached session_id
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          signed_tx: 'tx2',
          signature: 'sig2',
          chain: 'solana',
        }),
      });

      const client = new DcpClient({ mode: 'local' });

      // First call
      await client.signTx({ chain: 'solana', unsignedTx: 'tx1' });

      // Second call should include session_id
      await client.signTx({ chain: 'solana', unsignedTx: 'tx2' });

      // Check that second call included session_id
      const secondCallBody = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(secondCallBody.session_id).toBe('session_123');

      await client.close();
    });

    it('should clear sessions on clearSession call', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          signed_tx: 'tx1',
          signature: 'sig1',
          chain: 'solana',
          session_id: 'session_123',
        }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          signed_tx: 'tx2',
          signature: 'sig2',
          chain: 'solana',
        }),
      });

      const client = new DcpClient({ mode: 'local' });

      await client.signTx({ chain: 'solana', unsignedTx: 'tx1' });
      client.clearSession();
      await client.signTx({ chain: 'solana', unsignedTx: 'tx2' });

      // Check that second call did NOT include session_id
      const secondCallBody = JSON.parse(mockFetch.mock.calls[1][1].body);
      expect(secondCallBody.session_id).toBeUndefined();

      await client.close();
    });
  });
});

describe('DcpError', () => {
  it('should create error with correct code and action', () => {
    const err = new DcpError('VAULT_OFFLINE', 'Vault is offline');
    expect(err.code).toBe('VAULT_OFFLINE');
    expect(err.action).toBe('open_dcp_app');
    expect(err.message).toBe('Vault is offline');
  });

  it('should serialize to JSON correctly', () => {
    const err = new DcpError('CONSENT_REQUIRED', 'Consent needed', {
      consent_id: 'c123',
      expires_at: '2026-03-06T12:00:00Z',
    });

    const json = err.toJSON();
    expect(json.ok).toBe(false);
    expect(json.error.code).toBe('CONSENT_REQUIRED');
    expect(json.error.action).toBe('approve_in_dcp_app');
    expect(json.error.details?.consent_id).toBe('c123');
  });

  it('should detect consent required errors', () => {
    const consentErr = new DcpError('CONSENT_REQUIRED', 'Need consent');
    const otherErr = new DcpError('VAULT_LOCKED', 'Locked');

    expect(consentErr.isConsentRequired()).toBe(true);
    expect(otherErr.isConsentRequired()).toBe(false);
  });

  it('should detect vault unavailable errors', () => {
    const offlineErr = new DcpError('VAULT_OFFLINE', 'Offline');
    const lockedErr = new DcpError('VAULT_LOCKED', 'Locked');
    const otherErr = new DcpError('CONSENT_REQUIRED', 'Consent');

    expect(offlineErr.isVaultUnavailable()).toBe(true);
    expect(lockedErr.isVaultUnavailable()).toBe(true);
    expect(otherErr.isVaultUnavailable()).toBe(false);
  });

  it('should detect budget exceeded errors', () => {
    const txErr = new DcpError('BUDGET_EXCEEDED_TX', 'Over tx limit');
    const dailyErr = new DcpError('BUDGET_EXCEEDED_DAILY', 'Over daily limit');
    const otherErr = new DcpError('VAULT_LOCKED', 'Locked');

    expect(txErr.isBudgetExceeded()).toBe(true);
    expect(dailyErr.isBudgetExceeded()).toBe(true);
    expect(otherErr.isBudgetExceeded()).toBe(false);
  });
});

describe('Error Factory Functions', () => {
  it('vaultOffline should create VAULT_OFFLINE error', () => {
    const err = vaultOffline();
    expect(err.code).toBe('VAULT_OFFLINE');
  });

  it('vaultLocked should create VAULT_LOCKED error', () => {
    const err = vaultLocked();
    expect(err.code).toBe('VAULT_LOCKED');
  });

  it('consentRequired should create CONSENT_REQUIRED error with details', () => {
    const err = consentRequired('c123', '2026-03-06T12:00:00Z');
    expect(err.code).toBe('CONSENT_REQUIRED');
    expect(err.details.consent_id).toBe('c123');
    expect(err.details.expires_at).toBe('2026-03-06T12:00:00Z');
  });

  it('invalidConfig should create INVALID_CONFIG error', () => {
    const err = invalidConfig('Missing vaultId');
    expect(err.code).toBe('INVALID_CONFIG');
    expect(err.message).toBe('Missing vaultId');
  });
});

describe('parseErrorResponse', () => {
  it('should parse error object format', () => {
    const err = parseErrorResponse({
      error: {
        code: 'BUDGET_EXCEEDED_TX',
        message: 'Over limit',
        details: { remaining_daily: 5 },
      },
    });

    expect(err.code).toBe('BUDGET_EXCEEDED_TX');
    expect(err.message).toBe('Over limit');
  });

  it('should parse consent required format', () => {
    const err = parseErrorResponse({
      requires_consent: true,
      consent_id: 'c123',
      expires_at: '2026-03-06T12:00:00Z',
    });

    expect(err.code).toBe('CONSENT_REQUIRED');
    expect(err.details.consent_id).toBe('c123');
  });

  it('should return INTERNAL_ERROR for unknown format', () => {
    const err = parseErrorResponse('random string');
    expect(err.code).toBe('INTERNAL_ERROR');
  });
});

describe('createDcpClient factory', () => {
  it('should create a client instance', () => {
    const client = createDcpClient();
    expect(client).toBeInstanceOf(DcpClient);
  });

  it('should pass config to client', () => {
    const client = createDcpClient({ agentName: 'test-agent' });
    expect(client).toBeInstanceOf(DcpClient);
  });
});
