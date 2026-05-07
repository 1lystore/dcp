/**
 * Tests for Input Validation Schemas
 */

import { describe, it, expect } from 'vitest';
import {
  validateRequest,
  UnlockRequestSchema,
  SignMessageRequestSchema,
  SignTxRequestSchema,
  WriteRequestSchema,
  CreatePairingGrantSchema,
  UUIDSchema,
  Base64Schema,
  ChainSchema,
} from '../src/policy/schemas.js';

describe('Input Validation', () => {
  describe('UUIDSchema', () => {
    it('should accept valid UUIDs', () => {
      expect(() => UUIDSchema.parse('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
    });

    it('should reject invalid UUIDs', () => {
      expect(() => UUIDSchema.parse('not-a-uuid')).toThrow();
      expect(() => UUIDSchema.parse('')).toThrow();
    });
  });

  describe('Base64Schema', () => {
    it('should accept valid base64', () => {
      expect(() => Base64Schema.parse('SGVsbG8gV29ybGQ=')).not.toThrow();
      expect(() => Base64Schema.parse('YWJjMTIz')).not.toThrow();
    });

    it('should reject invalid base64', () => {
      expect(() => Base64Schema.parse('invalid!@#')).toThrow();
    });
  });

  describe('ChainSchema', () => {
    it('should accept valid chains', () => {
      expect(ChainSchema.parse('solana')).toBe('solana');
      expect(ChainSchema.parse('ethereum')).toBe('ethereum');
      expect(ChainSchema.parse('base')).toBe('base');
    });

    it('should reject invalid chains', () => {
      expect(() => ChainSchema.parse('bitcoin')).toThrow();
      expect(() => ChainSchema.parse('')).toThrow();
    });
  });

  describe('UnlockRequestSchema', () => {
    it('should accept valid unlock request', () => {
      const result = validateRequest(UnlockRequestSchema, {
        passphrase: 'my-secure-passphrase',
      });
      expect(result.passphrase).toBe('my-secure-passphrase');
    });

    it('should reject empty passphrase', () => {
      expect(() => {
        validateRequest(UnlockRequestSchema, { passphrase: '' });
      }).toThrow('VALIDATION_ERROR');
    });

    it('should reject missing passphrase', () => {
      expect(() => {
        validateRequest(UnlockRequestSchema, {});
      }).toThrow('VALIDATION_ERROR');
    });

    it('should reject too long passphrase', () => {
      expect(() => {
        validateRequest(UnlockRequestSchema, { passphrase: 'a'.repeat(257) });
      }).toThrow('VALIDATION_ERROR');
    });
  });

  describe('SignMessageRequestSchema', () => {
    it('should accept valid sign message request', () => {
      const result = validateRequest(SignMessageRequestSchema, {
        chain: 'solana',
        message: 'Hello, World!',
      });
      expect(result.chain).toBe('solana');
      expect(result.message).toBe('Hello, World!');
    });

    it('should accept optional fields', () => {
      const result = validateRequest(SignMessageRequestSchema, {
        chain: 'ethereum',
        message: 'Sign this',
        encoding: 'utf8',
        description: 'Test signing',
      });
      expect(result.encoding).toBe('utf8');
      expect(result.description).toBe('Test signing');
    });

    it('should reject invalid chain', () => {
      expect(() => {
        validateRequest(SignMessageRequestSchema, {
          chain: 'invalid',
          message: 'test',
        });
      }).toThrow('VALIDATION_ERROR');
    });

    it('should reject empty message', () => {
      expect(() => {
        validateRequest(SignMessageRequestSchema, {
          chain: 'solana',
          message: '',
        });
      }).toThrow('VALIDATION_ERROR');
    });
  });

  describe('WriteRequestSchema', () => {
    it('should accept valid write request', () => {
      const result = validateRequest(WriteRequestSchema, {
        scope: 'credentials.api.openai',
        data: { api_key: 'sk-xxx' },
      });
      expect(result.scope).toBe('credentials.api.openai');
    });

    it('should accept optional sensitivity', () => {
      const result = validateRequest(WriteRequestSchema, {
        scope: 'identity.email',
        data: { value: 'test@example.com' },
        sensitivity: 'private',
      });
      expect(result.sensitivity).toBe('private');
    });

    it('should reject invalid sensitivity', () => {
      expect(() => {
        validateRequest(WriteRequestSchema, {
          scope: 'test',
          data: {},
          sensitivity: 'invalid',
        });
      }).toThrow('VALIDATION_ERROR');
    });
  });

  describe('CreatePairingGrantSchema', () => {
    it('should accept valid pairing grant request', () => {
      const result = validateRequest(CreatePairingGrantSchema, {
        agent_name: 'test-agent',
        permission_scopes: ['read:credentials.api.*', 'sign:solana'],
      });
      expect(result.agent_name).toBe('test-agent');
      expect(result.permission_scopes).toHaveLength(2);
    });

    it('should accept optional budget', () => {
      const result = validateRequest(CreatePairingGrantSchema, {
        agent_name: 'test-agent',
        permission_scopes: ['sign:solana'],
        budget: {
          daily: 10,
          currency: 'USD',
          auto_approve_under: 1,
        },
      });
      expect(result.budget?.daily).toBe(10);
    });

    it('should reject empty agent name', () => {
      expect(() => {
        validateRequest(CreatePairingGrantSchema, {
          agent_name: '',
          permission_scopes: ['sign:solana'],
        });
      }).toThrow('VALIDATION_ERROR');
    });

    it('should reject empty permission scopes', () => {
      expect(() => {
        validateRequest(CreatePairingGrantSchema, {
          agent_name: 'test',
          permission_scopes: [],
        });
      }).toThrow('VALIDATION_ERROR');
    });

    it('should reject TTL over 7 days', () => {
      expect(() => {
        validateRequest(CreatePairingGrantSchema, {
          agent_name: 'test',
          permission_scopes: ['sign:solana'],
          ttl_ms: 8 * 24 * 60 * 60 * 1000, // 8 days
        });
      }).toThrow('VALIDATION_ERROR');
    });
  });

  describe('validateRequest helper', () => {
    it('should return validated data on success', () => {
      const result = validateRequest(UnlockRequestSchema, {
        passphrase: 'test123',
      });
      expect(result).toEqual({ passphrase: 'test123' });
    });

    it('should throw with VALIDATION_ERROR prefix', () => {
      try {
        validateRequest(UnlockRequestSchema, {});
      } catch (error) {
        expect((error as Error).message).toMatch(/^VALIDATION_ERROR:/);
      }
    });

    it('should include field path in error message', () => {
      try {
        validateRequest(UnlockRequestSchema, { passphrase: '' });
      } catch (error) {
        expect((error as Error).message).toContain('passphrase');
      }
    });
  });
});
