/**
 * DCP Agent Tests
 *
 * These tests focus on the agent-specific code that doesn't depend
 * on dcp-core's keytar-dependent modules.
 */

import { describe, it, expect } from 'vitest';
import { AgentError } from '../src/types.js';
import { VAULT_SIGN_X402_DESCRIPTION } from '../src/scope-guide.js';

// ============================================================================
// AgentError Tests
// ============================================================================

describe('AgentError', () => {
  it('should create error with code and message', () => {
    const err = new AgentError('INVALID_GRANT', 'Bad grant');
    expect(err.code).toBe('INVALID_GRANT');
    expect(err.message).toBe('Bad grant');
    expect(err.name).toBe('AgentError');
  });

  it('should include details if provided', () => {
    const err = new AgentError('CONNECTION_FAILED', 'Failed', { port: 8420 });
    expect(err.details).toEqual({ port: 8420 });
  });

  it('should serialize to JSON correctly', () => {
    const err = new AgentError('RATE_LIMITED', 'Too many requests', { retry_after: 60 });
    const json = err.toJSON();

    expect(json).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        details: { retry_after: 60 },
      },
    });
  });

  it('should have all error codes', () => {
    // Test that all error codes can be used
    const codes = [
      'INVALID_GRANT',
      'GRANT_EXPIRED',
      'CONFIG_NOT_FOUND',
      'CONNECTION_FAILED',
      'SESSION_EXPIRED',
      'RATE_LIMITED',
      'UNAUTHORIZED',
      'INTERNAL_ERROR',
    ] as const;

    for (const code of codes) {
      const err = new AgentError(code, `Test ${code}`);
      expect(err.code).toBe(code);
    }
  });
});

// ============================================================================
// JSON Output Redaction Tests
// ============================================================================

describe('JSON Output Redaction', () => {
  // Inline redaction logic for testing (mirrors index.ts redactConfigForOutput)
  function redactConfigForOutput(config: Record<string, unknown>): Record<string, unknown> {
    const REDACTED = '[REDACTED]';
    const redacted = { ...config };

    if (redacted.service_keypair && typeof redacted.service_keypair === 'object') {
      redacted.service_keypair = {
        ...(redacted.service_keypair as Record<string, unknown>),
        private: REDACTED,
      };
    }

    if ('session_token' in redacted && redacted.session_token) {
      redacted.session_token = REDACTED;
    }

    for (const key of Object.keys(redacted)) {
      const lowerKey = key.toLowerCase();
      if (
        (lowerKey.includes('private') || lowerKey.includes('secret') || lowerKey.includes('token')) &&
        typeof redacted[key] === 'string' &&
        redacted[key] !== REDACTED
      ) {
        redacted[key] = REDACTED;
      }
    }

    return redacted;
  }

  it('should redact service_keypair.private', () => {
    const config = {
      agent_id: 'agent_123',
      agent_name: 'TestAgent',
      service_keypair: {
        public: 'public_key_base64',
        private: 'SUPER_SECRET_PRIVATE_KEY',
      },
    };

    const redacted = redactConfigForOutput(config);

    expect(redacted.service_keypair).toEqual({
      public: 'public_key_base64',
      private: '[REDACTED]',
    });
  });

  it('should redact session_token', () => {
    const config = {
      agent_id: 'agent_123',
      session_token: 'secret_token_value',
    };

    const redacted = redactConfigForOutput(config);

    expect(redacted.session_token).toBe('[REDACTED]');
  });

  it('should redact any field containing "private", "secret", or "token"', () => {
    const config = {
      agent_id: 'agent_123',
      some_private_key: 'should_be_redacted',
      api_secret: 'also_redacted',
      auth_token: 'redacted_too',
      normal_field: 'not_redacted',
    };

    const redacted = redactConfigForOutput(config);

    expect(redacted.some_private_key).toBe('[REDACTED]');
    expect(redacted.api_secret).toBe('[REDACTED]');
    expect(redacted.auth_token).toBe('[REDACTED]');
    expect(redacted.normal_field).toBe('not_redacted');
  });

  it('should NOT output private keys in JSON string', () => {
    const config = {
      configured: true,
      agent_id: 'agent_123',
      service_keypair: {
        public: 'public_key',
        private: 'REAL_PRIVATE_KEY_DO_NOT_LEAK',
      },
      session_token: 'SESSION_TOKEN_DO_NOT_LEAK',
    };

    const redacted = redactConfigForOutput(config);
    const jsonString = JSON.stringify(redacted);

    // Must NOT contain actual secrets
    expect(jsonString).not.toContain('REAL_PRIVATE_KEY_DO_NOT_LEAK');
    expect(jsonString).not.toContain('SESSION_TOKEN_DO_NOT_LEAK');

    // Must contain redaction markers
    expect(jsonString).toContain('[REDACTED]');
  });

  it('should preserve non-sensitive fields', () => {
    const config = {
      agent_id: 'agent_123',
      agent_name: 'TestAgent',
      vault_id: 'vault_456',
      mode: 'local',
      relay_url: 'wss://relay.example.com',
      permission_scopes: ['read:identity.*', 'sign:*'],
    };

    const redacted = redactConfigForOutput(config);

    expect(redacted.agent_id).toBe('agent_123');
    expect(redacted.agent_name).toBe('TestAgent');
    expect(redacted.vault_id).toBe('vault_456');
    expect(redacted.mode).toBe('local');
    expect(redacted.relay_url).toBe('wss://relay.example.com');
    expect(redacted.permission_scopes).toEqual(['read:identity.*', 'sign:*']);
  });
});

// ============================================================================
// MCP Tool Description Tests
// ============================================================================

describe('MCP x402 tool description', () => {
  it('should clearly describe Solana x402 signing inputs', () => {
    expect(VAULT_SIGN_X402_DESCRIPTION).toContain('x402');
    expect(VAULT_SIGN_X402_DESCRIPTION).toContain('network must be solana');
    expect(VAULT_SIGN_X402_DESCRIPTION).toContain('payload must be');
    expect(VAULT_SIGN_X402_DESCRIPTION).toContain('base64');
    expect(VAULT_SIGN_X402_DESCRIPTION).toContain('amount');
    expect(VAULT_SIGN_X402_DESCRIPTION).toContain('currency');
  });
});

// ============================================================================
// Note: Tests for config.ts and connection.ts require keytar which isn't
// available in this environment. Those modules are tested through integration
// tests or manual testing with:
//   dcp-agent pair <grant>
//   dcp-agent run
// ============================================================================
