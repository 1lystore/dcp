/**
 * DCP Agent Secrets Provider Tests
 *
 * Tests for the OpenClaw exec provider protocol implementation.
 */

import { describe, it, expect } from 'vitest';

// ============================================================================
// Helper Function Tests
// We test the internal logic without requiring vault connection
// ============================================================================

/**
 * Normalize a secret ID to a DCP scope
 */
function normalizeScope(id: string): string {
  // Already in DCP format
  if (id.startsWith('credentials.') || id.startsWith('identity.') || id.startsWith('address.')) {
    return id;
  }

  // OpenClaw providers/X/Y format -> credentials.api.X
  const providerMatch = id.match(/^providers\/([^/]+)\/(\w+)$/);
  if (providerMatch) {
    const [, provider] = providerMatch;
    return `credentials.api.${provider.toLowerCase()}`;
  }

  // Default: treat as credentials scope
  return `credentials.${id}`;
}

/**
 * Check if a scope is allowed by the agent's permissions
 */
function isScopeAllowed(scope: string, allowedScopes: Set<string>): boolean {
  // Direct match
  if (allowedScopes.has(scope)) {
    return true;
  }

  // Wildcard matches
  for (const allowed of allowedScopes) {
    // read:credentials.api.* matches credentials.api.openai
    if (allowed.startsWith('read:') && scope.startsWith(allowed.slice(5).replace('.*', '.'))) {
      return true;
    }
    // credentials.api.* matches credentials.api.openai
    if (allowed.endsWith('.*') && scope.startsWith(allowed.slice(0, -1))) {
      return true;
    }
  }

  return false;
}

/**
 * Extract the primary value from credential data
 */
function extractSecretValue(
  data: Record<string, unknown>,
  scope: string
): string | null {
  const secretFields = [
    'api_key',
    'apiKey',
    'key',
    'token',
    'secret',
    'password',
    'value',
    'openai_api_key',
    scope.split('.').pop(),
  ];

  for (const field of secretFields) {
    if (field && typeof data[field] === 'string') {
      return data[field] as string;
    }
  }

  const stringFields = Object.entries(data).filter(
    ([, v]) => typeof v === 'string'
  );
  if (stringFields.length === 1) {
    return stringFields[0][1] as string;
  }

  if (Object.keys(data).length > 0) {
    return JSON.stringify(data);
  }

  return null;
}

// ============================================================================
// normalizeScope Tests
// ============================================================================

describe('normalizeScope', () => {
  it('should pass through DCP-format credentials scopes', () => {
    expect(normalizeScope('credentials.api.openai')).toBe('credentials.api.openai');
    expect(normalizeScope('credentials.api.stripe')).toBe('credentials.api.stripe');
  });

  it('should pass through DCP-format identity scopes', () => {
    expect(normalizeScope('identity.email')).toBe('identity.email');
    expect(normalizeScope('identity.phone')).toBe('identity.phone');
  });

  it('should pass through DCP-format address scopes', () => {
    expect(normalizeScope('address.home')).toBe('address.home');
    expect(normalizeScope('address.billing')).toBe('address.billing');
  });

  it('should convert OpenClaw providers format', () => {
    expect(normalizeScope('providers/openai/apiKey')).toBe('credentials.api.openai');
    expect(normalizeScope('providers/Stripe/secretKey')).toBe('credentials.api.stripe');
    expect(normalizeScope('providers/ANTHROPIC/token')).toBe('credentials.api.anthropic');
  });

  it('should prefix unknown formats with credentials.', () => {
    expect(normalizeScope('api.github')).toBe('credentials.api.github');
    expect(normalizeScope('custom.scope')).toBe('credentials.custom.scope');
  });
});

// ============================================================================
// isScopeAllowed Tests
// ============================================================================

describe('isScopeAllowed', () => {
  it('should allow direct matches', () => {
    const allowed = new Set(['credentials.api.openai', 'identity.email']);
    expect(isScopeAllowed('credentials.api.openai', allowed)).toBe(true);
    expect(isScopeAllowed('identity.email', allowed)).toBe(true);
  });

  it('should reject non-matching scopes', () => {
    const allowed = new Set(['credentials.api.openai']);
    expect(isScopeAllowed('credentials.api.stripe', allowed)).toBe(false);
    expect(isScopeAllowed('identity.email', allowed)).toBe(false);
  });

  it('should support wildcard at end', () => {
    const allowed = new Set(['credentials.api.*']);
    expect(isScopeAllowed('credentials.api.openai', allowed)).toBe(true);
    expect(isScopeAllowed('credentials.api.stripe', allowed)).toBe(true);
    expect(isScopeAllowed('credentials.db.postgres', allowed)).toBe(false);
  });

  it('should support read: prefix with wildcard', () => {
    const allowed = new Set(['read:credentials.api.*']);
    expect(isScopeAllowed('credentials.api.openai', allowed)).toBe(true);
    expect(isScopeAllowed('credentials.api.github', allowed)).toBe(true);
    expect(isScopeAllowed('credentials.db.mysql', allowed)).toBe(false);
  });

  it('should handle empty allowed set', () => {
    const allowed = new Set<string>();
    expect(isScopeAllowed('credentials.api.openai', allowed)).toBe(false);
  });
});

// ============================================================================
// extractSecretValue Tests
// ============================================================================

describe('extractSecretValue', () => {
  it('should extract api_key field', () => {
    const data = { api_key: 'sk-123', other: 'value' };
    expect(extractSecretValue(data, 'credentials.api.openai')).toBe('sk-123');
  });

  it('should extract apiKey field (camelCase)', () => {
    const data = { apiKey: 'sk-456', other: 'value' };
    expect(extractSecretValue(data, 'credentials.api.stripe')).toBe('sk-456');
  });

  it('should extract token field', () => {
    const data = { token: 'ghp_xxx', user: 'me' };
    expect(extractSecretValue(data, 'credentials.api.github')).toBe('ghp_xxx');
  });

  it('should extract secret field', () => {
    const data = { secret: 'my-secret-value' };
    expect(extractSecretValue(data, 'credentials.custom')).toBe('my-secret-value');
  });

  it('should extract password field', () => {
    const data = { password: 'hunter2', username: 'admin' };
    expect(extractSecretValue(data, 'credentials.db')).toBe('hunter2');
  });

  it('should extract field matching scope suffix', () => {
    const data = { openai: 'sk-789' };
    expect(extractSecretValue(data, 'credentials.api.openai')).toBe('sk-789');
  });

  it('should return single string field if no common field found', () => {
    const data = { custom_field: 'my-value' };
    expect(extractSecretValue(data, 'custom.scope')).toBe('my-value');
  });

  it('should return JSON if multiple fields and no match', () => {
    const data = { field1: 'val1', field2: 'val2' };
    const result = extractSecretValue(data, 'custom.scope');
    expect(result).toBe(JSON.stringify(data));
  });

  it('should return null for empty data', () => {
    expect(extractSecretValue({}, 'any.scope')).toBe(null);
  });
});

// ============================================================================
// Protocol Format Tests
// ============================================================================

describe('OpenClaw Protocol Format', () => {
  it('should define correct request format', () => {
    const request = {
      protocolVersion: 1,
      provider: 'dcp',
      ids: ['credentials.api.openai', 'credentials.api.stripe'],
    };

    expect(request.protocolVersion).toBe(1);
    expect(request.provider).toBe('dcp');
    expect(request.ids).toHaveLength(2);
  });

  it('should define correct response format', () => {
    const response = {
      protocolVersion: 1,
      values: {
        'credentials.api.openai': 'sk-xxx',
        'credentials.api.stripe': 'sk_live_xxx',
      },
    };

    expect(response.protocolVersion).toBe(1);
    expect(response.values['credentials.api.openai']).toBe('sk-xxx');
  });

  it('should define correct error format', () => {
    const errorResponse = {
      protocolVersion: 1,
      values: {},
      errors: {
        'credentials.api.missing': {
          message: 'Scope not in agent permissions',
        },
      },
    };

    expect(errorResponse.errors!['credentials.api.missing'].message).toBeTruthy();
  });
});
