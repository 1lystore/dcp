/**
 * DCP Agent Secrets Provider
 *
 * Implements the OpenClaw exec provider protocol for fetching secrets from DCP vault.
 *
 * Protocol:
 * - Input (stdin): { "protocolVersion": 1, "provider": "dcp", "ids": ["credentials.api.openai"] }
 * - Output (stdout): { "protocolVersion": 1, "values": { "credentials.api.openai": "<value>" } }
 *
 * Usage in OpenClaw config (JSON5):
 * {
 *   secrets: {
 *     providers: {
 *       dcp: {
 *         source: "exec",
 *         command: "dcp-agent",
 *         args: ["secrets"]
 *       }
 *     }
 *   }
 * }
 */

import { AgentConnection } from './connection.js';
import { getDefaultAgent } from './config.js';
import { AgentError } from './types.js';

// ============================================================================
// OpenClaw Exec Provider Protocol Types
// ============================================================================

interface SecretsRequest {
  protocolVersion: number;
  provider: string;
  ids: string[];
}

interface SecretsResponse {
  protocolVersion: number;
  values: Record<string, string>;
  errors?: Record<string, { message: string }>;
}

// ============================================================================
// Secrets Provider
// ============================================================================

/**
 * Process a secrets request from stdin and output to stdout
 */
export async function processSecretsRequest(): Promise<void> {
  let request: SecretsRequest;

  try {
    // Read JSON request from stdin
    const input = await readStdin();
    request = JSON.parse(input) as SecretsRequest;

    // Validate protocol version
    if (request.protocolVersion !== 1) {
      throw new Error(`Unsupported protocol version: ${request.protocolVersion}`);
    }

    // Validate request has ids
    if (!Array.isArray(request.ids) || request.ids.length === 0) {
      throw new Error('No secret IDs requested');
    }
  } catch (err) {
    // Fatal error reading request - output error and exit
    const response: SecretsResponse = {
      protocolVersion: 1,
      values: {},
      errors: {
        _request: {
          message: err instanceof Error ? err.message : 'Invalid request format',
        },
      },
    };
    console.log(JSON.stringify(response));
    process.exit(1);
  }

  // Get agent config
  const config = getDefaultAgent();
  if (!config) {
    const response: SecretsResponse = {
      protocolVersion: 1,
      values: {},
      errors: {
        _config: {
          message: 'No agent configured. Run "dcp-agent pair <grant>" first.',
        },
      },
    };
    console.log(JSON.stringify(response));
    process.exit(1);
  }

  // Check that requested scopes are in the agent's permissions
  const allowedScopes = new Set(config.permission_scopes);
  const unauthorizedScopes: string[] = [];

  for (const id of request.ids) {
    const scope = normalizeScope(id);
    if (!isScopeAllowed(scope, allowedScopes)) {
      unauthorizedScopes.push(id);
    }
  }

  if (unauthorizedScopes.length > 0) {
    const response: SecretsResponse = {
      protocolVersion: 1,
      values: {},
      errors: Object.fromEntries(
        unauthorizedScopes.map((id) => [
          id,
          { message: `Scope not in agent permissions: ${id}` },
        ])
      ),
    };
    console.log(JSON.stringify(response));
    process.exit(1);
  }

  // Connect to vault and fetch secrets
  const connection = new AgentConnection(config);
  const values: Record<string, string> = {};
  const errors: Record<string, { message: string }> = {};

  try {
    await connection.connect();

    // Fetch each secret
    for (const id of request.ids) {
      const scope = normalizeScope(id);
      try {
        const result = await connection.readCredential(scope);

        // Extract the primary value from the credential data
        if (result.data === null) {
          errors[id] = { message: `No data returned for scope: ${scope}` };
        } else {
          const value = extractSecretValue(result.data, scope);
          if (value !== null) {
            values[id] = value;
          } else {
            errors[id] = { message: `No value found for scope: ${scope}` };
          }
        }
      } catch (err) {
        if (err instanceof AgentError) {
          errors[id] = { message: err.message };
        } else {
          errors[id] = {
            message: err instanceof Error ? err.message : 'Unknown error',
          };
        }
      }
    }
  } catch (err) {
    // Connection error
    const response: SecretsResponse = {
      protocolVersion: 1,
      values: {},
      errors: {
        _connection: {
          message: err instanceof Error ? err.message : 'Failed to connect to vault',
        },
      },
    };
    console.log(JSON.stringify(response));
    process.exit(1);
  } finally {
    await connection.close();
  }

  // Output response
  const response: SecretsResponse = {
    protocolVersion: 1,
    values,
    ...(Object.keys(errors).length > 0 && { errors }),
  };

  console.log(JSON.stringify(response));

  // Exit with error if any secrets failed
  if (Object.keys(errors).length > 0) {
    process.exit(1);
  }
}

/**
 * Fetch a single secret (for programmatic use)
 */
export async function fetchSecret(scope: string): Promise<string | null> {
  const config = getDefaultAgent();
  if (!config) {
    throw new AgentError('CONFIG_NOT_FOUND', 'No agent configured');
  }

  const connection = new AgentConnection(config);
  try {
    await connection.connect();
    const result = await connection.readCredential(normalizeScope(scope));
    if (result.data === null) {
      return null;
    }
    return extractSecretValue(result.data, scope);
  } finally {
    await connection.close();
  }
}

/**
 * Fetch multiple secrets (for programmatic use)
 */
export async function fetchSecrets(
  scopes: string[]
): Promise<Record<string, string | null>> {
  const config = getDefaultAgent();
  if (!config) {
    throw new AgentError('CONFIG_NOT_FOUND', 'No agent configured');
  }

  const connection = new AgentConnection(config);
  const results: Record<string, string | null> = {};

  try {
    await connection.connect();
    for (const scope of scopes) {
      try {
        const result = await connection.readCredential(normalizeScope(scope));
        if (result.data === null) {
          results[scope] = null;
        } else {
          results[scope] = extractSecretValue(result.data, scope);
        }
      } catch {
        results[scope] = null;
      }
    }
    return results;
  } finally {
    await connection.close();
  }
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Read all input from stdin
 */
function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');

    process.stdin.on('readable', () => {
      let chunk;
      while ((chunk = process.stdin.read()) !== null) {
        data += chunk;
      }
    });

    process.stdin.on('end', () => {
      resolve(data.trim());
    });

    process.stdin.on('error', reject);

    // Set a timeout for stdin
    setTimeout(() => {
      if (data.length === 0) {
        reject(new Error('No input received on stdin'));
      }
    }, 5000);
  });
}

/**
 * Normalize a secret ID to a DCP scope
 *
 * Supports formats:
 * - credentials.api.openai -> credentials.api.openai
 * - providers/openai/apiKey -> credentials.api.openai
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
 *
 * For API credentials, looks for common field names like:
 * - api_key, apiKey, key, token, secret, password
 */
function extractSecretValue(
  data: Record<string, unknown>,
  scope: string
): string | null {
  // Common field names for secrets
  const secretFields = [
    'api_key',
    'apiKey',
    'key',
    'token',
    'secret',
    'password',
    'value',
    // OpenAI specific
    'openai_api_key',
    // Provider specific based on scope
    scope.split('.').pop(),
  ];

  for (const field of secretFields) {
    if (field && typeof data[field] === 'string') {
      return data[field] as string;
    }
  }

  // If there's only one string field, return it
  const stringFields = Object.entries(data).filter(
    ([, v]) => typeof v === 'string'
  );
  if (stringFields.length === 1) {
    return stringFields[0][1] as string;
  }

  // Return the whole data as JSON if no single field found
  if (Object.keys(data).length > 0) {
    return JSON.stringify(data);
  }

  return null;
}
