/**
 * Known Services Registry
 *
 * Built-in registry of verified services that can connect to DCP.
 * These are pre-configured with their public keys and endpoints.
 *
 * See protocol spec section B2 for the trust model.
 */

import type { KnownService } from './types.js';

// ============================================================================
// Known Services Registry
// ============================================================================

/**
 * Registry of known/verified services
 *
 * These services have been verified and their public keys are trusted.
 * Users can add custom services via `dcp trust <service> --key=...`
 */
export const KNOWN_SERVICES: Record<string, KnownService> = {
  '1ly': {
    service_id: '1ly',
    name: '1ly.store',
    connect_url: 'https://1ly.store/api/dcp/connect',
    auth_url: 'https://1ly.store/auth/dcp',
    public_key: 'ed25519:7Kf9xPQzTm8wKvYR5gH3nJ4bL6cM2dF1qE8sW0tU9vA',
    default_scopes: [
      'sign:solana',
      'read:credentials.api.1ly',
      'write:credentials.api.1ly',
    ],
    verified: true,
    description: 'API marketplace with autonomous agent payments',
    icon_url: 'https://1ly.store/favicon.ico',
  },
  virtuals: {
    service_id: 'virtuals',
    name: 'Virtuals Protocol',
    connect_url: 'https://virtuals.io/api/dcp/connect',
    auth_url: 'https://virtuals.io/auth/dcp',
    public_key: 'ed25519:placeholder_virtuals_key',
    default_scopes: ['sign:solana', 'read:credentials.api.virtuals'],
    verified: true,
    description: 'AI agent ecosystem',
  },
  eliza: {
    service_id: 'eliza',
    name: 'Eliza Framework',
    connect_url: 'https://eliza.ai/api/dcp/connect',
    auth_url: 'https://eliza.ai/auth/dcp',
    public_key: 'ed25519:placeholder_eliza_key',
    default_scopes: ['sign:solana', 'read:credentials.api.eliza'],
    verified: true,
    description: 'Open-source AI agent framework',
  },
};

// ============================================================================
// Registry Functions
// ============================================================================

/**
 * Get a known service by ID
 *
 * @param serviceId - Service identifier (e.g., '1ly')
 * @returns Known service config or undefined
 */
export function getKnownService(serviceId: string): KnownService | undefined {
  return KNOWN_SERVICES[serviceId.toLowerCase()];
}

/**
 * List all known services
 *
 * @returns Array of known services
 */
export function listKnownServices(): KnownService[] {
  return Object.values(KNOWN_SERVICES);
}

/**
 * Check if a service is known/verified
 *
 * @param serviceId - Service identifier
 * @returns true if the service is in the known registry
 */
export function isKnownService(serviceId: string): boolean {
  return serviceId.toLowerCase() in KNOWN_SERVICES;
}

/**
 * Parse a public key string
 *
 * Supports formats:
 * - ed25519:base64key (DCP format)
 * - raw base64 key
 *
 * @param key - Public key string
 * @returns { algorithm, keyData } or throws on invalid format
 */
export function parsePublicKey(key: string): { algorithm: string; keyData: string } {
  if (key.startsWith('ed25519:')) {
    return {
      algorithm: 'ed25519',
      keyData: key.slice(8),
    };
  }

  // Assume raw base64 is ed25519
  return {
    algorithm: 'ed25519',
    keyData: key,
  };
}

/**
 * Validate a public key format
 *
 * @param key - Public key string
 * @returns true if valid format, false otherwise
 */
export function isValidPublicKey(key: string): boolean {
  try {
    const { keyData } = parsePublicKey(key);

    // Check if it's valid base64
    const buffer = Buffer.from(keyData, 'base64');

    // Ed25519 public keys are 32 bytes
    return buffer.length === 32;
  } catch {
    return false;
  }
}

// ============================================================================
// Default Relay URL
// ============================================================================

/**
 * Default relay URL for DCP.
 *
 * Open source ships with NO hosted default — self-hosters point this at their
 * OWN relay via the `DCP_RELAY_URL` env var (or pass an explicit URL at the call
 * site). Managed products configure this explicitly. Empty string means
 * "relay not configured" and callers should require an explicit URL.
 */
export const DEFAULT_RELAY_URL = process.env.DCP_RELAY_URL || '';

/**
 * Alternative relay URLs (env-configurable; no hosted defaults in OSS).
 */
export const RELAY_URLS = {
  primary: process.env.DCP_RELAY_URL || '',
  fallback: process.env.DCP_RELAY_FALLBACK_URL || '',
};
