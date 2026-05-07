/**
 * DCP Agent Configuration Storage
 *
 * Manages agent config files in ~/.dcp/agents/
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  verifyPairingGrant,
  decodePairingGrant,
  generateSigningKeyPair,
  type SignedPairingGrant,
} from '@dcprotocol/core';
import { AgentConfig, AgentError } from './types.js';

// ============================================================================
// Constants
// ============================================================================

// Support VPS install-service via DCP_DATA_DIR environment variable
const VPS_DATA_DIR = process.env.DCP_DATA_DIR;
const DEFAULT_CONFIG_DIR = path.join(os.homedir(), '.dcp', 'agents');
const CONFIG_DIR = VPS_DATA_DIR || DEFAULT_CONFIG_DIR;

type RawVpsConfig = {
  agent_id?: string;
  agent_name?: string;
  vault_id?: string;
  relay_url?: string;
  vault_public_key?: string;
  vault_signing_key?: string;
  vault_hpke_public_key?: string;
  vault_signing_public_key?: string;
  public_key?: string;
  hostname?: string;
  environment?: string;
  created_at?: string;
  paired_at?: string;
};

// ============================================================================
// Pairing Grant Processing
// ============================================================================

/**
 * Parse and verify a pairing grant token
 *
 * @param grantToken - The dcp_pair_v1_... token
 * @returns Verified grant payload
 * @throws AgentError if invalid or expired
 */
export function parseAndVerifyGrant(grantToken: string): SignedPairingGrant {
  // First try to decode (to check format)
  const decoded = decodePairingGrant(grantToken);
  if (!decoded) {
    throw new AgentError('INVALID_GRANT', 'Invalid pairing grant format');
  }

  // Verify signature and expiration
  const verified = verifyPairingGrant(grantToken);
  if (!verified) {
    // Check if it's expired specifically
    const expiresAt = new Date(decoded.payload.expires_at);
    if (expiresAt < new Date()) {
      throw new AgentError('GRANT_EXPIRED', 'Pairing grant has expired', {
        expires_at: decoded.payload.expires_at,
      });
    }
    throw new AgentError('INVALID_GRANT', 'Invalid pairing grant signature');
  }

  return verified;
}

/**
 * Create agent config from verified pairing grant
 *
 * Per PRD Section 7.3, generates a new Ed25519 keypair for the agent
 * to use when signing relay requests.
 *
 * IMPORTANT: The pairing grant is REQUEST-ONLY - it does not carry permission
 * authority. The vault policy DB is the ONLY enforcement source for permissions.
 */
export function createConfigFromGrant(grant: SignedPairingGrant): AgentConfig {
  // Generate agent's Ed25519 keypair for signing relay requests
  // Per PRD Section 7.3: agents need their own keypair for authentication
  const keypair = generateSigningKeyPair();

  // Create config with only connection info from the grant
  // Permission-related fields (scopes, budget, tier) are DEPRECATED in grants
  // and should NOT be trusted - vault policy DB is the only source of truth
  const config: AgentConfig = {
    agent_id: grant.agent_id,
    agent_name: grant.agent_name,
    vault_id: grant.vault_id,
    mode: grant.mode,
    vault_hpke_public_key: grant.vault_hpke_public_key,
    vault_signing_public_key: grant.vault_signing_public_key,
    relay_url: grant.relay_url,
    service_keypair: {
      public: keypair.publicKey.toString('base64'),
      private: keypair.privateKey.toString('base64'),
    },
    paired_at: new Date().toISOString(),
    grant_expires_at: grant.expires_at,
  };

  // Include deprecated fields if present (for backward compatibility)
  // These should NOT be trusted as authority
  if (grant.permission_scopes) {
    config.permission_scopes = grant.permission_scopes;
  }
  if (grant.budget) {
    config.budget = grant.budget;
  }
  if (grant.tier) {
    config.tier = grant.tier;
  }

  return config;
}

// ============================================================================
// Configuration Storage
// ============================================================================

/**
 * Ensure config directory exists
 */
function ensureConfigDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

/**
 * Get path to agent config file
 */
function getConfigPath(agentId: string): string {
  return path.join(CONFIG_DIR, `${agentId}.json`);
}

/**
 * Save agent configuration
 */
export function saveConfig(config: AgentConfig): void {
  ensureConfigDir();
  const configPath = getConfigPath(config.agent_id);
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
}

/**
 * Load agent configuration
 *
 * @param agentId - Agent ID to load
 * @throws AgentError if config not found
 */
export function loadConfig(agentId: string): AgentConfig {
  const configPath = getConfigPath(agentId);
  if (!fs.existsSync(configPath)) {
    throw new AgentError('CONFIG_NOT_FOUND', `No configuration found for agent: ${agentId}`);
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  return JSON.parse(raw) as AgentConfig;
}

/**
 * List all configured agents
 */
export function listConfigs(): AgentConfig[] {
  ensureConfigDir();
  const files = fs.readdirSync(CONFIG_DIR).filter((f) => f.endsWith('.json'));
  return files.map((f) => {
    const raw = fs.readFileSync(path.join(CONFIG_DIR, f), 'utf8');
    return JSON.parse(raw) as AgentConfig;
  });
}

/**
 * Delete agent configuration
 */
export function deleteConfig(agentId: string): boolean {
  const configPath = getConfigPath(agentId);
  if (!fs.existsSync(configPath)) {
    return false;
  }
  fs.unlinkSync(configPath);
  return true;
}

/**
 * Get the default agent (first configured)
 * In VPS mode (DCP_DATA_DIR set), looks for config.json directly
 */
export function getDefaultAgent(): AgentConfig | null {
  // VPS mode: check for single config.json in DCP_DATA_DIR
  if (VPS_DATA_DIR) {
    const vpsConfigPath = path.join(VPS_DATA_DIR, 'config.json');
    if (fs.existsSync(vpsConfigPath)) {
      const raw = fs.readFileSync(vpsConfigPath, 'utf8');
      const config = JSON.parse(raw) as RawVpsConfig;
      if (config.environment === 'vps') {
        return loadVpsAgentConfig(config);
      }
      return config as AgentConfig;
    }
    return null;
  }

  const configs = listConfigs();
  return configs.length > 0 ? configs[0] : null;
}

function loadVpsAgentConfig(config: RawVpsConfig): AgentConfig {
  if (!config.agent_id) {
    throw new AgentError(
      'CONFIG_NOT_FOUND',
      'VPS pairing is not approved yet. Run install-service again with a fresh invite.'
    );
  }

  const privateKey = loadVpsPrivateKey();
  if (!privateKey) {
    throw new AgentError('CONFIG_NOT_FOUND', 'VPS service key not found');
  }

  const publicKey = config.public_key;
  const vaultPublicKey = config.vault_hpke_public_key || config.vault_public_key;
  const vaultSigningKey = config.vault_signing_public_key || config.vault_signing_key;

  if (!config.vault_id || !config.relay_url || !vaultPublicKey || !vaultSigningKey || !publicKey) {
    throw new AgentError('CONFIG_NOT_FOUND', 'VPS agent config is incomplete');
  }

  return {
    agent_id: config.agent_id,
    agent_name: config.agent_name || config.hostname || config.agent_id,
    vault_id: config.vault_id,
    mode: 'mcp',
    vault_hpke_public_key: vaultPublicKey,
    vault_signing_public_key: vaultSigningKey,
    relay_url: config.relay_url,
    service_keypair: {
      public: publicKey,
      private: privateKey.toString('base64'),
    },
    paired_at: config.paired_at || config.created_at || new Date().toISOString(),
    grant_expires_at: '',
  };
}

/**
 * VPS pending pairing config (before grant is received)
 * Written by install-service, used to complete pairing
 */
export interface VpsPendingConfig {
  invite_id: string;
  relay_url: string;
  vault_public_key: string;
  public_key: string;
  hostname: string;
  version: string;
  mcp_host: string;
  mcp_port: number;
  environment: 'vps';
  created_at: string;
}

/**
 * Load VPS pending config (for pairing flow)
 */
export function loadVpsPendingConfig(): VpsPendingConfig | null {
  if (!VPS_DATA_DIR) return null;

  const configPath = path.join(VPS_DATA_DIR, 'config.json');
  if (!fs.existsSync(configPath)) return null;

  const raw = fs.readFileSync(configPath, 'utf8');
  const config = JSON.parse(raw);

  // Check if this is a pending config (has invite_id but no agent_id)
  if (config.invite_id && !config.agent_id) {
    return config as VpsPendingConfig;
  }

  return null;
}

/**
 * Load VPS private key from service.key file
 */
export function loadVpsPrivateKey(): Buffer | null {
  if (!VPS_DATA_DIR) return null;

  const keyPath = path.join(VPS_DATA_DIR, 'service.key');
  if (!fs.existsSync(keyPath)) return null;

  const keyBase64 = fs.readFileSync(keyPath, 'utf8').trim();
  return Buffer.from(keyBase64, 'base64');
}

/**
 * Save full agent config to VPS location (after pairing completes)
 */
export function saveVpsConfig(config: AgentConfig): void {
  if (!VPS_DATA_DIR) {
    throw new AgentError('CONFIG_NOT_FOUND', 'DCP_DATA_DIR not set for VPS mode');
  }

  const configPath = path.join(VPS_DATA_DIR, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
}

/**
 * Find agent by ID or name (partial match)
 */
export function findAgent(query: string): AgentConfig | null {
  const configs = listConfigs();
  // Try exact ID match first
  const byId = configs.find((c) => c.agent_id === query);
  if (byId) return byId;
  // Try name match (case-insensitive, partial)
  const byName = configs.find((c) =>
    c.agent_name.toLowerCase().includes(query.toLowerCase())
  );
  return byName || null;
}

/**
 * Update agent config with session token
 */
export function updateSessionToken(agentId: string, sessionToken: string): void {
  const config = loadConfig(agentId);
  config.session_token = sessionToken;
  saveConfig(config);
}

// ============================================================================
// Pairing Exchange
// ============================================================================

/**
 * Exchange a pairing grant with the vault to get session credentials
 *
 * Per PRD Section 7.3, after generating a keypair, the agent must exchange
 * the pairing grant with the vault to:
 * 1. Register the agent's public key
 * 2. Receive a session token
 *
 * @param grantToken - The original pairing grant token
 * @param config - The agent config with generated keypair
 * @returns Updated config with session_token
 * @throws AgentError if exchange fails
 */
export async function exchangePairingGrant(
  grantToken: string,
  config: AgentConfig
): Promise<AgentConfig> {
  // Determine the vault URL for exchange
  // For local pairing, use local server at 8421
  // For relay mode, this would go through the relay
  const localUrl = 'http://127.0.0.1:8421';

  try {
    const response = await fetch(`${localUrl}/v1/pairing-grants/exchange`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        pairing_grant: grantToken,
        service_public_key: config.service_keypair.public,
      }),
    });

    if (!response.ok) {
      const error = await response.json() as { error?: { code?: string; message?: string } };
      throw new AgentError(
        (error.error?.code || 'CONNECTION_FAILED') as 'INVALID_GRANT' | 'CONNECTION_FAILED',
        error.error?.message || 'Failed to exchange pairing grant'
      );
    }

    const result = await response.json() as { session_token?: string };

    // Update config with session token
    if (result.session_token) {
      config.session_token = result.session_token;
    }

    return config;
  } catch (err) {
    if (err instanceof AgentError) {
      throw err;
    }

    // Network error - vault might not be running locally
    // For now, we'll proceed without exchange (grant contains needed info)
    // Session token will be obtained on first connection
    console.warn('Note: Could not exchange pairing grant with local vault.');
    console.warn('Agent will connect via relay when running.');
    return config;
  }
}
