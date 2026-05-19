import { randomUUID } from 'node:crypto';
import { signMessage, generateSigningKeyPair } from '@dcprotocol/core';
import type {
  MobileAgentClient,
  MobileAgentEnvironment,
  MobileDcpScope,
  MobilePairingBudget,
  MobilePairingInvite,
  MobilePendingConfig,
} from './types.js';

export const MOBILE_PAIRING_TYPE = 'dcp_agent_pairing';
export const MOBILE_PAIRING_VERSION = '1.0';
export const DEFAULT_MOBILE_RELAY_URL = 'https://relay.dcp.1ly.store';

const SUPPORTED_CLIENTS = new Set<MobileAgentClient>([
  'claude-desktop',
  'cursor',
  'vscode',
  'hermes',
  'openclaw',
  'mcp',
  'custom',
  'hosted',
]);

const SUPPORTED_ENVIRONMENTS = new Set<MobileAgentEnvironment>([
  'local',
  'vps',
  'hosted',
  'dev',
]);

const SUPPORTED_SCOPES = new Set<MobileDcpScope>([
  'read:wallet.address',
  'sign:solana',
  'vault_get_address',
  'vault_budget_check',
  'vault_sign_tx',
  'vault_sign_message',
]);

export interface CreateMobilePairingInviteInput {
  client: MobileAgentClient;
  environment: MobileAgentEnvironment;
  agentName: string;
  relayUrl?: string;
  requestedScopes?: MobileDcpScope[];
  requestedBudget?: MobilePairingBudget;
  ttlSeconds?: number;
}

export interface CreatedMobilePairingInvite {
  invite: MobilePairingInvite;
  inviteUrl: string;
  pendingConfig: MobilePendingConfig;
}

function canonicalJson(value: Record<string, unknown>): string {
  return JSON.stringify(value, Object.keys(value).sort());
}

function encodeMobilePairingInvite(invite: MobilePairingInvite): string {
  return `dcp://pair?invite=${encodeURIComponent(JSON.stringify(invite))}`;
}

function assertSupported(input: CreateMobilePairingInviteInput): void {
  if (!SUPPORTED_CLIENTS.has(input.client)) {
    throw new Error(`Unsupported mobile agent client: ${input.client}`);
  }
  if (!SUPPORTED_ENVIRONMENTS.has(input.environment)) {
    throw new Error(`Unsupported mobile agent environment: ${input.environment}`);
  }
  for (const scope of input.requestedScopes || []) {
    if (!SUPPORTED_SCOPES.has(scope)) {
      throw new Error(`Unsupported mobile MVP scope: ${scope}`);
    }
  }
}

export function createMobilePairingInvite(
  input: CreateMobilePairingInviteInput
): CreatedMobilePairingInvite {
  assertSupported(input);

  const keypair = generateSigningKeyPair();
  const createdAt = new Date();
  const ttlSeconds = input.ttlSeconds ?? 10 * 60;
  const expiresAt = new Date(createdAt.getTime() + ttlSeconds * 1000);
  const inviteId = `mob_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const requestedBudget = input.requestedBudget ?? {
    daily: 0,
    currency: 'USDC',
    approval_threshold: 0,
  };

  const unsignedInvite: Omit<MobilePairingInvite, 'signature'> = {
    type: MOBILE_PAIRING_TYPE,
    version: MOBILE_PAIRING_VERSION,
    relay_url: (input.relayUrl || process.env.DCP_MOBILE_RELAY_URL || DEFAULT_MOBILE_RELAY_URL).replace(/\/$/, ''),
    invite_id: inviteId,
    agent_public_key: keypair.publicKey.toString('base64'),
    agent_name: input.agentName.trim(),
    agent_client: input.client,
    environment: input.environment,
    requested_scopes: input.requestedScopes ?? ['read:wallet.address', 'sign:solana'],
    requested_budget: requestedBudget,
    created_at: createdAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    nonce: randomUUID(),
  };

  const signature = Buffer.from(
    signMessage(Buffer.from(canonicalJson(unsignedInvite), 'utf8'), keypair.privateKey)
  ).toString('base64');

  const invite: MobilePairingInvite = {
    ...unsignedInvite,
    signature,
  };
  const inviteUrl = encodeMobilePairingInvite(invite);

  return {
    invite,
    inviteUrl,
    pendingConfig: {
      invite_id: inviteId,
      invite_url: inviteUrl,
      invite,
      service_keypair: {
        public: keypair.publicKey.toString('base64'),
        private: keypair.privateKey.toString('base64'),
      },
      pairing_status: 'pending_mobile_approval',
      created_at: createdAt.toISOString(),
    },
  };
}
