import { randomUUID } from 'node:crypto';
import { signMessage, generateSigningKeyPair } from '@dcprotocol/core';
import type {
  MobileAgentClient,
  MobileAgentEnvironment,
  MobileDcpScope,
  MobilePairingApprovalStatus,
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
  agentId?: string;
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

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`;
  }

  return JSON.stringify(value);
}

function encodeMobilePairingInvite(invite: MobilePairingInvite): string {
  return `dcp://pair?invite=${encodeURIComponent(JSON.stringify(invite))}`;
}

export function canonicalMobileAgentId(client: MobileAgentClient): string {
  const ids: Record<MobileAgentClient, string> = {
    'claude-desktop': 'agent_claude_desktop',
    cursor: 'agent_cursor',
    vscode: 'agent_vscode',
    hermes: 'agent_hermes_local',
    openclaw: 'agent_openclaw_local',
    mcp: 'agent_local_mcp',
    custom: `agent_mobile_${randomUUID().replace(/-/g, '').slice(0, 12)}`,
    hosted: `agent_hosted_${randomUUID().replace(/-/g, '').slice(0, 12)}`,
  };
  return ids[client];
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
  const requestedAgentId = input.agentId?.trim() || canonicalMobileAgentId(input.client);
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
    requested_agent_id: requestedAgentId,
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

export async function getMobilePairingStatus(
  relayUrl: string,
  inviteId: string
): Promise<MobilePairingApprovalStatus> {
  const response = await fetch(
    `${relayUrl.replace(/\/$/, '')}/v1/mobile/pairings/${encodeURIComponent(inviteId)}/status`
  );

  if (!response.ok) {
    throw new Error(`Failed to fetch mobile pairing status (${response.status})`);
  }

  return (await response.json()) as MobilePairingApprovalStatus;
}

export async function waitForMobilePairingApproval(
  relayUrl: string,
  inviteId: string,
  options: { timeoutMs?: number; pollIntervalMs?: number } = {}
): Promise<MobilePairingApprovalStatus> {
  const timeoutMs = options.timeoutMs ?? 10 * 60 * 1000;
  const pollIntervalMs = options.pollIntervalMs ?? 2000;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const status = await getMobilePairingStatus(relayUrl, inviteId);
    if (status.status !== 'pending') {
      return status;
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  return {
    status: 'expired',
    invite_id: inviteId,
    error: 'Timed out waiting for mobile approval',
  };
}
