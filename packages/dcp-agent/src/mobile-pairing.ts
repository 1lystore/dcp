import { randomUUID } from 'node:crypto';
import { canonicalJson, signMessage, generateSigningKeyPair } from '@dcprotocol/core';
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
// No hosted default in OSS — configure via DCP_MOBILE_RELAY_URL / DCP_RELAY_URL or
// pass relayUrl explicitly. Empty means "relay not configured".
export const DEFAULT_MOBILE_RELAY_URL =
  process.env.DCP_MOBILE_RELAY_URL || process.env.DCP_RELAY_URL || '';

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

function isSupportedMobileScope(scope: string): scope is MobileDcpScope {
  return (
    SUPPORTED_SCOPES.has(scope as MobileDcpScope) ||
    scope.startsWith('read:credentials.api.') ||
    scope.startsWith('write:credentials.api.')
  );
}

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
  shortInviteUrl: string;
  pendingConfig: MobilePendingConfig;
}

export { canonicalJson };

function encodeMobilePairingInvite(invite: MobilePairingInvite): string {
  return `dcp://pair?invite=${encodeURIComponent(JSON.stringify(invite))}`;
}

function encodeShortMobilePairingInvite(invite: MobilePairingInvite): string {
  const params = new URLSearchParams({
    relay: invite.relay_url,
    invite_id: invite.invite_id,
  });
  return `dcp://pair?${params.toString()}`;
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
    if (!isSupportedMobileScope(scope)) {
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
    currency: 'SOL',
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
    requested_scopes: input.requestedScopes ?? [],
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
  const shortInviteUrl = encodeShortMobilePairingInvite(invite);

  return {
    invite,
    inviteUrl,
    shortInviteUrl,
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

export async function publishMobilePairingInvite(invite: MobilePairingInvite): Promise<void> {
  const response = await fetch(`${invite.relay_url.replace(/\/$/, '')}/v1/mobile/pairings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ invite }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Failed to publish mobile pairing invite (${response.status})${text ? `: ${text}` : ''}`);
  }
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
