#!/usr/bin/env node
/**
 * DCP Vault REST Server
 *
 * REST API for AI agents and browser UIs to interact with the vault.
 * SECURITY: Binds to 127.0.0.1 only - never exposed to network (protocol spec R1).
 *
 * Endpoints (protocol spec R2):
 * - GET  /health               - Health check
 * - GET  /scopes               - List available scopes
 * - GET  /address/:chain       - Get wallet address
 * - GET  /budget/check         - Check budget
 * - GET  /agents               - List active sessions
 * - GET  /consent              - List pending consents
 * - POST /consent/:id/approve  - Approve consent
 * - POST /consent/:id/deny     - Deny consent
 * - POST /revoke/:agent        - Revoke agent sessions
 *
 * v1 API Endpoints:
 * - POST /v1/vault/read        - Read data (with consent flow)
 * - POST /v1/vault/write       - Write data (with consent flow)
 * - POST /v1/vault/sign        - Sign transaction (with consent + budget)
 * - POST /v1/vault/sign-message - Sign message (with consent)
 * - POST /v1/vault/sign_message - Sign message (alias)
 * - POST /v1/vault/sign_x402   - Sign x402 payment (with consent)
 * - GET  /v1/vault/activity    - Get audit events
 * - POST /v1/vault/unlock      - Unlock vault (local only)
 * - POST /v1/vault/lock        - Lock vault (local only)
 * - POST /v1/vault/agents/:id/revoke - Revoke specific session
 */

import Fastify, { FastifyInstance, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import {
  VaultStorage,
  BudgetEngine,
  getStorage,
  getBudgetEngine,
  VaultError,
  Chain,
  ItemType,
  SensitivityLevel,
  AuditEventType,
  envelopeDecrypt,
  signTransaction,
  signSolanaMessage,
  type VaultErrorCode,
  type TrustedService,
  type AgentConnection,
  type AgentConnectionMode,
  type AgentConnectionTier,
  type TelegramConfig,
  type CreateTelegramConfigInput,
  type TelegramConsentPayload,
  type TelegramRequestCategory,
  isValidPublicKey,
  listKnownServices,
  createSignedPairingGrant,
  createVpsPairingInvite,
  parseVpsPairingInvite,
  verifyPairingGrantWithKey,
  decodePairingGrant,
  canonicalJson,
  DEFAULT_RELAY_URL as CORE_DEFAULT_RELAY_URL,
} from '@dcprotocol/core';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import keytar from 'keytar';
import nacl from 'tweetnacl';
import {
  RelayClient,
  generateKeyPair,
  generateSigningKeyPair,
  type HpkeKeyPair,
  type SigningKeyPair,
  type StoredPairingClaim,
} from '@dcprotocol/relay-client';

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_PORT = 8421;
const HOST = '127.0.0.1'; // SECURITY: localhost only
const MCP_UNLOCK_KEYCHAIN_SERVICE = 'dcp-mcp-unlock';
const MCP_UNLOCK_KEYCHAIN_ACCOUNT = 'passphrase';
const MCP_UNLOCK_META_ACCOUNT = 'meta';
const MCP_UNLOCK_SESSION_MINUTES = parseInt(
  process.env.DCP_MCP_SESSION_MINUTES || '30',
  10
);
const PACKAGE_VERSION = getPackageVersion();

// Desktop Owner Trust Model Constants
const OWNER_TOKEN_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const OWNER_TOKEN_MAX_AGE_MS = 4 * 60 * 60 * 1000; // 4 hours
const CHALLENGE_TIMEOUT_MS = 60 * 1000; // 60 seconds
const DEFAULT_RELAY_URL = process.env.DCP_RELAY_URL || '';

// In-memory storage for owner sessions and challenges
interface OwnerToken {
  token: string;
  desktop_id: string;
  created_at: number;
  last_used_at: number;
}

interface Challenge {
  nonce: string;
  desktop_id: string;
  expires_at: number;
}

const ownerTokens: Map<string, OwnerToken> = new Map(); // token -> OwnerToken
const pendingChallenges: Map<string, Challenge> = new Map(); // desktop_id -> Challenge

// ============================================================================
// Unlock Rate Limiting (protocol spec)
// ============================================================================
// 5 failed attempts per minute -> 5 minute lockout
const UNLOCK_MAX_ATTEMPTS = 5;
const UNLOCK_WINDOW_MS = 60 * 1000; // 1 minute window
const UNLOCK_LOCKOUT_MS = 5 * 60 * 1000; // 5 minute lockout

interface UnlockAttemptTracker {
  attempts: number[];
  locked_until: number | null;
}

const unlockAttempts: Map<string, UnlockAttemptTracker> = new Map();

function getUnlockRateLimitKey(request: FastifyRequest): string {
  // For localhost, we track by source port as a basic identifier
  // In production, this is always localhost so we use a single key
  return 'local';
}

function checkUnlockRateLimit(key: string): { allowed: boolean; retry_after_seconds?: number } {
  const now = Date.now();
  let tracker = unlockAttempts.get(key);

  if (!tracker) {
    tracker = { attempts: [], locked_until: null };
    unlockAttempts.set(key, tracker);
  }

  // Check if currently locked out
  if (tracker.locked_until && now < tracker.locked_until) {
    const retry_after_seconds = Math.ceil((tracker.locked_until - now) / 1000);
    return { allowed: false, retry_after_seconds };
  }

  // Clear lockout if expired
  if (tracker.locked_until && now >= tracker.locked_until) {
    tracker.locked_until = null;
    tracker.attempts = [];
  }

  // Clean up old attempts outside the window
  const windowStart = now - UNLOCK_WINDOW_MS;
  tracker.attempts = tracker.attempts.filter((t) => t > windowStart);

  return { allowed: true };
}

function recordUnlockFailure(key: string): { locked: boolean; retry_after_seconds?: number } {
  const now = Date.now();
  let tracker = unlockAttempts.get(key);

  if (!tracker) {
    tracker = { attempts: [], locked_until: null };
    unlockAttempts.set(key, tracker);
  }

  // Record this attempt
  tracker.attempts.push(now);

  // Clean up old attempts outside the window
  const windowStart = now - UNLOCK_WINDOW_MS;
  tracker.attempts = tracker.attempts.filter((t) => t > windowStart);

  // Check if we've exceeded the limit
  if (tracker.attempts.length >= UNLOCK_MAX_ATTEMPTS) {
    tracker.locked_until = now + UNLOCK_LOCKOUT_MS;
    const retry_after_seconds = Math.ceil(UNLOCK_LOCKOUT_MS / 1000);
    return { locked: true, retry_after_seconds };
  }

  return { locked: false };
}

function clearUnlockRateLimit(key: string): void {
  unlockAttempts.delete(key);
}

// ============================================================================
// Permission Scope Normalization
// ============================================================================
// Fixes old permission_scopes saved without operation prefix (read:/write:/sign:)
// This ensures backward compatibility with agents created before the fix
const SIGNING_CHAINS = ['solana'];

function normalizePermissionScope(scope: string): string {
  // Already has a valid prefix - return as-is
  if (scope.startsWith('read:') || scope.startsWith('write:') || scope.startsWith('sign:')) {
    return scope;
  }

  // Check if it's a chain name that should be sign:
  const lowerScope = scope.toLowerCase();
  if (SIGNING_CHAINS.includes(lowerScope)) {
    return `sign:${lowerScope}`;
  }

  // Everything else gets read: prefix (identity, credentials, etc.)
  return `read:${scope}`;
}

function normalizePermissionScopes(scopes: string[]): string[] {
  if (!scopes || !Array.isArray(scopes)) return [];

  // Normalize each scope and remove duplicates
  const normalized = scopes.map(normalizePermissionScope);
  return [...new Set(normalized)];
}

function getPackageVersion(): string {
  try {
    const entryPath = process.argv[1] ? path.dirname(process.argv[1]) : process.cwd();
    const candidates = [
      path.join(entryPath, '..', 'package.json'),
      path.join(process.cwd(), 'packages', 'dcp-vault', 'package.json'),
      path.join(process.cwd(), 'package.json'),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        const raw = fs.readFileSync(p, 'utf8');
        const json = JSON.parse(raw) as { version?: string };
        if (json.version) return json.version;
      }
    }
    return '0.0.0';
  } catch {
    return '0.0.0';
  }
}

// ============================================================================
// Server Setup
// ============================================================================

let storage: VaultStorage;
let budget: BudgetEngine;
let relayClient: RelayClient | null = null;
let relayConnected = false;

// Pending VPS pairing claims from relay (awaiting user approval in Desktop)
const pendingPairingClaims: Map<string, StoredPairingClaim> = new Map();

// Track which consents have been notified to avoid duplicates
// This enables Telegram notifications for ALL MCP clients (Claude, Cursor, etc.)
const notifiedConsentIds: Set<string> = new Set();
const CONSENT_POLL_INTERVAL_MS = 1500; // Poll every 1.5 seconds
const REMOTE_APPROVAL_POLL_INTERVAL_MS = parseInt(
  process.env.DCP_TELEGRAM_APPROVAL_POLL_MS || '5000',
  10
);

interface RemoteApprovalCommand {
  id: string;
  consent_id: string;
  action: 'approve' | 'deny';
  created_at: string;
}

function findActiveSessionForScope(agentName: string, scope: string): string | undefined {
  const sessions = storage.listActiveSessionsForAgent(agentName);
  for (const session of sessions) {
    if (session.granted_scopes.includes(scope)) {
      return session.id;
    }
    for (const granted of session.granted_scopes) {
      if (granted.endsWith('.*')) {
        const prefix = granted.slice(0, -2);
        if (scope.startsWith(prefix + '.')) {
          return session.id;
        }
      }
    }
  }
  return undefined;
}

function scopeMatches(pattern: string, scope: string): boolean {
  if (pattern === scope) return true;
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2);
    return scope.startsWith(prefix + '.');
  }
  return false;
}

function isWriteAllowed(agentName: string, scope: string): boolean {
  const config = budget.getConfig();
  const permissions = config.write_permissions || {};
  const allowed = permissions[agentName];
  if (!allowed || allowed.length === 0) {
    return false;
  }
  return allowed.some((pattern) => scopeMatches(pattern, scope));
}

function inferItemType(scope: string): ItemType {
  if (scope.startsWith('identity.')) return 'IDENTITY';
  if (scope.startsWith('address.')) return 'ADDRESS';
  if (scope.startsWith('preferences.')) return 'PREFERENCES';
  if (scope.startsWith('crypto.')) return 'WALLET_KEY';
  if (scope.startsWith('credentials.')) return 'CREDENTIALS';
  if (scope.startsWith('health.')) return 'HEALTH';
  if (scope.startsWith('budget.')) return 'BUDGET';
  return 'PREFERENCES';
}

function inferSensitivity(scope: string): SensitivityLevel {
  if (
    scope.startsWith('identity.passport') ||
    scope.startsWith('identity.drivers_license') ||
    scope.startsWith('crypto.')
  ) {
    return 'critical';
  }
  if (scope.startsWith('credentials.')) {
    return 'sensitive';
  }
  if (scope.startsWith('identity.') || scope.startsWith('address.') || scope.startsWith('health.')) {
    return 'sensitive';
  }
  return 'standard';
}

function ensureSchemaVersion(data: Record<string, unknown>): Record<string, unknown> {
  if ('schema_version' in data) {
    return data;
  }
  return { ...data, schema_version: '1.0' };
}

function normalizeWriteData(scope: string, data: Record<string, unknown>): Record<string, unknown> {
  const base = ensureSchemaVersion(data);
  if (scope.startsWith('credentials.api.')) {
    return validateAndNormalizeCredentialsApi(base);
  }
  return base;
}

function validateAndNormalizeCredentialsApi(data: Record<string, unknown>): Record<string, unknown> {
  const allowedKeys = [
    'schema_version',
    'label',
    'service',
    'key',
    'base_url',
    'auth_type',
    'headers',
  ];

  for (const key of Object.keys(data)) {
    if (!allowedKeys.includes(key)) {
      throw new VaultError('INVALID_SCHEMA', `Unexpected field in credentials.api: ${key}`);
    }
  }

  const normalized: Record<string, unknown> = {
    schema_version: String(data.schema_version || '1.0'),
    label: data.label ?? null,
    service: data.service ?? null,
    key: data.key ?? null,
    base_url: data.base_url ?? null,
    auth_type: data.auth_type ?? null,
    headers: data.headers ?? null,
  };

  if (typeof normalized.schema_version !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'schema_version must be a string');
  }
  if (normalized.label !== null && typeof normalized.label !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'label must be a string or null');
  }
  if (normalized.service !== null && typeof normalized.service !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'service must be a string or null');
  }
  if (normalized.key !== null && typeof normalized.key !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'key must be a string or null');
  }
  if (normalized.base_url !== null && typeof normalized.base_url !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'base_url must be a string or null');
  }
  if (normalized.auth_type !== null && typeof normalized.auth_type !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'auth_type must be a string or null');
  }
  if (
    normalized.headers !== null &&
    (typeof normalized.headers !== 'object' || Array.isArray(normalized.headers))
  ) {
    throw new VaultError('INVALID_SCHEMA', 'headers must be an object or null');
  }

  return normalized;
}

function normalizeAmount(amount?: string | number): number | undefined {
  if (amount === undefined || amount === null) return undefined;
  if (typeof amount === 'number') return amount;
  if (typeof amount === 'string' && amount.trim().length > 0) {
    const parsed = Number(amount);
    if (!Number.isFinite(parsed)) {
      throw new VaultError('INTERNAL_ERROR', 'Invalid amount');
    }
    return parsed;
  }
  return undefined;
}

// ============================================================================
// Telegram Notification Helpers (Option B: Cloud Service)
// ============================================================================

// Cloud webhook URL - desktop calls this, cloud service sends to Telegram
const TELEGRAM_CLOUD_URL = process.env.DCP_TELEGRAM_CLOUD_URL || 'https://telegram.dcp.1ly.store';

/**
 * Categorize a request based on action and scope
 */
function categorizeTelegramRequest(action: string, scope: string): TelegramRequestCategory {
  if (action === 'sign_tx' || scope.startsWith('crypto.wallet')) {
    return 'transaction_signing';
  }
  if (action === 'sign_message') {
    return 'message_signing';
  }
  if (action === 'read') {
    return 'data_read';
  }
  if (action === 'write') {
    return 'data_write';
  }
  if (scope.startsWith('credentials.')) {
    return 'credential_access';
  }
  return 'other';
}

/**
 * Get the vault ID for this instance (consistent hash of vault directory)
 */
function getApprovalBaseUrl(): string {
  const port = process.env.VAULT_PORT || String(DEFAULT_PORT);
  return `http://127.0.0.1:${port}`;
}

/**
 * Dispatch a Telegram notification via cloud service (Option B from the protocol spec).
 * Desktop calls cloud webhook, cloud service sends to user's Telegram.
 * Bot token is stored in cloud, not on each user's desktop.
 */
async function dispatchTelegramNotification(consent: {
  id: string;
  agent_name: string;
  action: string;
  scope: string;
  created_at?: string;
  expires_at: string;
  details?: string;
}): Promise<void> {
  console.log('[TG] dispatchTelegramNotification called for consent:', consent.id);
  try {
    // Check if Telegram is enabled (just needs to be paired, no local bot token needed)
    const telegramConfig = storage.getTelegramConfig();
    if (!telegramConfig || !telegramConfig.enabled) {
      console.log('[TG] Skipping - not enabled');
      return;
    }
    if (!telegramConfig.notify_consent) {
      console.log('[TG] Skipping - consent notifications disabled');
      return;
    }

    // Get vault identity for signing (protocol spec)
    const identity = await ensureRelayIdentity();
    const vaultId = identity.vaultId;
    console.log('[TG] vault_id:', vaultId);

    // Generate unique nonce for replay protection (protocol spec)
    const nonce = crypto.randomBytes(16).toString('base64');

    // Build webhook payload (cloud service will look up chat_id from vault_id)
    // protocol spec: Every desktop-to-Telegram request must include:
    // vault ID, timestamp, nonce, signature
    const category = categorizeTelegramRequest(consent.action, consent.scope);

    // Extract amount/currency/chain from consent.details for transaction context
    let amount: number | undefined;
    let currency: string | undefined;
    let chain: string | undefined;
    if (consent.details) {
      try {
        const details = typeof consent.details === 'string'
          ? JSON.parse(consent.details)
          : consent.details;
        amount = typeof details.amount === 'number' ? details.amount : undefined;
        currency = typeof details.currency === 'string' ? details.currency : undefined;
        chain = typeof details.chain === 'string' ? details.chain : undefined;
      } catch {
        // Ignore JSON parse errors
      }
    }

    const payloadWithoutSig = {
      vault_id: vaultId,
      event: 'consent_created' as const,
      data: {
        consent_id: consent.id,
        agent_name: consent.agent_name,
        category,
        scope: consent.scope, // Include scope for better context (e.g., "identity.email", "sign:solana")
        created_at: consent.created_at || new Date().toISOString(),
        expires_at: consent.expires_at,
        review_link: `${getApprovalBaseUrl()}/consent/${consent.id}`,
        // Include transaction context for informed consent decisions
        ...(amount !== undefined && { amount }),
        ...(currency && { currency }),
        ...(chain && { chain }),
      },
      timestamp: new Date().toISOString(),
      nonce,
    };

    // Sign the payload with vault's Ed25519 key (protocol spec)
    const message = Buffer.from(canonicalJson(payloadWithoutSig), 'utf8');
    const signatureBytes = nacl.sign.detached(
      new Uint8Array(message),
      new Uint8Array(identity.signingKeyPair.privateKey)
    );
    const signature = Buffer.from(signatureBytes).toString('base64');

    const payload = {
      ...payloadWithoutSig,
      signature,
    };

    // Call cloud webhook
    const webhookUrl = `${TELEGRAM_CLOUD_URL}/webhook/consent`;
    console.log('[TG] Calling cloud webhook:', webhookUrl);

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const result = await response.json() as { sent?: boolean; error?: string; reason?: string };
    console.log('[TG] Cloud response:', response.status, result);

    if (response.ok && result.sent) {
      storage.recordTelegramNotification();
      storage.logTelegramNotification({
        consent_id: consent.id,
        chat_id: telegramConfig.chat_id || 'cloud',
        notification_type: 'consent_request',
      });
      console.log('[TG] Notification sent via cloud');
    } else if (response.status === 404) {
      console.log('[TG] Vault not paired with cloud Telegram service');
    } else {
      console.log('[TG] Cloud error:', result.error || result.reason);
    }
  } catch (err) {
    console.log('[TG] Exception:', err);
  }
}

/**
 * Send a budget exceeded notification to Telegram.
 * This notifies the admin when daily/tx budget is exceeded so they can
 * manually increase limits in the Desktop app if needed.
 */
async function dispatchBudgetExceededNotification(params: {
  agent_name: string;
  amount: number;
  currency: string;
  chain: string;
  error_code: 'BUDGET_EXCEEDED_TX' | 'BUDGET_EXCEEDED_DAILY';
  remaining_daily: number;
  remaining_tx: number;
  limit_daily: number;
  limit_tx: number;
}): Promise<void> {
  console.log('[TG] dispatchBudgetExceededNotification called:', params.error_code);
  try {
    // Check if Telegram is enabled
    const telegramConfig = storage.getTelegramConfig();
    if (!telegramConfig || !telegramConfig.enabled) {
      console.log('[TG] Skipping budget notification - not enabled');
      return;
    }

    // Get vault identity for signing
    const identity = await ensureRelayIdentity();
    const vaultId = identity.vaultId;

    // Ensure vault key is registered with telegram service (survives telegram restarts)
    const publicKeyBase64 = identity.signingKeyPair.publicKey.toString('base64');
    try {
      await fetch(`${TELEGRAM_CLOUD_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vault_id: vaultId, public_key: publicKeyBase64 }),
      });
    } catch {
      // Ignore registration errors - telegram service might be down
    }

    // Generate unique nonce for replay protection
    const nonce = crypto.randomBytes(16).toString('base64');

    // Build webhook payload
    const payloadWithoutSig = {
      vault_id: vaultId,
      event: 'budget_exceeded' as const,
      data: {
        agent_name: params.agent_name,
        amount: params.amount,
        currency: params.currency,
        chain: params.chain,
        error_code: params.error_code,
        remaining_daily: params.remaining_daily,
        remaining_tx: params.remaining_tx,
        limit_daily: params.limit_daily,
        limit_tx: params.limit_tx,
        message: params.error_code === 'BUDGET_EXCEEDED_DAILY'
          ? `Daily budget exceeded! Agent "${params.agent_name}" tried to spend ${params.amount} ${params.currency} but daily limit is ${params.limit_daily} ${params.currency}. Open Desktop app to increase limits.`
          : `Transaction limit exceeded! Agent "${params.agent_name}" tried to spend ${params.amount} ${params.currency} but per-tx limit is ${params.limit_tx} ${params.currency}. Open Desktop app to increase limits.`,
      },
      timestamp: new Date().toISOString(),
      nonce,
    };

    // Sign the payload with vault's Ed25519 key
    const message = Buffer.from(canonicalJson(payloadWithoutSig), 'utf8');
    const signatureBytes = nacl.sign.detached(
      new Uint8Array(message),
      new Uint8Array(identity.signingKeyPair.privateKey)
    );
    const signature = Buffer.from(signatureBytes).toString('base64');

    const payload = {
      ...payloadWithoutSig,
      signature,
    };

    // Call cloud webhook
    const webhookUrl = `${TELEGRAM_CLOUD_URL}/webhook/budget`;
    console.log('[TG] Calling budget webhook:', webhookUrl);

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const result = await response.json() as { sent?: boolean; error?: string; reason?: string };
    console.log('[TG] Budget notification response:', response.status, result);

    if (response.ok && result.sent) {
      storage.logTelegramNotification({
        consent_id: `budget_${Date.now()}`,
        chat_id: telegramConfig.chat_id || 'cloud',
        notification_type: 'budget_alert',
      });
      console.log('[TG] Budget exceeded notification sent via cloud');
    } else if (response.status === 404) {
      console.log('[TG] Vault not paired with cloud Telegram service');
    } else {
      console.log('[TG] Cloud error:', result.error || result.reason);
    }
  } catch (err) {
    console.log('[TG] Budget notification exception:', err);
  }
}

/**
 * Start polling for new pending consents and send Telegram notifications.
 * This enables Telegram notifications for ALL consent sources (MCP, relay, etc.)
 * without duplicating code in each client.
 */
function startConsentWatcher(): void {
  console.log('[TG-WATCHER] Starting consent watcher...');

  const poll = () => {
    try {
      // Get all pending consents
      const pendingConsents = storage.getPendingConsents();

      for (const consent of pendingConsents) {
        // Skip if already notified
        if (notifiedConsentIds.has(consent.id)) {
          continue;
        }

        // Mark as notified immediately to prevent duplicates
        notifiedConsentIds.add(consent.id);

        // Only notify for pending status (not already approved/denied)
        if (consent.status === 'pending') {
          console.log('[TG-WATCHER] New consent detected:', consent.id);
          dispatchTelegramNotification({
            id: consent.id,
            agent_name: consent.agent_name,
            action: consent.action,
            scope: consent.scope,
            created_at: consent.created_at,
            expires_at: consent.expires_at,
            details: consent.details,
          }).catch((err) => {
            console.log('[TG-WATCHER] Notification error:', err);
          });
        }
      }

      // Cleanup: remove old consent IDs that are no longer pending (memory management)
      const pendingIds = new Set(pendingConsents.map(c => c.id));
      for (const id of notifiedConsentIds) {
        if (!pendingIds.has(id)) {
          notifiedConsentIds.delete(id);
        }
      }
    } catch (err) {
      console.log('[TG-WATCHER] Poll error:', err);
    }

    // Schedule next poll
    setTimeout(poll, CONSENT_POLL_INTERVAL_MS);
  };

  // Start polling
  poll();
}

function processRemoteApprovalCommand(command: RemoteApprovalCommand): string {
  const consent = storage.getPendingConsent(command.consent_id);

  if (!consent) {
    return 'consent not found';
  }

  if (consent.status !== 'pending') {
    return `consent already ${consent.status}`;
  }

  if (new Date(consent.expires_at) < new Date()) {
    storage.resolveConsent(consent.id, 'expired');
    return 'consent expired';
  }

  if (command.action === 'approve') {
    // Create a 5-minute session (same as desktop "Approve Once")
    // This allows the agent's retry to succeed without new consent
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    const session = storage.createSession(
      consent.agent_name,
      [consent.scope],
      'once',
      expiresAt
    );

    storage.resolveConsent(consent.id, 'approved', session.id);
    storage.logAudit('GRANT', 'success', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: 'telegram_remote_grant',
      details: JSON.stringify({ command_id: command.id, consent_mode: 'once', session_id: session.id }),
    });
    return 'success';
  }

  if (command.action === 'deny') {
    storage.resolveConsent(consent.id, 'denied');
    storage.logAudit('DENY', 'denied', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: consent.action,
      details: JSON.stringify({ command_id: command.id, source: 'telegram_remote' }),
    });
    return 'success';
  }

  return `unknown action: ${command.action}`;
}

async function acknowledgeRemoteApproval(commandId: string, result: string): Promise<void> {
  const response = await fetch(`${TELEGRAM_CLOUD_URL}/api/approvals/processed`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command_id: commandId, result }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Failed to acknowledge remote approval: ${response.status} ${body}`);
  }
}

async function pollRemoteApprovals(): Promise<void> {
  const telegramConfig = storage.getTelegramConfig();
  if (!telegramConfig || !telegramConfig.enabled || !telegramConfig.notify_consent) {
    return;
  }

  const identity = await ensureRelayIdentity();
  const vaultId = identity.vaultId;
  const response = await fetch(`${TELEGRAM_CLOUD_URL}/api/approvals/${vaultId}`);

  if (response.status === 404 || response.status === 403) {
    return;
  }

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Failed to fetch remote approvals: ${response.status} ${body}`);
  }

  const payload = await response.json() as { commands?: RemoteApprovalCommand[] };
  const commands = payload.commands || [];

  for (const command of commands) {
    let result = 'success';
    try {
      result = processRemoteApprovalCommand(command);
    } catch (err) {
      result = err instanceof Error ? err.message : 'unknown processing error';
    }

    try {
      await acknowledgeRemoteApproval(command.id, result);
    } catch (err) {
      console.log('[TG-APPROVAL] Ack error:', err);
    }
  }
}

function startRemoteApprovalWatcher(): void {
  console.log('[TG-APPROVAL] Starting remote approval watcher...');

  const poll = async () => {
    try {
      await pollRemoteApprovals();
    } catch (err) {
      console.log('[TG-APPROVAL] Poll error:', err);
    } finally {
      setTimeout(poll, REMOTE_APPROVAL_POLL_INTERVAL_MS);
    }
  };

  poll();
}

// ============================================================================
// Desktop Owner Trust Model Helpers
// ============================================================================

/**
 * Verify Ed25519 signature
 */
function verifyEd25519Signature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return nacl.sign.detached.verify(message, signature, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate a random nonce for challenge-response
 */
function generateChallenge(): string {
  return crypto.randomBytes(32).toString('base64');
}

/**
 * Generate a secure owner token
 */
function generateOwnerToken(): string {
  return crypto.randomBytes(48).toString('base64url');
}

/**
 * Check if request has valid owner token
 * Returns true if the request should bypass consent (owner mode)
 */
function isOwnerRequest(request: FastifyRequest): boolean {
  const token = request.headers['x-dcp-owner-token'] as string | undefined;
  if (!token) return false;

  const ownerToken = ownerTokens.get(token);
  if (!ownerToken) return false;

  const now = Date.now();

  // Check if token is expired (max age)
  if (now - ownerToken.created_at > OWNER_TOKEN_MAX_AGE_MS) {
    ownerTokens.delete(token);
    return false;
  }

  // Check if token is idle expired
  if (now - ownerToken.last_used_at > OWNER_TOKEN_IDLE_TIMEOUT_MS) {
    ownerTokens.delete(token);
    return false;
  }

  // Update last used time
  ownerToken.last_used_at = now;
  return true;
}

/**
 * Require valid owner token or throw error
 */
function requireOwnerToken(request: FastifyRequest): void {
  if (!isOwnerRequest(request)) {
    throw new VaultError('UNAUTHORIZED' as VaultErrorCode, 'Valid owner token required');
  }
}

/**
 * Clean up expired tokens and challenges
 */
function cleanupOwnerState(): void {
  const now = Date.now();

  // Clean up expired tokens
  for (const [token, data] of ownerTokens.entries()) {
    if (
      now - data.created_at > OWNER_TOKEN_MAX_AGE_MS ||
      now - data.last_used_at > OWNER_TOKEN_IDLE_TIMEOUT_MS
    ) {
      ownerTokens.delete(token);
    }
  }

  // Clean up expired challenges
  for (const [desktopId, challenge] of pendingChallenges.entries()) {
    if (now > challenge.expires_at) {
      pendingChallenges.delete(desktopId);
    }
  }
}

async function buildServer(): Promise<FastifyInstance> {
  // Use pino-pretty only in development, plain JSON in production/bundled
  const isDev = process.env.NODE_ENV !== 'production' && !process.env.DCP_BUNDLED;
  const loggerConfig = isDev
    ? {
        level: 'info',
        transport: {
          target: 'pino-pretty',
          options: {
            translateTime: 'HH:MM:ss',
            ignore: 'pid,hostname',
          },
        },
      }
    : { level: 'info' };

  const server = Fastify({
    logger: loggerConfig,
  });

  // CORS for desktop UI access (restrict to trusted origins)
  const allowedOrigins = new Set([
    'tauri://localhost',
    'https://tauri.localhost',
    'http://localhost:1420',
    'http://127.0.0.1:1420',
  ]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await server.register(cors as any, {
    origin: (origin: string | undefined, cb: (err: Error | null, allow: boolean) => void) => {
      if (!origin) return cb(null, true); // non-browser clients
      if (allowedOrigins.has(origin)) return cb(null, true);
      try {
        const url = new URL(origin);
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
          return cb(null, true);
        }
      } catch {
        // fall through
      }
      return cb(new Error('Not allowed by CORS'), false);
    },
    methods: ['GET', 'POST', 'DELETE', 'PATCH'],
  });

  // Initialize vault storage (respects VAULT_DIR env for testing)
  const vaultDir = process.env.VAULT_DIR;
  storage = getStorage(vaultDir);
  storage.initializeSchema();
  budget = getBudgetEngine(storage, vaultDir);

  // NOTE: Vault is locked by default. Use /v1/vault/unlock to open for this process.

  // Error handler
  server.setErrorHandler((error: Error, request, reply) => {
    if (error instanceof VaultError) {
      reply.status(400).send(error.toJSON());
    } else {
      server.log.error(error);
      reply.status(500).send({
        error: {
          code: 'INTERNAL_ERROR',
          message: error.message,
        },
      });
    }
  });

  // ============================================================================
  // Health Check
  // ============================================================================

  server.get('/health', async () => {
    const initialized = await storage.isProvisioned();
    return {
      status: 'ok',
      initialized,
      unlocked: storage.isUnlocked(),
      version: PACKAGE_VERSION,
    };
  });

  // ============================================================================
  // Local Approval UI
  // ============================================================================

  server.get('/', async (_request, reply) => {
    reply
      .header('Cache-Control', 'no-store')
      .type('text/html')
      .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DCP Vault Approval</title>
    <style>
      :root {
        --bg: #0b0f14;
        --bg-2: #0e131a;
        --panel: #111821;
        --panel-2: #0f1620;
        --text: #e6edf3;
        --muted: #9aa4b2;
        --accent: #8bd3ff;
        --danger: #ff6b6b;
        --ok: #2dd4bf;
        --border: #1f2a37;
      }
      [data-theme="light"] {
        --bg: #f5f7fb;
        --bg-2: #ffffff;
        --panel: #ffffff;
        --panel-2: #f3f5f8;
        --text: #0b0f14;
        --muted: #667085;
        --accent: #2563eb;
        --danger: #dc2626;
        --ok: #059669;
        --border: #e4e7ec;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        background: radial-gradient(1200px 600px at 10% -10%, #18202b, transparent),
          radial-gradient(1200px 600px at 90% -10%, #101720, transparent),
          var(--bg);
        color: var(--text);
      }
      [data-theme="light"] body {
        background: radial-gradient(1200px 600px at 10% -10%, #e9efff, transparent),
          radial-gradient(1200px 600px at 90% -10%, #eef2f7, transparent),
          var(--bg);
      }
      .wrap {
        max-width: 900px;
        margin: 40px auto;
        padding: 0 20px;
      }
      .card {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
      }
      [data-theme="light"] .card {
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
      }
      .row { display: flex; gap: 12px; align-items: center; }
      .row.space { justify-content: space-between; }
      .title { font-size: 20px; font-weight: 700; }
      .subtitle { font-size: 13px; color: var(--muted); }
      .muted { color: var(--muted); }
      .badge {
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 12px;
        border: 1px solid var(--border);
        color: var(--muted);
      }
      .btn {
        padding: 8px 12px;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--panel-2);
        color: var(--text);
        cursor: pointer;
      }
      .btn:hover { border-color: #2c3b4c; }
      [data-theme="light"] .btn:hover { border-color: #cbd5e1; }
      .btn.ok { border-color: #1f766e; color: #bbf7d0; }
      .btn.danger { border-color: #7f1d1d; color: #fecaca; }
      .input {
        width: 100%;
        padding: 8px 10px;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--panel-2);
        color: var(--text);
      }
      .input.compact { width: 220px; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      .consent {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 12px;
        background: var(--panel-2);
      }
      .actions { display: flex; gap: 8px; }
      .small { font-size: 12px; }
      .pill {
        display: inline-flex;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 11px;
        border: 1px solid var(--border);
        color: var(--muted);
      }
      .lock-screen {
        display: none;
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
      }
      .lock-screen.active { display: block; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <div class="row space">
          <div>
            <div class="title">DCP Vault Approval</div>
            <div class="subtitle">Local only — http://127.0.0.1:8420</div>
          </div>
          <div class="row" style="gap:8px;">
            <button class="btn" id="theme-btn">Toggle Theme</button>
            <div class="badge" id="status-badge">checking...</div>
          </div>
        </div>
        <div class="row space" style="margin-top: 8px;">
          <div class="pill" id="mcp-status">MCP: unknown</div>
          <div class="row" style="gap:8px;">
            <input id="passphrase-top" class="input compact" type="password" placeholder="Passphrase for MCP" />
            <button class="btn" id="unlock-mcp-btn-top">Unlock MCP</button>
            <div class="muted small" id="mcp-msg"></div>
          </div>
        </div>
      </div>

      <div class="card" id="unlock-card">
        <div class="row space">
          <div>
            <div class="title">Unlock Vault</div>
            <div class="subtitle">Required once per server process. Passphrase never leaves your machine.</div>
          </div>
        </div>
        <div class="row" style="margin-top: 12px;">
          <input id="passphrase" class="input" type="password" placeholder="Passphrase" />
          <button class="btn ok" id="unlock-btn">Unlock</button>
        </div>
        <div class="muted small" id="unlock-msg" style="margin-top: 8px;"></div>
      </div>

      <div class="lock-screen" id="lock-screen">
        <div class="row space">
          <div>
            <div class="title">Vault Locked</div>
            <div class="subtitle">Unlock to view or approve requests.</div>
          </div>
          <div class="badge">locked</div>
        </div>
      </div>

      <div class="card" id="requests-card">
        <div class="row space">
          <div>
            <div class="title">Pending Requests</div>
            <div class="subtitle">Approve or deny agent requests. Auto-refreshes every 5s.</div>
          </div>
          <button class="btn" id="refresh-btn">Refresh</button>
        </div>
        <div id="consents" style="margin-top: 12px;"></div>
        <div class="muted small" id="empty-msg" style="margin-top: 8px;"></div>
      </div>
    </div>

    <script>
      async function fetchJSON(url, options) {
        const res = await fetch(url, options);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw data;
        return data;
      }

      async function refreshStatus() {
        const status = await fetchJSON('/health');
        const badge = document.getElementById('status-badge');
        const mcpBadge = document.getElementById('mcp-status');
        const unlockCard = document.getElementById('unlock-card');
        const lockScreen = document.getElementById('lock-screen');
        const requestsCard = document.getElementById('requests-card');
        if (status.unlocked) {
          badge.textContent = 'unlocked';
          badge.style.color = '#bbf7d0';
          unlockCard.style.display = 'none';
          lockScreen.classList.remove('active');
          requestsCard.style.display = 'block';
        } else {
          badge.textContent = 'locked';
          badge.style.color = '#fecaca';
          unlockCard.style.display = 'block';
          lockScreen.classList.add('active');
          requestsCard.style.display = 'none';
        }

        try {
          const mcp = await fetchJSON('/v1/vault/mcp-status');
          if (mcp.running) {
            mcpBadge.textContent = mcp.unlocked ? 'MCP: unlocked' : 'MCP: locked';
          } else {
            mcpBadge.textContent = 'MCP: not running';
          }
        } catch {
          mcpBadge.textContent = 'MCP: unknown';
        }
      }

      async function unlockVault() {
        const passphrase = document.getElementById('passphrase').value;
        const msg = document.getElementById('unlock-msg');
        msg.textContent = '';
        try {
          await fetchJSON('/v1/vault/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase }),
          });
          msg.textContent = 'Unlocked.';
          await refreshStatus();
        } catch (err) {
          msg.textContent = err?.error?.message || 'Failed to unlock';
        }
      }

      async function unlockMcp() {
        const passTop = document.getElementById('passphrase-top').value;
        const passMain = document.getElementById('passphrase').value;
        const passphrase = passTop || passMain;
        const msg = document.getElementById('mcp-msg');
        msg.textContent = '';
        if (!passphrase) {
          msg.textContent = 'Passphrase required.';
          return;
        }
        try {
          await fetchJSON('/v1/vault/unlock-mcp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase }),
          });
          msg.textContent = 'MCP unlock queued.';
        } catch (err) {
          msg.textContent = err?.error?.message || 'Failed to unlock MCP';
        }
      }

      async function loadConsents() {
        const container = document.getElementById('consents');
        const emptyMsg = document.getElementById('empty-msg');
        container.innerHTML = '';
        emptyMsg.textContent = '';
        const res = await fetchJSON('/consent');
        const pending = res.pending || [];
        if (pending.length === 0) {
          emptyMsg.textContent = 'No pending requests.';
          return;
        }

        for (const c of pending) {
          const el = document.createElement('div');
          el.className = 'consent';
          const details = c.details || {};
          const amount = details.amount && details.currency ? \`\${details.amount} \${details.currency}\` : null;
          const note = details.description ? details.description : '';
          const chain = details.chain ? details.chain : null;
          const recipient = details.recipient ? details.recipient : null;
          const purpose = details.purpose ? details.purpose : null;
          const network = details.network ? details.network : null;
          el.innerHTML = \`
            <div class="row space">
              <div><strong>\${c.agent_name || 'Agent'}</strong> wants <strong>\${c.action}</strong></div>
              <div class="small muted">\${c.id}</div>
            </div>
            <div class="small muted" style="margin-top: 6px;">
              Scope: \${c.scope || '-'} • Expires: \${new Date(c.expires_at).toLocaleTimeString()}
            </div>
            <div class="small muted" style="margin-top: 6px;">
              \${amount ? '<span class="pill">Amount</span> ' + amount : ''}
              \${chain ? ' <span class="pill">Chain</span> ' + chain : ''}
              \${network ? ' <span class="pill">Network</span> ' + network : ''}
            </div>
            \${recipient ? '<div class="small muted" style="margin-top: 6px;">Recipient: ' + recipient + '</div>' : ''}
            \${purpose ? '<div class="small muted" style="margin-top: 6px;">Purpose: ' + purpose + '</div>' : ''}
            \${note ? '<div class="small muted" style="margin-top: 6px;">Note: ' + note + '</div>' : ''}
            <div class="actions" style="margin-top: 10px;">
              <button class="btn ok" data-id="\${c.id}" data-mode="once">Approve once</button>
              <button class="btn" data-id="\${c.id}" data-mode="session">Session</button>
              <button class="btn danger" data-id="\${c.id}" data-mode="deny">Deny</button>
            </div>
          \`;
          container.appendChild(el);
        }
      }

      async function handleAction(e) {
        const btn = e.target.closest('button');
        if (!btn) return;
        const id = btn.getAttribute('data-id');
        const mode = btn.getAttribute('data-mode');
        if (!id || !mode) return;

        if (mode === 'deny') {
          await fetchJSON(\`/consent/\${id}/deny\`, { method: 'POST' });
        } else {
          await fetchJSON(\`/consent/\${id}/approve\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: mode === 'session' }),
          });
        }
        await loadConsents();
      }

      document.getElementById('unlock-btn').addEventListener('click', unlockVault);
      document.getElementById('unlock-mcp-btn-top').addEventListener('click', unlockMcp);
      document.getElementById('refresh-btn').addEventListener('click', loadConsents);
      document.getElementById('consents').addEventListener('click', handleAction);
      document.getElementById('theme-btn').addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('dcp-theme', next);
      });

      const savedTheme = localStorage.getItem('dcp-theme');
      if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
      }

      refreshStatus().then(loadConsents);
      setInterval(loadConsents, 5000);
    </script>
  </body>
</html>`);
  });

  // ============================================================================
  // Vault Unlock (local only)
  // ============================================================================

  server.post('/v1/vault/unlock', async (request, reply) => {
    const rateLimitKey = getUnlockRateLimitKey(request);

    // Check rate limit before processing
    const rateCheck = checkUnlockRateLimit(rateLimitKey);
    if (!rateCheck.allowed) {
      reply.code(429);
      return {
        error: {
          code: 'RATE_LIMITED',
          message: `Too many failed unlock attempts. Try again in ${rateCheck.retry_after_seconds} seconds.`,
          retry_after_seconds: rateCheck.retry_after_seconds,
        },
      };
    }

    const body = request.body as { passphrase?: string };

    if (!body || typeof body.passphrase !== 'string' || body.passphrase.length === 0) {
      throw new VaultError('INTERNAL_ERROR', 'passphrase is required');
    }

    try {
      await storage.unlock(body.passphrase);

      // Success - clear any rate limit tracking
      clearUnlockRateLimit(rateLimitKey);

      // Start relay client if not already connected (e.g., first unlock after init)
      if (!relayConnected && (await storage.isProvisioned())) {
        startRelayClient(server).catch((err) => {
          server.log.error(err, 'Relay client failed to start after unlock');
        });
      }

      return { unlocked: true };
    } catch (err) {
      if (err instanceof VaultError && err.message.includes('Wrong passphrase')) {
        // Record failed attempt and check if we should lock out
        const lockResult = recordUnlockFailure(rateLimitKey);
        if (lockResult.locked) {
          reply.code(429);
          return {
            error: {
              code: 'RATE_LIMITED',
              message: `Too many failed unlock attempts. Account locked for ${lockResult.retry_after_seconds} seconds.`,
              retry_after_seconds: lockResult.retry_after_seconds,
            },
          };
        }
        throw new VaultError('INTERNAL_ERROR', 'Wrong passphrase');
      }
      throw err;
    }
  });

  // ============================================================================
  // MCP Unlock Bridge (local only)
  // ============================================================================

  server.post('/v1/vault/unlock-mcp', async (request) => {
    const body = request.body as { passphrase?: string };
    if (!body || typeof body.passphrase !== 'string' || body.passphrase.length === 0) {
      throw new VaultError('INTERNAL_ERROR', 'passphrase is required');
    }

    // Store passphrase + expiry in OS keychain for MCP to retrieve (no disk writes)
    try {
      const expiresAt = new Date(Date.now() + MCP_UNLOCK_SESSION_MINUTES * 60 * 1000).toISOString();
      await keytar.setPassword(
        MCP_UNLOCK_KEYCHAIN_SERVICE,
        MCP_UNLOCK_KEYCHAIN_ACCOUNT,
        body.passphrase
      );
      await keytar.setPassword(
        MCP_UNLOCK_KEYCHAIN_SERVICE,
        MCP_UNLOCK_META_ACCOUNT,
        JSON.stringify({ expires_at: expiresAt })
      );
    } catch {
      throw new VaultError(
        'INTERNAL_ERROR',
        'Keychain unavailable. Use CLI unlock or vault_unlock instead.'
      );
    }

    // Write a one-time signal file for MCP to pick up (no secrets)
    const dir = vaultDir || path.join(os.homedir(), '.dcp');
    const unlockPath = path.join(dir, 'mcp.unlock');
    const payload = JSON.stringify({ created_at: new Date().toISOString() });
    fs.writeFileSync(unlockPath, payload, { mode: 0o600 });

    return { queued: true };
  });

  // ============================================================================
  // MCP Status (local only)
  // ============================================================================

  server.get('/v1/vault/mcp-status', async () => {
    try {
      const dir = vaultDir || path.join(os.homedir(), '.dcp');
      const statusPath = path.join(dir, 'mcp.status');
      if (!fs.existsSync(statusPath)) {
        return { running: false, unlocked: false };
      }
      const raw = fs.readFileSync(statusPath, 'utf8');
      const data = JSON.parse(raw) as { unlocked?: boolean; updated_at?: string; pid?: number };
      if (data.pid) {
        try {
          process.kill(data.pid, 0);
        } catch {
          return { running: false, unlocked: false };
        }
      }
      return {
        running: true,
        unlocked: Boolean(data.unlocked),
        updated_at: data.updated_at,
        pid: data.pid,
      };
    } catch {
      return { running: false, unlocked: false };
    }
  });

  // ============================================================================
  // Local MCP Agent Setup
  // ============================================================================

  /**
   * Setup local MCP agent for Claude Desktop / Cursor / VS Code / etc.
   *
   * This endpoint creates a pre-configured local MCP agent so users don't need
   * to manually pair. The agent is created with full local permissions and the
   * config is written directly to ~/.dcp/agents/.
   *
   * Supports multiple local agents (one per AI client type).
   */
  server.post<{
    Body: {
      agent_type?: 'claude-desktop' | 'cursor' | 'vscode' | 'openclaw' | 'other';
      custom_name?: string;
    };
  }>('/v1/vault/setup-local-mcp', async (request) => {
    // Owner token required for local MCP setup (protocol spec 3.1)
    requireOwnerToken(request);

    const body = request.body || {};
    const agentType = body.agent_type || 'claude-desktop';

    // Map agent type to ID and name
    const agentTypeMapping: Record<string, { id: string; name: string }> = {
      'claude-desktop': { id: 'agent_claude_desktop', name: 'Claude Desktop' },
      'cursor': { id: 'agent_cursor', name: 'Cursor' },
      'vscode': { id: 'agent_vscode', name: 'VS Code' },
      'openclaw': { id: 'agent_openclaw_local', name: 'OpenClaw' },
      'other': { id: 'agent_local_mcp', name: body.custom_name || 'Local MCP' },
    };

    const { id: LOCAL_MCP_AGENT_ID, name: LOCAL_MCP_AGENT_NAME } = agentTypeMapping[agentType] || agentTypeMapping['claude-desktop'];

    // Check if local MCP agent already exists and is paired
    const existingConnection = storage.getAgentConnection(LOCAL_MCP_AGENT_ID);
    if (existingConnection?.status === 'active') {
      // Check if config file exists AND public keys match
      const agentConfigDir = path.join(os.homedir(), '.dcp', 'agents');
      const configPath = path.join(agentConfigDir, `${LOCAL_MCP_AGENT_ID}.json`);
      if (fs.existsSync(configPath)) {
        try {
          const configData = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
          const configPublicKey = configData.service_keypair?.public;
          const storedPublicKey = existingConnection.service_public_key;

          // Only return "already configured" if public keys match
          if (configPublicKey && storedPublicKey && configPublicKey === storedPublicKey) {
            return {
              success: true,
              agent_id: LOCAL_MCP_AGENT_ID,
              agent_name: LOCAL_MCP_AGENT_NAME,
              already_configured: true,
              message: 'Local MCP agent already configured',
            };
          }
          // Keys don't match - fall through to regenerate
          console.log('[LOCAL_MCP] Public key mismatch, regenerating...');
        } catch {
          // Config file is corrupted - fall through to regenerate
          console.log('[LOCAL_MCP] Config file corrupted, regenerating...');
        }
      }
    }

    // Get vault identity
    const identity = await ensureRelayIdentity();

    // Request-only by default: local MCP can ask, but gets no automatic access.
    // Users can add explicit permissions later from Desktop/CLI policy controls.
    const permissionScopes: string[] = [];

    // Generate service keypair for the agent
    const keypair = generateSigningKeyPair();
    const servicePublicKey = keypair.publicKey.toString('base64');
    const servicePrivateKey = keypair.privateKey.toString('base64');

    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('base64url');
    const sessionTokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

    // Create or update agent connection in storage
    if (!existingConnection) {
      storage.createAgentConnection({
        agent_id: LOCAL_MCP_AGENT_ID,
        name: LOCAL_MCP_AGENT_NAME,
        mode: 'mcp' as AgentConnectionMode,
        permission_scopes: permissionScopes,
        budget: { daily: 0, currency: 'USD', auto_approve_under: 0 },
        tier: 'local' as AgentConnectionTier,
      });
    }

    // Mark as paired with service public key
    storage.markAgentPaired(LOCAL_MCP_AGENT_ID, sessionTokenHash, servicePublicKey);

    // Prepare agent config to write to ~/.dcp/agents/
    const agentConfig = {
      agent_id: LOCAL_MCP_AGENT_ID,
      agent_name: LOCAL_MCP_AGENT_NAME,
      vault_id: identity.vaultId,
      mode: 'mcp' as AgentConnectionMode,
      vault_hpke_public_key: identity.hpkeKeyPair.publicKey.toString('base64'),
      vault_signing_public_key: identity.signingKeyPair.publicKey.toString('base64'),
      permission_scopes: permissionScopes,
      budget: { daily: 0, currency: 'USD', auto_approve_under: 0 },
      tier: 'local',
      relay_url: identity.relayUrl || DEFAULT_RELAY_URL || CORE_DEFAULT_RELAY_URL,
      service_keypair: {
        public: servicePublicKey,
        private: servicePrivateKey,
      },
      session_token: sessionToken,
      paired_at: new Date().toISOString(),
    };

    // Write config file to ~/.dcp/agents/
    const agentConfigDir = path.join(os.homedir(), '.dcp', 'agents');
    if (!fs.existsSync(agentConfigDir)) {
      fs.mkdirSync(agentConfigDir, { recursive: true, mode: 0o700 });
    }
    const configPath = path.join(agentConfigDir, `${LOCAL_MCP_AGENT_ID}.json`);
    fs.writeFileSync(configPath, JSON.stringify(agentConfig, null, 2), { mode: 0o600 });

    // Log audit event
    storage.logAudit('CONFIG', 'success', {
      operation: 'local_mcp_setup',
      details: JSON.stringify({
        agent_id: LOCAL_MCP_AGENT_ID,
        agent_name: LOCAL_MCP_AGENT_NAME,
      }),
    });

    return {
      success: true,
      agent_id: LOCAL_MCP_AGENT_ID,
      agent_name: LOCAL_MCP_AGENT_NAME,
      already_configured: false,
      message: 'Local MCP agent configured successfully',
    };
  });

  /**
   * Check local MCP agent status - returns all configured local agents
   */
  server.get<{
    Querystring: { agent_type?: string };
  }>('/v1/vault/local-mcp-status', async (request) => {
    const agentType = request.query.agent_type;
    const agentConfigDir = path.join(os.homedir(), '.dcp', 'agents');

    // Known local agent IDs
    const knownLocalAgents = [
      'agent_claude_desktop',
      'agent_cursor',
      'agent_vscode',
      'agent_openclaw_local',
      'agent_local_mcp',
    ];

    // If specific agent type requested
    if (agentType) {
      const agentIdMap: Record<string, string> = {
        'claude-desktop': 'agent_claude_desktop',
        'cursor': 'agent_cursor',
        'vscode': 'agent_vscode',
        'openclaw': 'agent_openclaw_local',
        'other': 'agent_local_mcp',
      };
      const agentId = agentIdMap[agentType];
      if (agentId) {
        const configPath = path.join(agentConfigDir, `${agentId}.json`);
        const configExists = fs.existsSync(configPath);
        const connection = storage.getAgentConnection(agentId);
        const hasConnection = connection !== undefined;

        return {
          configured: configExists && hasConnection,
          config_exists: configExists,
          connection_status: connection?.status || 'none',
          agent_id: agentId,
        };
      }
    }

    // Return status of all local agents
    const localAgents: Array<{ agent_id: string; name: string; configured: boolean; status: string }> = [];

    // Check all config files in agents directory
    if (fs.existsSync(agentConfigDir)) {
      const files = fs.readdirSync(agentConfigDir);
      for (const file of files) {
        if (file.endsWith('.json')) {
          const agentId = file.replace('.json', '');
          const connection = storage.getAgentConnection(agentId);
          if (connection && connection.mode === 'mcp') {
            localAgents.push({
              agent_id: agentId,
              name: connection.name,
              configured: true,
              status: connection.status,
            });
          }
        }
      }
    }

    // For backward compatibility
    const hasAnyConfigured = localAgents.length > 0;
    const firstAgent = localAgents[0];

    return {
      configured: hasAnyConfigured,
      config_exists: hasAnyConfigured,
      connection_status: firstAgent?.status || 'none',
      agent_id: firstAgent?.agent_id || '',
      local_agents: localAgents,
    };
  });

  // ============================================================================
  // Desktop Owner Trust Model Endpoints
  // ============================================================================

  /**
   * Register desktop public key
   * POST /v1/desktop/register
   */
  server.post<{
    Body: {
      desktop_id: string;
      public_key: string; // base64 encoded Ed25519 public key
    };
  }>('/v1/desktop/register', async (request) => {
    const { desktop_id, public_key } = request.body;

    if (!desktop_id || !public_key) {
      throw new VaultError('INTERNAL_ERROR', 'desktop_id and public_key are required');
    }

    // Validate public key is valid base64 and correct length (32 bytes for Ed25519)
    try {
      const keyBytes = Buffer.from(public_key, 'base64');
      if (keyBytes.length !== 32) {
        throw new VaultError('INTERNAL_ERROR', 'Invalid public key length. Expected 32 bytes.');
      }
    } catch {
      throw new VaultError('INTERNAL_ERROR', 'Invalid public key format');
    }

    // Store in config
    budget.setConfig('desktop_owner', {
      desktop_id,
      public_key,
      registered_at: new Date().toISOString(),
    });

    storage.logAudit('CONFIG', 'success', {
      operation: 'desktop_register',
      details: JSON.stringify({ desktop_id }),
    });

    return { registered: true };
  });

  /**
   * Get challenge nonce for desktop authentication
   * GET /v1/desktop/challenge?desktop_id=<uuid>
   */
  server.get<{
    Querystring: {
      desktop_id: string;
    };
  }>('/v1/desktop/challenge', async (request) => {
    const { desktop_id } = request.query;

    if (!desktop_id) {
      throw new VaultError('INTERNAL_ERROR', 'desktop_id is required');
    }

    // Verify this desktop_id is registered
    const config = budget.getConfig();
    if (!config.desktop_owner || config.desktop_owner.desktop_id !== desktop_id) {
      throw new VaultError('INTERNAL_ERROR', 'Desktop not registered');
    }

    // Clean up expired state
    cleanupOwnerState();

    // Generate challenge
    const nonce = generateChallenge();
    const expires_at = Date.now() + CHALLENGE_TIMEOUT_MS;

    // Store challenge
    pendingChallenges.set(desktop_id, {
      nonce,
      desktop_id,
      expires_at,
    });

    return {
      desktop_id,
      nonce,
      expires_at: new Date(expires_at).toISOString(),
    };
  });

  /**
   * Verify challenge signature and issue owner token
   * POST /v1/desktop/verify
   */
  server.post<{
    Body: {
      desktop_id: string;
      nonce: string;
      signature: string; // base64 encoded Ed25519 signature
    };
  }>('/v1/desktop/verify', async (request) => {
    const { desktop_id, nonce, signature } = request.body;

    if (!desktop_id || !nonce || !signature) {
      throw new VaultError('INTERNAL_ERROR', 'desktop_id, nonce, and signature are required');
    }

    // Clean up expired state
    cleanupOwnerState();

    // Get pending challenge
    const challenge = pendingChallenges.get(desktop_id);
    if (!challenge) {
      throw new VaultError('INTERNAL_ERROR', 'No pending challenge for this desktop');
    }

    // Check if challenge expired
    if (Date.now() > challenge.expires_at) {
      pendingChallenges.delete(desktop_id);
      throw new VaultError('CONSENT_TIMEOUT', 'Challenge expired');
    }

    // Check nonce matches
    if (challenge.nonce !== nonce) {
      throw new VaultError('INTERNAL_ERROR', 'Invalid nonce');
    }

    // Get registered public key
    const config = budget.getConfig();
    if (!config.desktop_owner || config.desktop_owner.desktop_id !== desktop_id) {
      throw new VaultError('INTERNAL_ERROR', 'Desktop not registered');
    }

    // Verify signature
    const publicKeyBytes = Buffer.from(config.desktop_owner.public_key, 'base64');
    const nonceBytes = Buffer.from(nonce, 'base64');
    const signatureBytes = Buffer.from(signature, 'base64');

    const valid = verifyEd25519Signature(
      new Uint8Array(nonceBytes),
      new Uint8Array(signatureBytes),
      new Uint8Array(publicKeyBytes)
    );

    if (!valid) {
      storage.logAudit('DENY', 'denied', {
        operation: 'desktop_verify',
        details: JSON.stringify({ desktop_id, reason: 'invalid_signature' }),
      });
      throw new VaultError('INTERNAL_ERROR', 'Invalid signature');
    }

    // Remove used challenge
    pendingChallenges.delete(desktop_id);

    // Generate owner token
    const token = generateOwnerToken();
    const now = Date.now();

    ownerTokens.set(token, {
      token,
      desktop_id,
      created_at: now,
      last_used_at: now,
    });

    storage.logAudit('GRANT', 'success', {
      operation: 'desktop_verify',
      details: JSON.stringify({ desktop_id }),
    });

    return {
      verified: true,
      token,
      expires_at: new Date(now + OWNER_TOKEN_MAX_AGE_MS).toISOString(),
      idle_timeout_minutes: OWNER_TOKEN_IDLE_TIMEOUT_MS / 60000,
    };
  });

  // ============================================================================
  // Relay Info / Config (owner only)
  // ============================================================================

  server.get('/v1/relay/info', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const identity = await ensureRelayIdentity();
    return {
      vault_id: identity.vaultId,
      relay_url: identity.relayUrl,
      hpke_public_key: identity.hpkeKeyPair.publicKey.toString('base64'),
      pairing_token: identity.pairingToken || null,
      relay_connected: relayConnected,
    };
  });

  server.post<{
    Body: {
      relay_url?: string;
      pairing_token?: string;
    };
  }>('/v1/relay/config', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const { relay_url, pairing_token } = request.body || {};
    if (relay_url !== undefined) {
      budget.setConfig('relay_url', relay_url);
    }
    if (pairing_token !== undefined) {
      budget.setConfig('relay_pairing_token', pairing_token);
    }

    // Restart relay client with new config
    try {
      await startRelayClient(server);
    } catch (err) {
      return reply.status(500).send({
        error: {
          code: 'RELAY_START_FAILED',
          message: err instanceof Error ? err.message : 'Failed to start relay client',
        },
      });
    }

    return {
      updated: true,
    };
  });

  // ============================================================================
  // Pairing Tokens (owner only)
  // ============================================================================

  server.post<{
    Body: {
      service_id: string;
      scopes: string[];
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      ttl_seconds?: number;
    };
  }>('/v1/pairing/start', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const body = request.body || {};
    if (!body.service_id || !body.scopes || body.scopes.length === 0) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: 'service_id and at least one scope are required',
        },
      });
    }

    const budgetConfig = normalizeBudget(body.budget);
    const { token, expires_at } = storage.createPairingToken({
      service_id: body.service_id,
      scopes: body.scopes,
      budget: budgetConfig,
      ttl_seconds: body.ttl_seconds,
    });

    return {
      token,
      expires_at,
      service_id: body.service_id,
      scopes: body.scopes,
      budget: budgetConfig,
    };
  });

  // ============================================================================
  // Signed Pairing Grants (protocol spec section 7.1)
  // ============================================================================

  server.post<{
    Body: {
      agent_name: string;
      mode: AgentConnectionMode;
      permission_scopes: string[];
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      tier?: AgentConnectionTier;
      ttl_ms?: number;
    };
  }>('/v1/pairing-grants', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const body = request.body || {};
    if (!body.agent_name || !body.mode || !body.permission_scopes || body.permission_scopes.length === 0) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: 'agent_name, mode, and at least one permission_scope are required',
        },
      });
    }

    // Validate mode
    const validModes: AgentConnectionMode[] = ['proxy', 'mcp', 'sdk'];
    if (!validModes.includes(body.mode)) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: `mode must be one of: ${validModes.join(', ')}`,
        },
      });
    }

    // Get vault identity (keys, vault_id, relay_url)
    const identity = await ensureRelayIdentity();
    const budgetConfig = normalizeBudget(body.budget);

    // Generate agent_id
    const agentId = `agent_${crypto.randomBytes(12).toString('hex')}`;

    // Create the signed pairing grant (REQUEST-ONLY, no authority)
    // Permissions are stored ONLY in vault policy DB via createAgentConnection
    const token = createSignedPairingGrant(
      {
        vault_id: identity.vaultId,
        agent_id: agentId,
        agent_name: body.agent_name.trim(),
        mode: body.mode,
        vault_hpke_public_key: identity.hpkeKeyPair.publicKey.toString('base64'),
        vault_signing_public_key: identity.signingKeyPair.publicKey.toString('base64'),
        relay_url: identity.relayUrl || DEFAULT_RELAY_URL || CORE_DEFAULT_RELAY_URL,
        ttl_ms: body.ttl_ms,
        // NOTE: permission_scopes, budget, tier are NOT included in the grant
        // They are stored ONLY in the vault policy DB
      },
      identity.signingKeyPair.privateKey
    );

    // Create pending agent connection
    storage.createAgentConnection({
      agent_id: agentId,
      name: body.agent_name.trim(),
      mode: body.mode,
      permission_scopes: body.permission_scopes,
      budget: budgetConfig,
      tier: body.tier || 'free',
    });

    // Log audit event
    storage.logAudit('CONFIG', 'success', {
      operation: 'pairing_grant_created',
      details: JSON.stringify({
        agent_id: agentId,
        agent_name: body.agent_name,
        mode: body.mode,
        scopes: body.permission_scopes,
      }),
    });

    return {
      token,
      agent_id: agentId,
      agent_name: body.agent_name.trim(),
      mode: body.mode,
      permission_scopes: body.permission_scopes,
      budget: budgetConfig,
      tier: body.tier || 'free',
    };
  });

  /**
   * Exchange a pairing grant for session credentials
   *
   * Called by dcp-agent after receiving a pairing token.
   * The agent generates its own service keypair and sends the public key.
   * The vault verifies the grant and returns session credentials.
   */
  server.post<{
    Body: {
      pairing_grant: string;
      service_public_key: string;
    };
  }>('/v1/pairing-grants/exchange', async (request, reply) => {
    const body = request.body || {};
    if (!body.pairing_grant || !body.service_public_key) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: 'pairing_grant and service_public_key are required',
        },
      });
    }

    // Get vault identity to verify with our signing key
    const identity = await ensureRelayIdentity();

    // Decode and verify the pairing grant
    const decoded = decodePairingGrant(body.pairing_grant);
    if (!decoded) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_GRANT',
          message: 'Invalid pairing grant format',
        },
      });
    }

    // Verify signature with our signing key
    const verified = verifyPairingGrantWithKey(
      body.pairing_grant,
      identity.signingKeyPair.publicKey
    );
    if (!verified) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_GRANT',
          message: 'Pairing grant signature invalid or expired',
        },
      });
    }

    // Verify vault_id matches
    if (verified.vault_id !== identity.vaultId) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_GRANT',
          message: 'Pairing grant is for a different vault',
        },
      });
    }

    // Check if agent connection exists and is still pending
    const connection = storage.getAgentConnection(verified.agent_id);
    if (!connection) {
      return reply.status(404).send({
        error: {
          code: 'AGENT_NOT_FOUND',
          message: 'Agent connection not found',
        },
      });
    }

    if (connection.status === 'revoked') {
      return reply.status(403).send({
        error: {
          code: 'AGENT_REVOKED',
          message: 'Agent connection has been revoked',
        },
      });
    }

    if (connection.status === 'active') {
      return reply.status(400).send({
        error: {
          code: 'ALREADY_PAIRED',
          message: 'Agent is already paired',
        },
      });
    }

    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('base64url');
    const sessionTokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

    // Mark agent as paired with their public key (protocol spec section 7.3)
    storage.markAgentPaired(verified.agent_id, sessionTokenHash, body.service_public_key);

    // Log audit event
    storage.logAudit('CONFIG', 'success', {
      operation: 'pairing_grant_exchanged',
      details: JSON.stringify({
        agent_id: verified.agent_id,
        agent_name: verified.agent_name,
        mode: verified.mode,
        has_service_public_key: !!body.service_public_key,
      }),
    });

    // Return credentials for agent.json
    return {
      version: 1,
      vault_id: verified.vault_id,
      agent_id: verified.agent_id,
      agent_name: verified.agent_name,
      mode: verified.mode,
      vault_hpke_public_key: verified.vault_hpke_public_key,
      vault_signing_public_key: verified.vault_signing_public_key,
      session_token: sessionToken,
      permission_scopes: verified.permission_scopes,
      budget: verified.budget,
      tier: verified.tier,
      relay_url: verified.relay_url,
      paired_at: new Date().toISOString(),
    };
  });

  // ============================================================================
  // Vault Lock (local only)
  // ============================================================================

  server.post('/v1/vault/lock', async () => {
    storage.lock();
    return { locked: true };
  });

  // ============================================================================
  // Scopes
  // ============================================================================

  server.get('/scopes', async () => {
    const records = storage.listRecords();

    return {
      scopes: records.map((r) => {
        // Format scope with operation prefix to match authorization checks
        // WALLET_KEY uses sign:{chain}, other data types use read:{scope}
        let formattedScope: string;
        if (r.item_type === 'WALLET_KEY' && r.chain) {
          formattedScope = `sign:${r.chain}`;
        } else {
          formattedScope = `read:${r.scope}`;
        }
        return {
          scope: formattedScope,
          type: r.item_type,
          sensitivity: r.sensitivity,
          chain: r.chain,
          public_address: r.public_address,
        };
      }),
    };
  });

  // ============================================================================
  // Address
  // ============================================================================

  function getWalletAddress(chain: Chain): { chain: Chain; address: string } {
    const records = storage.listRecords();
    const wallet = records.find((r) => r.item_type === 'WALLET_KEY' && r.chain === chain);

    if (!wallet || !wallet.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    return {
      chain,
      address: wallet.public_address,
    };
  }

  server.get<{ Params: { chain: Chain } }>('/address/:chain', async (request) => {
    return getWalletAddress(request.params.chain);
  });

  server.get<{ Params: { chain: Chain } }>('/v1/address/:chain', async (request) => {
    return getWalletAddress(request.params.chain);
  });

  // ============================================================================
  // Budget Check
  // ============================================================================

  server.get<{ Querystring: { amount: string; currency: string; chain?: Chain } }>(
    '/budget/check',
    async (request) => {
      const amount = parseFloat(request.query.amount);
      const currency = request.query.currency;
      const chainParam = request.query.chain;

      if (isNaN(amount) || !currency) {
        throw new VaultError('INTERNAL_ERROR', 'amount and currency are required');
      }

      const limits = budget.getLimits(currency);
      const chain = getChainForCurrency(currency, chainParam);
      const result = budget.checkBudget(amount, currency, chain);

      return {
        allowed: result.allowed,
        limits: {
          per_tx: limits.tx_limit,
          daily: limits.daily_budget,
          approval_threshold: limits.approval_threshold,
        },
        remaining: {
          daily: result.remaining_daily,
          per_tx: result.remaining_tx,
        },
        requires_approval: result.requires_approval,
        reason: result.reason,
      };
    }
  );

  // ============================================================================
  // Budget Config (Owner Only)
  // ============================================================================

  server.get('/v1/vault/budgets', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const config = budget.getConfig();
    return {
      daily_budget: config.daily_budget,
      tx_limit: config.tx_limit,
      approval_threshold: config.approval_threshold,
    };
  });

  server.post<{
    Body: {
      daily_budget?: Record<string, number>;
      tx_limit?: Record<string, number>;
      approval_threshold?: Record<string, number>;
    };
  }>('/v1/vault/budgets', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const { daily_budget, tx_limit, approval_threshold } = request.body || {};

    if (daily_budget) {
      for (const [currency, amount] of Object.entries(daily_budget)) {
        budget.setLimit('daily_budget', currency, Number(amount));
      }
    }
    if (tx_limit) {
      for (const [currency, amount] of Object.entries(tx_limit)) {
        budget.setLimit('tx_limit', currency, Number(amount));
      }
    }
    if (approval_threshold) {
      for (const [currency, amount] of Object.entries(approval_threshold)) {
        budget.setLimit('approval_threshold', currency, Number(amount));
      }
    }

    const config = budget.getConfig();
    return {
      updated: true,
      daily_budget: config.daily_budget,
      tx_limit: config.tx_limit,
      approval_threshold: config.approval_threshold,
    };
  });

  // ============================================================================
  // Currency Management (Owner Only)
  // ============================================================================

  server.get('/v1/vault/currencies', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    return budget.getAllCurrencies();
  });

  server.post<{
    Body: {
      action: 'add' | 'remove';
      code: string;
    };
  }>('/v1/vault/currencies', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const { action, code } = request.body || {};

    if (!action || !code) {
      return reply.status(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'action and code are required',
        },
      });
    }

    try {
      if (action === 'add') {
        budget.addCustomCurrency(code);
      } else if (action === 'remove') {
        budget.removeCustomCurrency(code);
      } else {
        return reply.status(400).send({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'action must be "add" or "remove"',
          },
        });
      }

      return {
        success: true,
        ...budget.getAllCurrencies(),
      };
    } catch (err) {
      const error = err as Error;
      return reply.status(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.message,
        },
      });
    }
  });

  // ============================================================================
  // Agents (Sessions)
  // ============================================================================

  server.get('/agents', async () => {
    const sessions = storage.listActiveSessions();

    return {
      agents: sessions.map((s) => ({
        id: s.id,
        agent_name: s.agent_name,
        granted_scopes: s.granted_scopes,
        consent_mode: s.consent_mode,
        expires_at: s.expires_at,
        created_at: s.created_at,
        last_used_at: s.last_used_at,
      })),
    };
  });

  // ============================================================================
  // Agent Connections (Owner dashboard + agent heartbeat)
  // ============================================================================

  server.get('/v1/agent-connections', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    // Normalize permission_scopes to fix old data saved without read:/sign: prefix
    const agents = storage.listAgentConnections().map((agent) => ({
      ...agent,
      permission_scopes: normalizePermissionScopes(agent.permission_scopes || []),
    }));

    return { agents };
  });

  server.post<{ Params: { id: string } }>('/v1/agent-connections/:id/revoke', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const revoked = storage.revokeAgentConnection(request.params.id);
    return { revoked };
  });

  server.delete<{ Params: { id: string } }>('/v1/agent-connections/:id', async (request, reply) => {
    // Owner auth required for security, but for local agents we also delete the config file
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const agentId = request.params.id;
    const deleted = storage.deleteAgentConnection(agentId);

    // Also delete the local agent config file if it exists
    if (deleted) {
      const agentConfigPath = path.join(os.homedir(), '.dcp', 'agents', `${agentId}.json`);
      if (fs.existsSync(agentConfigPath)) {
        try {
          fs.unlinkSync(agentConfigPath);
        } catch (err) {
          console.error(`Failed to delete agent config file: ${agentConfigPath}`, err);
        }
      }
    }

    return { deleted };
  });

  server.patch<{
    Params: { id: string };
    Body: {
      permission_scopes?: string[];
      budget?: {
        daily?: number;
        currency?: string;
        auto_approve_under?: number;
      };
    };
  }>('/v1/agent-connections/:id', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const agentId = request.params.id;
    const body = request.body || {};

    // Verify agent exists
    const agent = storage.getAgentConnection(agentId);
    if (!agent) {
      return reply.status(404).send({
        error: {
          code: 'AGENT_NOT_FOUND',
          message: 'Agent connection not found',
        },
      });
    }

    if (agent.status === 'revoked') {
      return reply.status(400).send({
        error: {
          code: 'AGENT_REVOKED',
          message: 'Cannot update a revoked agent',
        },
      });
    }

    // Validate permission_scopes if provided
    if (body.permission_scopes !== undefined) {
      if (!Array.isArray(body.permission_scopes)) {
        return reply.status(400).send({
          error: {
            code: 'INVALID_REQUEST',
            message: 'permission_scopes must be an array',
          },
        });
      }
      // Validate each scope is a non-empty string
      for (const scope of body.permission_scopes) {
        if (typeof scope !== 'string' || scope.trim().length === 0) {
          return reply.status(400).send({
            error: {
              code: 'INVALID_REQUEST',
              message: 'Each permission scope must be a non-empty string',
            },
          });
        }
      }
    }

    // Build updates object
    const updates: {
      permission_scopes?: string[];
      budget_daily?: number;
      budget_currency?: string;
      budget_auto_approve_under?: number;
    } = {};

    if (body.permission_scopes !== undefined) {
      // Normalize scopes to ensure they have proper read:/sign: prefix
      updates.permission_scopes = normalizePermissionScopes(
        body.permission_scopes.map((s: string) => s.trim())
      );
    }
    if (body.budget?.daily !== undefined) {
      updates.budget_daily = body.budget.daily;
    }
    if (body.budget?.currency !== undefined) {
      updates.budget_currency = body.budget.currency.toUpperCase();
    }
    if (body.budget?.auto_approve_under !== undefined) {
      updates.budget_auto_approve_under = body.budget.auto_approve_under;
    }

    const updated = storage.updateAgentConnection(agentId, updates);
    if (!updated) {
      return reply.status(500).send({
        error: {
          code: 'UPDATE_FAILED',
          message: 'Failed to update agent connection',
        },
      });
    }

    // Return the updated agent with normalized scopes
    const updatedAgent = storage.getAgentConnection(agentId);
    return {
      updated: true,
      agent: updatedAgent ? {
        ...updatedAgent,
        permission_scopes: normalizePermissionScopes(updatedAgent.permission_scopes || []),
      } : null,
    };
  });

  server.post<{
    Body: {
      agent_id?: string;
    };
  }>('/v1/heartbeat', async (request, reply) => {
    const body = request.body || {};
    const agentId = body.agent_id?.trim();
    if (!agentId) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: 'agent_id is required',
        },
      });
    }

    const ok = storage.recordAgentHeartbeat(agentId);
    if (!ok) {
      return reply.status(404).send({
        error: {
          code: 'AGENT_NOT_FOUND',
          message: 'Agent connection not found or revoked',
        },
      });
    }

    return {
      ok: true,
      agent_id: agentId,
      last_seen_at: storage.getAgentConnection(agentId)?.last_seen_at,
    };
  });

  // ============================================================================
  // VPS Pairing Claims (Owner Only)
  // ============================================================================

  /**
   * Create a VPS pairing invite token (dcp_vps_v1_...)
   * This is used by the Desktop app to generate invites for remote agents
   */
  server.post<{
    Body: {
      agent_name: string;
      ttl_ms?: number;
    };
  }>('/v1/pairing-invites', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const { agent_name, ttl_ms } = request.body || {};
    if (!agent_name || typeof agent_name !== 'string' || !agent_name.trim()) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: 'agent_name is required',
        },
      });
    }

    // Get or create vault relay identity (keys and relay URL)
    const identity = await ensureRelayIdentity();
    const relayUrl = identity.relayUrl || DEFAULT_RELAY_URL || CORE_DEFAULT_RELAY_URL || '';

    if (!identity.vaultId || !relayUrl) {
      return reply.status(400).send({
        error: {
          code: 'NOT_CONFIGURED',
          message: 'Vault relay identity not configured. Ensure vault is initialized.',
        },
      });
    }

    // Create the VPS invite
    const inviteToken = createVpsPairingInvite(
      identity.vaultId,
      relayUrl,
      identity.hpkeKeyPair.publicKey.toString('base64'),
      identity.signingKeyPair.publicKey.toString('base64'),
      ttl_ms || 3600000 // Default 1 hour
    );
    const parsedInvite = parseVpsPairingInvite(inviteToken);
    if (!parsedInvite) {
      return reply.status(500).send({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to create VPS pairing invite',
        },
      });
    }

    try {
      await registerVpsInviteWithRelay(relayUrl, parsedInvite.invite_id, identity.vaultId);
    } catch (err) {
      return reply.status(502).send({
        error: {
          code: 'RELAY_UNAVAILABLE',
          message: err instanceof Error ? err.message : 'Failed to register invite with relay',
        },
      });
    }

    return {
      token: inviteToken,
      agent_name: agent_name.trim(),
      vault_id: identity.vaultId,
      relay_url: relayUrl,
      expires_at: new Date(Date.now() + (ttl_ms || 3600000)).toISOString(),
    };
  });

  /**
   * List pending VPS pairing claims waiting for user approval
   */
  server.get('/v1/pairing-claims', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    // Return all pending claims
    const claims = Array.from(pendingPairingClaims.values()).filter(
      (claim) => claim.status === 'pending'
    );
    return { claims };
  });

  /**
   * Get a specific pairing claim
   */
  server.get<{ Params: { id: string } }>('/v1/pairing-claims/:id', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const claim = pendingPairingClaims.get(request.params.id);
    if (!claim) {
      return reply.status(404).send({
        error: {
          code: 'CLAIM_NOT_FOUND',
          message: 'Pairing claim not found',
        },
      });
    }

    return { claim };
  });

  /**
   * Approve a VPS pairing claim
   */
  server.post<{
    Params: { id: string };
    Body: {
      agent_name?: string;
      permission_scopes?: string[];
    };
  }>('/v1/pairing-claims/:id/approve', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const claim = pendingPairingClaims.get(request.params.id);
    if (!claim) {
      return reply.status(404).send({
        error: {
          code: 'CLAIM_NOT_FOUND',
          message: 'Pairing claim not found',
        },
      });
    }

    if (claim.status !== 'pending') {
      return reply.status(400).send({
        error: {
          code: 'CLAIM_ALREADY_RESOLVED',
          message: `Claim already ${claim.status}`,
        },
      });
    }

    // Generate agent ID and register the agent
    const agentId = `vps_${crypto.randomUUID().slice(0, 8)}`;
    const agentName = request.body?.agent_name || claim.claim.agent_hostname || 'VPS Agent';
    // Request-only by default: approving pairing only establishes the channel.
    // Permission scopes are optional policy, not part of the invite/claim authority.
    const permissionScopes = request.body?.permission_scopes || [];
    const vaultConfig = budget.getConfig();

    // Register the agent connection
    storage.createAgentConnection({
      agent_id: agentId,
      name: agentName,
      mode: 'mcp',
      tier: 'free',
      permission_scopes: permissionScopes,
      budget: { daily: 0, currency: 'USD', auto_approve_under: 0 },
    });

    // Mark agent as paired and store its public key for relay auth
    storage.markAgentPaired(agentId, undefined, claim.claim.agent_public_key);

    // Update claim status
    claim.status = 'approved';
    claim.agent_id = agentId;
    claim.vault_id = vaultConfig.vault_id || '';
    claim.resolved_at = Date.now();

    // Send approval result back to relay
    if (relayClient) {
      relayClient.sendPairingResult(claim.claim_id, true, agentId);
    }

    // Remove from pending after a short delay (let polling pick up the result)
    setTimeout(() => {
      pendingPairingClaims.delete(claim.claim_id);
    }, 60_000);

    return {
      approved: true,
      agent_id: agentId,
      agent_name: agentName,
    };
  });

  /**
   * Deny a VPS pairing claim
   */
  server.post<{ Params: { id: string } }>('/v1/pairing-claims/:id/deny', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const claim = pendingPairingClaims.get(request.params.id);
    if (!claim) {
      return reply.status(404).send({
        error: {
          code: 'CLAIM_NOT_FOUND',
          message: 'Pairing claim not found',
        },
      });
    }

    if (claim.status !== 'pending') {
      return reply.status(400).send({
        error: {
          code: 'CLAIM_ALREADY_RESOLVED',
          message: `Claim already ${claim.status}`,
        },
      });
    }

    // Update claim status
    claim.status = 'denied';
    claim.resolved_at = Date.now();

    // Send denial result back to relay
    if (relayClient) {
      relayClient.sendPairingResult(claim.claim_id, false);
    }

    // Remove from pending after a short delay
    setTimeout(() => {
      pendingPairingClaims.delete(claim.claim_id);
    }, 60_000);

    return { denied: true };
  });

  // ============================================================================
  // Trusted Services (Owner Only)
  // ============================================================================

  server.get('/v1/services', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const services = storage.listTrustedServices();
    return { services };
  });

  server.get('/v1/services/known', async () => {
    return { services: listKnownServices() };
  });

  server.post<{
    Body: {
      service_id?: string;
      name?: string;
      public_key?: string;
      scopes?: string[] | string;
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      enabled?: boolean;
      verified?: boolean;
    };
  }>('/v1/services', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const body = request.body || {};
    const serviceId = body.service_id?.trim();
    if (!serviceId) {
      throw new VaultError('INTERNAL_ERROR', 'service_id is required');
    }

    const publicKey = body.public_key?.trim();
    if (!publicKey || !isValidPublicKey(publicKey)) {
      throw new VaultError('INTERNAL_ERROR', 'Valid public_key is required');
    }

    const scopes = normalizeScopes(body.scopes);
    if (scopes.length === 0) {
      throw new VaultError('INTERNAL_ERROR', 'At least one scope is required');
    }

    const budget = normalizeBudget(body.budget);
    const enabled = body.enabled !== undefined ? Boolean(body.enabled) : true;

    storage.addTrustedService({
      service_id: serviceId,
      name: body.name?.trim() || serviceId,
      public_key: publicKey,
      scopes,
      budget,
      verified: body.verified ?? false,
    });

    if (!enabled) {
      storage.updateTrustedService(serviceId, { enabled: false });
    }

    return { created: true, service: storage.getTrustedService(serviceId) };
  });

  server.patch<{
    Params: { id: string };
    Body: {
      name?: string;
      public_key?: string;
      scopes?: string[] | string;
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      enabled?: boolean;
      verified?: boolean;
    };
  }>('/v1/services/:id', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const serviceId = request.params.id;
    const body = request.body || {};
    const updates: Partial<Pick<TrustedService, 'name' | 'public_key' | 'scopes' | 'budget' | 'enabled' | 'verified'>> = {};

    if (body.name !== undefined) {
      updates.name = body.name.trim();
    }
    if (body.public_key !== undefined) {
      const key = body.public_key.trim();
      if (!isValidPublicKey(key)) {
        throw new VaultError('INTERNAL_ERROR', 'Invalid public_key');
      }
      updates.public_key = key;
    }
    if (body.scopes !== undefined) {
      const scopes = normalizeScopes(body.scopes);
      if (scopes.length === 0) {
        throw new VaultError('INTERNAL_ERROR', 'At least one scope is required');
      }
      updates.scopes = scopes;
    }
    if (body.budget !== undefined) {
      updates.budget = normalizeBudget(body.budget);
    }
    if (body.enabled !== undefined) {
      updates.enabled = Boolean(body.enabled);
    }
    if (body.verified !== undefined) {
      updates.verified = Boolean(body.verified);
    }

    storage.updateTrustedService(serviceId, updates);
    return { updated: true, service: storage.getTrustedService(serviceId) };
  });

  server.delete<{ Params: { id: string } }>('/v1/services/:id', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const serviceId = request.params.id;
    storage.revokeTrustedService(serviceId);
    return { revoked: true };
  });

  // ============================================================================
  // Consent - List Pending
  // ============================================================================

  server.get('/consent', async () => {
    const pending = storage.getPendingConsents();

    return {
      pending: pending.map((c) => {
        let details: Record<string, unknown> = {};
        try {
          if (c.details) {
            details = JSON.parse(c.details);
          }
        } catch {
          // Ignore
        }

        return {
          id: c.id,
          agent_name: c.agent_name,
          action: c.action,
          scope: c.scope,
          details,
          status: c.status,
          created_at: c.created_at,
          expires_at: c.expires_at,
        };
      }),
    };
  });

  // ============================================================================
  // Consent - Approve
  // ============================================================================

  server.post<{ Params: { id: string }; Body: { session?: boolean; mode?: string } }>(
    '/consent/:id/approve',
    async (request) => {
      // Owner token required for consent approval (protocol spec 3.1)
      requireOwnerToken(request);

      const { id } = request.params;
      const body = request.body || {};
      const createSession = Boolean(body.session || body.mode === 'session');

      const consent = storage.getPendingConsent(id);

      if (!consent) {
        throw new VaultError('CONSENT_NOT_FOUND', `Consent not found: ${id}`);
      }

      if (consent.status !== 'pending') {
        throw new VaultError('INTERNAL_ERROR', `Consent already ${consent.status}`);
      }

      if (new Date(consent.expires_at) < new Date()) {
        storage.resolveConsent(id, 'expired');
        throw new VaultError('CONSENT_TIMEOUT', 'Consent has expired');
      }

      // Create session only for "session" mode
      // "once" mode: NO session - the sign endpoint will check for approved consent and consume it
      let sessionId: string | undefined;
      if (createSession) {
        // Session mode: 4 hour session (allows multiple transactions)
        const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
        const newSession = storage.createSession(
          consent.agent_name,
          [consent.scope],
          'session',
          expiresAt
        );
        sessionId = newSession.id;
      }
      // else: Once mode - NO session created
      // The retry will find this approved consent via consumeApprovedConsent()

      // Approve (with session_id if created, undefined for "once" mode)
      storage.resolveConsent(id, 'approved', sessionId);

      // Log to audit
      storage.logAudit('GRANT', 'success', {
        agentName: consent.agent_name,
        scope: consent.scope,
        operation: createSession ? 'session_grant' : 'once_grant',
        details: sessionId ? JSON.stringify({ session_id: sessionId }) : undefined,
      });

      return {
        approved: true,
        session_id: sessionId,
      };
    }
  );

  // ============================================================================
  // Consent - Deny
  // ============================================================================

  server.post<{ Params: { id: string } }>('/consent/:id/deny', async (request) => {
    // Owner token required for consent denial (protocol spec 3.1)
    requireOwnerToken(request);

    const { id } = request.params;

    const consent = storage.getPendingConsent(id);

    if (!consent) {
      throw new VaultError('CONSENT_NOT_FOUND', `Consent not found: ${id}`);
    }

    if (consent.status !== 'pending') {
      throw new VaultError('INTERNAL_ERROR', `Consent already ${consent.status}`);
    }

    // Deny
    storage.resolveConsent(id, 'denied');

    // Log to audit
    storage.logAudit('DENY', 'denied', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: consent.action,
      details: 'Denied via REST API',
    });

    return {
      denied: true,
    };
  });

  // ============================================================================
  // Consent - Status (for polling)
  // ============================================================================

  server.get<{ Params: { id: string } }>('/consent/:id/status', async (request) => {
    const { id } = request.params;

    const consent = storage.getPendingConsent(id);

    if (!consent) {
      // Consent not found - might have been cleaned up
      return {
        id,
        status: 'not_found',
      };
    }

    // Check if expired
    if (consent.status === 'pending' && new Date(consent.expires_at) < new Date()) {
      storage.resolveConsent(id, 'expired');
      return {
        id,
        status: 'expired',
      };
    }

    return {
      id,
      status: consent.status,
      session_id: consent.session_id,
    };
  });

  // ============================================================================
  // Revoke Agent Sessions
  // ============================================================================

  server.post<{ Params: { agent: string } }>('/revoke/:agent', async (request) => {
    const { agent } = request.params;

    const count = storage.revokeAgentSessions(agent);

    if (count > 0) {
      storage.logAudit('REVOKE', 'success', {
        agentName: agent,
        operation: 'revoke_agent',
        details: JSON.stringify({ sessions_revoked: count }),
      });
    }

    return {
      revoked: count,
    };
  });

  // ============================================================================
  // V1 API: Vault Read (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      agent_name: string;
      session_id?: string;
      description?: string;
      // Agent signature fields (optional, for paired agents)
      service_id?: string;
      service_signature?: string;
      timestamp?: string;
      nonce?: string;
    };
  }>('/v1/vault/read', async (request) => {
    const { scope, agent_name, session_id, description } = request.body;
    let effectiveSessionId = session_id;

    if (!scope || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope and agent_name are required');
    }

    // Check if vault is unlocked
    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Check agent permissions FIRST (before session/consent flow)
    // If a paired agent is making this request, verify they have permission for this scope
    const requestedScope = `read:${scope}`;
    const agentAuth = verifyLocalAgentRequest(request.body as Record<string, unknown>, requestedScope);
    if (!agentAuth.authorized && agentAuth.skipConsentFlow) {
      // Agent is out of scope - deny immediately, no consent popup
      throw new VaultError('SERVICE_SCOPE_VIOLATION', agentAuth.reason || 'Scope not permitted for this agent');
    }

    // Check if this is an owner request (desktop app with valid token)
    const ownerMode = isOwnerRequest(request);

    // Try to reuse an existing active session by agent + scope
    if (!effectiveSessionId && !ownerMode) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session (skip for owner mode or explicitly pre-authorized agents).
    // Request-only agents are authenticated but still go through consent.
    let hasSession = ownerMode || agentAuth.preAuthorized === true;
    if (!hasSession && effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(scope) || session.granted_scopes.some(s => scope.startsWith(s.replace('.*', '')))) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session and not owner/verified agent, create pending consent
    if (!hasSession) {
      const { consent, isNew } = storage.createPendingConsent(
        agent_name,
        'read',
        scope,
        description ? JSON.stringify({ description }) : undefined
      );

      console.log('[CONSENT] Created consent:', consent.id, 'for agent:', agent_name, 'isNew:', isNew);
      // Telegram notification handled by consent watcher (avoids duplicates)

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    // Get the record
    const record = storage.getRecord(scope);
    if (!record) {
      throw new VaultError('RECORD_NOT_FOUND', `No record found for scope: ${scope}`);
    }

    // Decrypt if it's not a CRITICAL item
    if (record.sensitivity === 'critical') {
      // Don't return critical data - return reference only
      storage.logAudit('READ', 'success', {
        agentName: agent_name,
        scope,
        operation: 'read_reference',
      });

      return {
        scope,
        type: record.item_type,
        sensitivity: record.sensitivity,
        note: 'Critical data cannot be read directly. Use vault_sign_tx for signing operations.',
      };
    }

    // Decrypt and return
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(scope);
    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No encrypted data for scope: ${scope}`);
    }

    const decrypted = envelopeDecrypt(payload, masterKey);
    const data = JSON.parse(decrypted.toString('utf-8'));

    storage.logAudit('READ', 'success', {
      agentName: agent_name,
      scope,
      operation: 'read_data',
    });

    return {
      scope,
      data,
    };
  });

  // ============================================================================
  // V1 API: Vault Write (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      data: Record<string, unknown>;
      agent_name: string;
      session_id?: string;
      description?: string;
      // Agent signature fields (optional, for paired agents)
      service_id?: string;
      service_signature?: string;
      timestamp?: string;
      nonce?: string;
    };
  }>('/v1/vault/write', async (request) => {
    const { scope, data, agent_name, session_id } = request.body;
    let effectiveSessionId = session_id;

    if (!scope || !data || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope, data, and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Check agent permissions FIRST (before session/consent flow)
    const requestedScope = `write:${scope}`;
    const agentAuth = verifyLocalAgentRequest(request.body as Record<string, unknown>, requestedScope);
    if (!agentAuth.authorized && agentAuth.skipConsentFlow) {
      throw new VaultError('SERVICE_SCOPE_VIOLATION', agentAuth.reason || 'Scope not permitted for this agent');
    }

    // Check if this is an owner request (desktop app with valid token)
    const ownerMode = isOwnerRequest(request);

    // Skip write permission check for owner mode
    if (!ownerMode && !isWriteAllowed(agent_name, scope)) {
      throw new VaultError(
        'SCOPE_VIOLATION',
        `Agent ${agent_name} not authorized to write scope: ${scope}`
      );
    }

    if (!effectiveSessionId && !ownerMode) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session (skip for owner mode)
    let hasSession = ownerMode; // Owner mode auto-approves
    if (!hasSession && effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (
          session.granted_scopes.includes(scope) ||
          session.granted_scopes.some((s) => scope.startsWith(s.replace('.*', '')))
        ) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session and not owner, create pending consent
    if (!hasSession) {
      const { consent, isNew } = storage.createPendingConsent(
        agent_name,
        'write',
        scope
      );

      // Telegram notification handled by consent watcher (avoids duplicates)

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const masterKey = storage.getMasterKey();
    const existing = storage.getRecord(scope);
    const payloadData = normalizeWriteData(scope, data);

    if (existing) {
      storage.updateRecord(existing.id, payloadData, masterKey);
    } else {
      storage.createRecord({
        scope,
        item_type: inferItemType(scope),
        sensitivity: inferSensitivity(scope),
        data: payloadData,
      });
    }

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope,
      operation: 'write',
    });

    return {
      scope,
      created: !existing,
      updated: !!existing,
      sensitivity: existing?.sensitivity || inferSensitivity(scope),
    };
  });

  // ============================================================================
  // V1 API: Vault Delete (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/delete', async (request) => {
    const { scope, agent_name, session_id, description } = request.body;
    let effectiveSessionId = session_id;

    if (!scope || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const ownerMode = isOwnerRequest(request);

    if (!ownerMode && !isWriteAllowed(agent_name, scope)) {
      throw new VaultError(
        'SCOPE_VIOLATION',
        `Agent ${agent_name} not authorized to delete scope: ${scope}`
      );
    }

    if (!effectiveSessionId && !ownerMode) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = ownerMode;
    if (!hasSession && effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (
          session.granted_scopes.includes(scope) ||
          session.granted_scopes.some((s) => scope.startsWith(s.replace('.*', '')))
        ) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    if (!hasSession) {
      const { consent, isNew } = storage.createPendingConsent(
        agent_name,
        'delete',
        scope,
        JSON.stringify({ description })
      );

      // Telegram notification handled by consent watcher (avoids duplicates)

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const existing = storage.listRecords().find((r) => r.scope === scope);
    if (!existing) {
      throw new VaultError('RECORD_NOT_FOUND', `No record found for scope: ${scope}`);
    }

    const deleted = storage.deleteRecord(scope);
    if (deleted) {
      storage.logAudit('EXECUTE', 'success', {
        agentName: agent_name,
        scope,
        operation: 'delete',
      });
    }

    return {
      scope,
      deleted,
    };
  });

  // ============================================================================
  // V1 API: Vault Sign (with consent + budget)
  // ============================================================================

  server.post<{
    Body: {
      chain: Chain;
      unsigned_tx: string;
      amount?: number;
      currency?: string;
      agent_name: string;
      session_id?: string;
      description?: string;
      idempotency_key?: string;
      // Agent signature fields (optional, for paired agents)
      service_id?: string;
      service_signature?: string;
      timestamp?: string;
      nonce?: string;
    };
  }>('/v1/vault/sign', async (request) => {
    const { chain, unsigned_tx, amount, currency, agent_name, session_id, description, idempotency_key } = request.body;
    let effectiveSessionId = session_id;

    if (!chain || !unsigned_tx || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'chain, unsigned_tx, and agent_name are required');
    }

    // Check if vault is unlocked
    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Check agent permissions FIRST (before session/consent flow)
    const requestedScope = `sign:${chain}`;
    const agentAuth = verifyLocalAgentRequest(request.body as Record<string, unknown>, requestedScope);
    if (!agentAuth.authorized && agentAuth.skipConsentFlow) {
      throw new VaultError('SERVICE_SCOPE_VIOLATION', agentAuth.reason || 'Scope not permitted for this agent');
    }

    // Determine currency from chain if not provided
    const txCurrency = currency || 'SOL';

    // Track if budget check auto-approved this transaction (amount under threshold)
    // When true, we skip the session/consent check since user configured this threshold
    let budgetAutoApproved = false;

    // Budget check if amount is provided
    if (amount !== undefined && amount > 0) {
      const budgetResult = budget.checkBudget(amount, txCurrency, chain);

      if (!budgetResult.allowed) {
        storage.logAudit('EXECUTE', 'denied', {
          agentName: agent_name,
          scope: `crypto.wallet.${chain}`,
          operation: 'sign_tx',
          details: JSON.stringify({ reason: budgetResult.reason, amount, currency: txCurrency }),
        });

        const errorCode = budgetResult.reason?.includes('BUDGET_EXCEEDED_TX')
          ? 'BUDGET_EXCEEDED_TX'
          : 'BUDGET_EXCEEDED_DAILY';

        // Send Telegram notification about budget exceeded (fire and forget)
        const limits = budget.getLimits(txCurrency);
        dispatchBudgetExceededNotification({
          agent_name,
          amount,
          currency: txCurrency,
          chain,
          error_code: errorCode,
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
          limit_daily: limits.daily_budget,
          limit_tx: limits.tx_limit,
        }).catch(err => console.log('[TG] Budget notification failed:', err));

        throw new VaultError(errorCode, budgetResult.reason || 'Budget exceeded', {
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
        });
      }

      // If above approval threshold, check for approved consent or require new consent
      if (budgetResult.requires_approval) {
        const walletScope = `crypto.wallet.${chain}`;

        // Check if there's an approved consent that can be consumed (approve-once semantics)
        const consumedConsent = storage.consumeApprovedConsent(agent_name, 'sign_tx', walletScope);
        if (consumedConsent) {
          // Approved consent found and consumed - proceed to signing below
          // Skip session check since we already have budget approval
          budgetAutoApproved = true;
          // Log the consumption
          storage.logAudit('EXECUTE', 'success', {
            agentName: agent_name,
            scope: walletScope,
            operation: 'consume_approval',
            details: JSON.stringify({ consent_id: consumedConsent.id, amount, currency: txCurrency }),
          });
        } else {
          // No approved consent - create pending consent
          const { consent, isNew } = storage.createPendingConsent(
            agent_name,
            'sign_tx',
            walletScope,
            JSON.stringify({ description, amount, currency: txCurrency, chain })
          );

          // Telegram notification handled by consent watcher (avoids duplicates)

          return {
            requires_consent: true,
            consent_id: consent.id,
            expires_at: consent.expires_at,
            reason: 'Amount exceeds approval threshold',
            message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
          };
        }
      } else {
        // Amount is under approval threshold - auto-approve without session/consent
        // This is the user's configured threshold, so we trust it
        budgetAutoApproved = true;
        storage.logAudit('EXECUTE', 'success', {
          agentName: agent_name,
          scope: `crypto.wallet.${chain}`,
          operation: 'budget_auto_approve',
          details: JSON.stringify({ amount, currency: txCurrency, chain, threshold: budget.getLimits(txCurrency).approval_threshold }),
        });
      }
    }

    // Get wallet scope
    const walletScope = `crypto.wallet.${chain}`;

    // Try to reuse an existing active session by agent + scope
    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session
    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session AND not budget auto-approved, check for consent
    // Skip this check if budget auto-approved (amount under threshold)
    if (!hasSession && !budgetAutoApproved) {
      // Check if there's an approved consent that can be consumed (approve-once semantics)
      const consumedConsent = storage.consumeApprovedConsent(agent_name, 'sign_tx', walletScope);
      if (!consumedConsent) {
        // No approved consent - create pending consent
        const { consent, isNew } = storage.createPendingConsent(
          agent_name,
          'sign_tx',
          walletScope,
          JSON.stringify({ description, amount, currency: txCurrency, chain })
        );

        // Telegram notification handled by consent watcher (avoids duplicates)

        return {
          requires_consent: true,
          consent_id: consent.id,
          expires_at: consent.expires_at,
          message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
        };
      }

      // Approved consent consumed - proceed to signing
      storage.logAudit('EXECUTE', 'success', {
        agentName: agent_name,
        scope: walletScope,
        operation: 'consume_approval',
        details: JSON.stringify({ consent_id: consumedConsent.id }),
      });
    }

    // Get wallet and sign
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(walletScope);

    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    // Sign the transaction (signTransaction expects base64 string for Solana)
    const signResult = await signTransaction(payload, masterKey, chain, unsigned_tx);

    // Record spend event if amount provided
    if (amount !== undefined && amount > 0 && effectiveSessionId) {
      storage.recordSpend(effectiveSessionId, amount, txCurrency, chain, 'sign_tx', 'committed', {
        idempotencyKey: idempotency_key,
      });
    }

    // Get updated budget info
    const budgetInfo = budget.checkBudget(0, txCurrency, chain);

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_tx',
      details: JSON.stringify({ chain, amount, currency: txCurrency }),
    });

    return {
      signed_tx: signResult.signed_tx,
      signature: signResult.signature,
      chain,
      remaining_daily: budgetInfo.remaining_daily,
      session_id: effectiveSessionId,
    };
  });

  // ============================================================================
  // V1 API: Vault Sign Message (with consent)
  // ============================================================================

  const handleSignMessage = async (body: {
    chain: Chain;
    message: string;
    encoding?: 'utf8' | 'base64';
    agent_name: string;
    session_id?: string;
    description?: string;
  }) => {
    const { chain, message, encoding, agent_name, session_id, description } = body;
    let effectiveSessionId = session_id;

    if (!chain || !message || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'chain, message, and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const walletScope = `crypto.wallet.${chain}`;

    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    if (!hasSession) {
      const { consent, isNew } = storage.createPendingConsent(
        agent_name,
        'sign_message',
        walletScope,
        JSON.stringify({
          description,
          chain,
          message_length: message.length,
          encoding: encoding || 'utf8',
        })
      );

      // Telegram notification handled by consent watcher (avoids duplicates)

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const records = storage.listRecords();
    const walletRecord = records.find(
      (r) => r.item_type === 'WALLET_KEY' && r.chain === chain
    );
    if (!walletRecord || !walletRecord.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(walletScope);
    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const resolvedEncoding = encoding || 'utf8';
    const signature = signSolanaMessage(payload, masterKey, message, resolvedEncoding);

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_message',
      details: JSON.stringify({ chain }),
    });

    return {
      signature,
      public_key: walletRecord.public_address,
      chain,
      session_id: effectiveSessionId,
    };
  };

  server.post<{
    Body: {
      chain: Chain;
      message: string;
      encoding?: 'utf8' | 'base64';
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/sign-message', async (request) => {
    return handleSignMessage(request.body);
  });

  server.post<{
    Body: {
      chain: Chain;
      message: string;
      encoding?: 'utf8' | 'base64';
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/sign_message', async (request) => {
    return handleSignMessage(request.body);
  });

  // ============================================================================
  // V1 API: Vault Sign x402 (with consent)
  // ============================================================================

  server.post<{
    Body: {
      network: 'solana';
      payload: string;
      amount?: string | number;
      currency?: string;
      recipient?: string;
      purpose?: string;
      agent_name: string;
      session_id?: string;
    };
  }>('/v1/vault/sign_x402', async (request) => {
    const {
      network,
      payload,
      amount,
      currency,
      recipient,
      purpose,
      agent_name,
      session_id,
    } = request.body;
    let effectiveSessionId = session_id;

    if (!network || !payload || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'network, payload, and agent_name are required');
    }

    if (network !== 'solana') {
      throw new VaultError('INVALID_CHAIN', 'Only solana network is supported');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const chain: Chain = 'solana';
    const walletScope = `crypto.wallet.${chain}`;

    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    const parsedAmount = normalizeAmount(amount);
    if (parsedAmount !== undefined && !currency) {
      throw new VaultError('INTERNAL_ERROR', 'currency is required when amount is provided');
    }

    // Track if budget check auto-approved this transaction
    let budgetAutoApproved = false;

    if (parsedAmount !== undefined && currency) {
      const budgetResult = budget.checkBudget(parsedAmount, currency, chain);

      if (!budgetResult.allowed) {
        const errorCode = budgetResult.reason?.includes('BUDGET_EXCEEDED_TX')
          ? 'BUDGET_EXCEEDED_TX'
          : 'BUDGET_EXCEEDED_DAILY';

        // Send Telegram notification about budget exceeded (fire and forget)
        const limits = budget.getLimits(currency);
        dispatchBudgetExceededNotification({
          agent_name,
          amount: parsedAmount,
          currency,
          chain,
          error_code: errorCode,
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
          limit_daily: limits.daily_budget,
          limit_tx: limits.tx_limit,
        }).catch(err => console.log('[TG] Budget notification failed:', err));

        throw new VaultError(errorCode, budgetResult.reason || 'Budget exceeded', {
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
        });
      }

      if (budgetResult.requires_approval) {
        const { consent, isNew } = storage.createPendingConsent(
          agent_name,
          'sign_x402',
          walletScope,
          JSON.stringify({
            amount: parsedAmount,
            currency,
            network,
            recipient,
            purpose,
          })
        );

        // Telegram notification handled by consent watcher (avoids duplicates)

        return {
          requires_consent: true,
          consent_id: consent.id,
          expires_at: consent.expires_at,
          reason: 'Amount exceeds approval threshold',
          message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
        };
      } else {
        // Amount is under approval threshold - auto-approve
        budgetAutoApproved = true;
        storage.logAudit('EXECUTE', 'success', {
          agentName: agent_name,
          scope: walletScope,
          operation: 'budget_auto_approve',
          details: JSON.stringify({ amount: parsedAmount, currency, chain, threshold: budget.getLimits(currency).approval_threshold }),
        });
      }
    }

    // Skip session check if budget auto-approved
    if (!hasSession && !budgetAutoApproved) {
      const { consent, isNew } = storage.createPendingConsent(
        agent_name,
        'sign_x402',
        walletScope,
        JSON.stringify({
          amount: parsedAmount,
          currency,
          network,
          recipient,
          purpose,
        })
      );

      // Telegram notification handled by consent watcher (avoids duplicates)

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const records = storage.listRecords();
    const walletRecord = records.find(
      (r) => r.item_type === 'WALLET_KEY' && r.chain === chain
    );
    if (!walletRecord || !walletRecord.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const masterKey = storage.getMasterKey();
    const encryptedKey = storage.getEncryptedPayload(walletScope);
    if (!encryptedKey) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const signature = signSolanaMessage(encryptedKey, masterKey, payload, 'base64');

    if (parsedAmount !== undefined && currency && effectiveSessionId) {
      storage.recordSpend(effectiveSessionId, parsedAmount, currency, chain, 'sign_x402', 'committed', {
        destination: recipient,
      });
    }

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_x402',
      details: JSON.stringify({
        amount: parsedAmount,
        currency,
        network,
        recipient,
        purpose,
      }),
    });

    return {
      signature,
      public_key: walletRecord.public_address,
      chain,
      session_id: effectiveSessionId,
    };
  });

  // ============================================================================
  // V1 API: Activity (Audit Events)
  // ============================================================================

  server.get<{
    Querystring: {
      limit?: string;
      agent?: string;
      type?: string;
      since?: string;
    };
  }>('/v1/vault/activity', async (request) => {
    const limit = parseInt(request.query.limit || '100', 10);
    const agentName = request.query.agent;
    const eventType = request.query.type?.toUpperCase() as AuditEventType | undefined;
    const since = request.query.since ? new Date(request.query.since) : undefined;

    // Validate event type
    if (eventType && !['GRANT', 'DENY', 'EXECUTE', 'READ', 'REVOKE', 'CONFIG', 'EXPIRE'].includes(eventType)) {
      throw new VaultError('INTERNAL_ERROR', `Invalid event type: ${request.query.type}`);
    }

    const events = storage.getAuditEvents(limit, {
      eventType,
      agentName,
      since,
    });

    return {
      events: events.map((e) => ({
        id: e.id,
        event_type: e.event_type,
        agent_name: e.agent_name,
        scope: e.scope,
        operation: e.operation,
        outcome: e.outcome,
        created_at: e.created_at,
        details: e.details ? (() => {
          try {
            return JSON.parse(e.details);
          } catch {
            return e.details;
          }
        })() : undefined,
      })),
      count: events.length,
    };
  });

  // ============================================================================
  // V1 API: Revoke Specific Session
  // ============================================================================

  server.post<{ Params: { id: string } }>('/v1/vault/agents/:id/revoke', async (request) => {
    const { id } = request.params;

    const session = storage.getSession(id);
    if (!session) {
      throw new VaultError('INTERNAL_ERROR', `Session not found: ${id}`);
    }

    const success = storage.revokeSession(id);

    if (success) {
      storage.logAudit('REVOKE', 'success', {
        agentName: session.agent_name,
        operation: 'revoke_session',
        details: JSON.stringify({ session_id: id }),
      });
    }

    return {
      revoked: success,
      session_id: id,
      agent_name: session.agent_name,
    };
  });

  // ============================================================================
  // V1 API: Telegram Notifications (protocol spec section 15)
  // ============================================================================

  /**
   * Start Telegram pairing - call cloud service to generate code
   * User then sends this code to the cloud bot to complete pairing
   * protocol spec: Desktop creates signed pairing start request
   */
  server.post('/v1/telegram/pair/start', async (request, reply) => {
    requireOwnerToken(request);

    // Get vault identity for signing (protocol spec)
    const identity = await ensureRelayIdentity();
    const vaultId = identity.vaultId;

    try {
      // First register the vault's public key with Telegram service
      const publicKeyBase64 = identity.signingKeyPair.publicKey.toString('base64');
      const regResponse = await fetch(`${TELEGRAM_CLOUD_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vault_id: vaultId,
          public_key: publicKeyBase64,
        }),
      });

      if (!regResponse.ok) {
        const error = await regResponse.json() as { error?: string; message?: string };
        console.error('[TG] Failed to register vault key:', error);
        // Continue anyway - might already be registered
      }

      // Build signed pairing request (protocol spec)
      const timestamp = new Date().toISOString();
      const nonce = crypto.randomBytes(16).toString('base64');
      const payloadWithoutSig = { vault_id: vaultId, timestamp, nonce };

      const message = Buffer.from(canonicalJson(payloadWithoutSig), 'utf8');
      const signatureBytes = nacl.sign.detached(
        new Uint8Array(message),
        new Uint8Array(identity.signingKeyPair.privateKey)
      );
      const signature = Buffer.from(signatureBytes).toString('base64');

      // Call cloud service to create pairing code
      const response = await fetch(`${TELEGRAM_CLOUD_URL}/api/pair/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...payloadWithoutSig, signature }),
      });

      if (!response.ok) {
        const error = await response.json() as { error?: string; message?: string };
        throw new VaultError('INTERNAL_ERROR', error.message || 'Failed to start pairing');
      }

      const data = await response.json() as { code: string; expires_at: string };

      // Also store locally that we're attempting to pair
      const existingConfig = storage.getTelegramConfig();
      if (!existingConfig) {
        // Create a placeholder config (will be updated when pairing completes)
        storage.createTelegramConfig({
          chat_id: 'pending',
          bot_token: 'cloud', // Indicates cloud mode
          enabled: false, // Will be enabled when pairing completes
          notify_consent: true,
        });
      }

      return {
        code: data.code,
        expires_at: data.expires_at,
        message: `Send /pair ${data.code} to the DCP Telegram bot`,
      };
    } catch (err) {
      if (err instanceof VaultError) throw err;
      console.error('[TG] Cloud pairing start failed:', err);
      throw new VaultError('INTERNAL_ERROR', 'Failed to connect to Telegram service');
    }
  });

  /**
   * Check Telegram pairing status from cloud
   */
  server.get('/v1/telegram/pair/status', async (request, reply) => {
    requireOwnerToken(request);

    const identity = await ensureRelayIdentity();
    const vaultId = identity.vaultId;

    try {
      const response = await fetch(`${TELEGRAM_CLOUD_URL}/api/pair/status/${vaultId}`);
      const data = await response.json() as {
        paired: boolean;
        chat_id?: string;
        paired_at?: string;
        enabled?: boolean;
      };

      if (data.paired) {
        // Update local config to mark as paired and enabled
        const config = storage.getTelegramConfig();
        if (config && (!config.enabled || !config.paired_at)) {
          const updates: Partial<TelegramConfig> = {
            chat_id: data.chat_id || config.chat_id,
            enabled: true,
            paired_at: data.paired_at || new Date().toISOString(),
          };
          storage.updateTelegramConfig(updates);
        }
      }

      return data;
    } catch (err) {
      console.error('[TG] Cloud pairing status check failed:', err);
      return { paired: false, error: 'Failed to check pairing status' };
    }
  });

  /**
   * Get Telegram configuration (without sensitive bot token)
   */
  server.get('/v1/telegram/config', async (request, reply) => {
    requireOwnerToken(request);

    const config = storage.getTelegramConfig();
    if (!config) {
      return { configured: false };
    }

    return {
      configured: true,
      chat_id: config.chat_id,
      enabled: config.enabled,
      notify_consent: config.notify_consent,
      rate_limit_per_hour: config.rate_limit_per_hour,
      notifications_this_hour: config.notifications_this_hour,
      last_notification_at: config.last_notification_at,
      muted_until: config.muted_until,
      paired_at: config.paired_at,
    };
  });

  /**
   * Update Telegram configuration
   */
  server.post<{
    Body: {
      enabled?: boolean;
      notify_consent?: boolean;
      rate_limit_per_hour?: number;
      muted_until?: string;
    };
  }>('/v1/telegram/config', async (request, reply) => {
    requireOwnerToken(request);

    const config = storage.getTelegramConfig();
    if (!config) {
      throw new VaultError('INTERNAL_ERROR', 'Telegram not configured');
    }

    const { enabled, notify_consent, rate_limit_per_hour, muted_until } = request.body;

    const success = storage.updateTelegramConfig({
      enabled,
      notify_consent,
      rate_limit_per_hour,
      muted_until,
    });

    return { success };
  });

  /**
   * Delete Telegram configuration (unlink)
   */
  server.delete('/v1/telegram/config', async (request, reply) => {
    requireOwnerToken(request);

    // Also notify cloud service to delete pairing
    const identity = await ensureRelayIdentity();
    const vaultId = identity.vaultId;
    try {
      await fetch(`${TELEGRAM_CLOUD_URL}/api/pair/${vaultId}`, {
        method: 'DELETE',
      });
    } catch (err) {
      // Ignore cloud errors - still delete local config
      console.error('[TELEGRAM] Failed to notify cloud of unlink:', err);
    }

    const success = storage.deleteTelegramConfig();
    return { success };
  });

  /**
   * Send test notification to Telegram (via cloud service - Option B)
   */
  server.post('/v1/telegram/test', async (request, reply) => {
    requireOwnerToken(request);

    const config = storage.getTelegramConfig();
    if (!config) {
      throw new VaultError('INTERNAL_ERROR', 'Telegram not configured');
    }

    if (!config.enabled) {
      throw new VaultError('INTERNAL_ERROR', 'Telegram notifications are disabled');
    }

    // Check rate limit
    if (storage.checkTelegramRateLimit()) {
      throw new VaultError('RATE_LIMITED', 'Telegram notification rate limit exceeded');
    }

    // Send test via cloud service (Option B architecture)
    // protocol spec: Include vault_id, timestamp, nonce, signature
    const webhookUrl = `${TELEGRAM_CLOUD_URL}/webhook/consent`;
    const identity = await ensureRelayIdentity();
    const vaultId = identity.vaultId;

    // Ensure vault key is registered with telegram service (survives telegram restarts)
    const publicKeyBase64 = identity.signingKeyPair.publicKey.toString('base64');
    try {
      await fetch(`${TELEGRAM_CLOUD_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vault_id: vaultId, public_key: publicKeyBase64 }),
      });
    } catch {
      // Ignore registration errors - telegram service might be down
    }

    const nonce = crypto.randomBytes(16).toString('base64');

    const payloadWithoutSig = {
      vault_id: vaultId,
      event: 'test' as const,
      data: { consent_id: 'test', agent_name: 'test', action: 'test', scope: 'test' },
      timestamp: new Date().toISOString(),
      nonce,
    };

    // Sign the payload
    const message = Buffer.from(canonicalJson(payloadWithoutSig), 'utf8');
    const signatureBytes = nacl.sign.detached(
      new Uint8Array(message),
      new Uint8Array(identity.signingKeyPair.privateKey)
    );
    const signature = Buffer.from(signatureBytes).toString('base64');

    const payload = {
      ...payloadWithoutSig,
      signature,
    };

    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || response.statusText);
      }

      const result = await response.json() as { sent?: boolean; error?: string };

      if (!result.sent) {
        throw new Error(result.error || 'Cloud service failed to send');
      }

      // Record notification
      storage.recordTelegramNotification();
      storage.logTelegramNotification({
        chat_id: config.chat_id,
        notification_type: 'test',
      });

      return { success: true, message: 'Test notification sent' };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      storage.logTelegramNotification({
        chat_id: config.chat_id,
        notification_type: 'test',
        error: errorMessage,
      });
      throw new VaultError('INTERNAL_ERROR', `Failed to send test notification: ${errorMessage}`);
    }
  });

  /**
   * Get Telegram notification logs
   */
  server.get<{
    Querystring: { limit?: string };
  }>('/v1/telegram/logs', async (request, reply) => {
    requireOwnerToken(request);

    const limit = parseInt(request.query.limit || '50', 10);
    const logs = storage.getTelegramNotificationLogs(limit);

    return { logs, count: logs.length };
  });

  return server;
}

// ============================================================================
// Helpers
// ============================================================================

function getChainForCurrency(currency: string, chain?: Chain): Chain {
  if (chain) return chain;
  switch (currency.toUpperCase()) {
    case 'SOL':
      return 'solana';
    case 'USDC':
    case 'USDT':
      throw new VaultError('INTERNAL_ERROR', `chain is required for ${currency}`);
    default:
      throw new VaultError('INTERNAL_ERROR', `Unknown currency: ${currency}`);
  }
}

// ============================================================================
// Service Signature Verification (protocol spec section B2)
// ============================================================================

/**
 * Verify a service's Ed25519 signature on a relay request payload
 *
 * The service signs the payload (minus the signature field) to prove identity.
 * The vault verifies this signature using the trusted service's public key.
 *
 * @param payload - Decrypted relay payload
 * @param serviceId - Service identifier
 * @param signature - Base64-encoded Ed25519 signature
 * @param publicKey - Service's Ed25519 public key (base64 or ed25519:xxx format)
 * @returns true if signature is valid
 */
function verifyServiceSignature(
  payload: Record<string, unknown>,
  serviceId: string,
  signature: string,
  publicKey: string
): boolean {
  // Extract the raw public key
  let keyData: string;
  if (publicKey.startsWith('ed25519:')) {
    keyData = publicKey.slice(8);
  } else {
    keyData = publicKey;
  }

  const publicKeyBytes = Buffer.from(keyData, 'base64');
  if (publicKeyBytes.length !== 32) {
    return false;
  }

  // Create the message to verify (payload without signature)
  const payloadWithoutSig = { ...payload };
  delete payloadWithoutSig.service_signature;
  const message = Buffer.from(canonicalJson(payloadWithoutSig), 'utf8');

  // Verify using nacl (canonical JSON)
  const signatureBytes = Buffer.from(signature, 'base64');
  const canonicalOk = nacl.sign.detached.verify(
    new Uint8Array(message),
    new Uint8Array(signatureBytes),
    new Uint8Array(publicKeyBytes)
  );

  if (canonicalOk) return true;

  // Backward compatibility: legacy JSON.stringify ordering
  const legacyMessage = Buffer.from(JSON.stringify(payloadWithoutSig), 'utf8');
  return nacl.sign.detached.verify(
    new Uint8Array(legacyMessage),
    new Uint8Array(signatureBytes),
    new Uint8Array(publicKeyBytes)
  );
}

function normalizeScopes(scopes: string[] | string | undefined): string[] {
  if (!scopes) return [];
  if (Array.isArray(scopes)) {
    return scopes.map((s) => s.trim()).filter((s) => s.length > 0);
  }
  return scopes
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function normalizeBudget(input?: { daily?: number; currency?: string; auto_approve_under?: number }): {
  daily: number;
  currency: string;
  auto_approve_under: number;
} {
  const daily = typeof input?.daily === 'number' && !Number.isNaN(input.daily)
    ? input.daily
    : 10;
  const currency = (input?.currency || 'USDC').toUpperCase();
  const autoApprove = typeof input?.auto_approve_under === 'number' && !Number.isNaN(input.auto_approve_under)
    ? input.auto_approve_under
    : 0;

  return {
    daily,
    currency,
    auto_approve_under: autoApprove,
  };
}

/**
 * Check if a relay request is from a trusted service and has proper authorization
 *
 * @param serviceId - Service identifier from the request
 * @param signature - Service signature
 * @param payload - Decrypted payload for signature verification
 * @param requestedScope - The scope being requested (e.g., 'crypto.wallet.solana')
 * @returns { authorized: true, service } or { authorized: false, reason }
 */
function verifyServiceAuthorization(
  serviceId: string | undefined,
  signature: string | undefined,
  payload: Record<string, unknown>,
  requestedScope: string
): { authorized: boolean; service?: TrustedService; reason?: string } {
  // If no service_id, this might be a local request (no service verification needed)
  if (!serviceId) {
    return { authorized: true };
  }

  // Look up the trusted service OR agent connection
  let service = storage.getTrustedService(serviceId);
  let isAgent = false;

  // If not found in trusted_services, check agent_connections (protocol spec section 7 flow)
  // Accept both 'agent_' (local) and 'vps_' (remote VPS) prefixes
  if (!service && (serviceId.startsWith('agent_') || serviceId.startsWith('vps_'))) {
    const agent = storage.getAgentConnection(serviceId);
    if (agent && agent.status === 'active' && agent.service_public_key) {
      // Convert agent to TrustedService-like structure for auth
      service = {
        service_id: agent.agent_id,
        name: agent.name,
        public_key: agent.service_public_key,
        scopes: agent.permission_scopes,
        budget: agent.budget,
        verified: true,
        trusted_at: agent.paired_at || agent.created_at,
        enabled: true,
      };
      isAgent = true;
    }
  }

  if (!service) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'service_not_trusted' }),
    });
    return { authorized: false, reason: `Service '${serviceId}' is not trusted` };
  }

  if (!service.enabled) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'service_disabled' }),
    });
    return { authorized: false, reason: `Service '${serviceId}' is disabled` };
  }

  // Verify signature
  if (!signature) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'missing_signature' }),
    });
    return { authorized: false, reason: 'Service signature required' };
  }

  const signatureValid = verifyServiceSignature(payload, serviceId, signature, service.public_key);
  if (!signatureValid) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'invalid_signature' }),
    });
    return { authorized: false, reason: 'Invalid service signature' };
  }

  // Check scope authorization
  // For agents, an empty scope list means request-only mode: the agent may ask,
  // but downstream vault endpoints still create a normal consent request.
  if (isAgent) {
    if (service.scopes.length === 0) {
      storage.recordAgentRequest(serviceId);
      return { authorized: true, service };
    }

    const hasScope = service.scopes.some((s: string) => {
      if (s === '*') return true;
      if (s === requestedScope) return true;
      // Handle wildcard patterns like 'read:identity.*' matching 'read:identity.email'
      if (s.endsWith('.*')) {
        const prefix = s.slice(0, -1); // 'read:identity.'
        return requestedScope.startsWith(prefix);
      }
      // Handle simple prefix like 'sign:*' matching 'sign:solana'
      if (s.endsWith(':*')) {
        const prefix = s.slice(0, -1); // 'sign:'
        return requestedScope.startsWith(prefix);
      }
      return false;
    });
    if (!hasScope) {
      storage.logAudit('DENY', 'denied', {
        operation: 'relay_request',
        details: JSON.stringify({ service_id: serviceId, scope: requestedScope, reason: 'scope_not_permitted' }),
      });
      return { authorized: false, service, reason: `Scope '${requestedScope}' not permitted for this agent` };
    }
    // Update agent last_request_at
    storage.recordAgentRequest(serviceId);
    return { authorized: true, service };
  }

  // For trusted services, use existing scope check
  const scopeResult = storage.isServiceAuthorized(serviceId, requestedScope);
  if (!scopeResult.authorized) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, scope: requestedScope, reason: scopeResult.reason }),
    });
    return { authorized: false, service, reason: scopeResult.reason };
  }

  return { authorized: true, service };
}

/**
 * Verify a local agent request and check scope permissions.
 *
 * When an agent makes a local HTTP request (not via relay), it should include:
 * - service_id: The agent ID (e.g., "agent_xxx")
 * - service_signature: Ed25519 signature of the request body
 * - timestamp: ISO timestamp for replay protection
 * - nonce: Unique request ID
 *
 * This function verifies the signature and checks if the requested scope
 * is within the agent's permission_scopes. If out of scope, the request
 * is denied immediately (no consent flow).
 *
 * @param body - The request body (must include service_id, service_signature, etc.)
 * @param requestedScope - The scope being requested (e.g., "read:identity.email")
 * @returns Authorization result with agent info or denial reason
 */
function verifyLocalAgentRequest(
  body: Record<string, unknown>,
  requestedScope: string
): {
  authorized: boolean;
  agent?: AgentConnection;
  reason?: string;
  skipConsentFlow?: boolean;
  preAuthorized?: boolean;
} {
  const serviceId = body.service_id as string | undefined;
  const serviceSignature = body.service_signature as string | undefined;
  const timestamp = body.timestamp as string | undefined;

  // If no service_id, this is an unsigned request (desktop app, MCP, etc.)
  // Allow it through to the normal consent flow
  if (!serviceId) {
    return { authorized: true };
  }

  // Only handle agent_ and vps_ prefixed IDs
  if (!serviceId.startsWith('agent_') && !serviceId.startsWith('vps_')) {
    return { authorized: true };
  }

  // Look up the agent
  const agent = storage.getAgentConnection(serviceId);
  if (!agent) {
    storage.logAudit('DENY', 'denied', {
      operation: 'local_agent_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'agent_not_found' }),
    });
    return { authorized: false, reason: `Agent '${serviceId}' not found`, skipConsentFlow: true };
  }

  if (agent.status !== 'active') {
    storage.logAudit('DENY', 'denied', {
      operation: 'local_agent_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'agent_not_active', status: agent.status }),
    });
    return { authorized: false, reason: `Agent '${serviceId}' is not active (status: ${agent.status})`, skipConsentFlow: true };
  }

  if (!agent.service_public_key) {
    storage.logAudit('DENY', 'denied', {
      operation: 'local_agent_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'no_public_key' }),
    });
    return { authorized: false, reason: `Agent '${serviceId}' has no registered public key`, skipConsentFlow: true };
  }

  // Verify signature if provided
  if (serviceSignature) {
    // Build the payload that was signed (everything except the signature)
    const { service_signature: _, ...payloadWithoutSig } = body;

    const signatureValid = verifyServiceSignature(
      payloadWithoutSig,
      serviceId,
      serviceSignature,
      agent.service_public_key
    );

    if (!signatureValid) {
      storage.logAudit('DENY', 'denied', {
        operation: 'local_agent_request',
        details: JSON.stringify({ service_id: serviceId, reason: 'invalid_signature' }),
      });
      return { authorized: false, reason: 'Invalid agent signature', skipConsentFlow: true };
    }

    // Check timestamp for replay protection (5 minute window)
    if (timestamp) {
      const requestTime = new Date(timestamp).getTime();
      const now = Date.now();
      const fiveMinutes = 5 * 60 * 1000;
      if (Math.abs(now - requestTime) > fiveMinutes) {
        storage.logAudit('DENY', 'denied', {
          operation: 'local_agent_request',
          details: JSON.stringify({ service_id: serviceId, reason: 'timestamp_expired' }),
        });
        return { authorized: false, reason: 'Request timestamp expired', skipConsentFlow: true };
      }
    }
  }

  // Check scope permissions. Empty permissions are request-only: authenticated,
  // but not pre-authorized, so the normal consent flow must run.
  // Normalize scopes to handle old data saved without read:/sign: prefix
  const normalizedScopes = normalizePermissionScopes(agent.permission_scopes || []);

  if (normalizedScopes.length === 0) {
    storage.recordAgentRequest(serviceId);
    return { authorized: true, agent, preAuthorized: false };
  }

  const hasScope = normalizedScopes.some((s: string) => {
    if (s === '*') return true;
    if (s === requestedScope) return true;

    // Handle wildcard patterns like 'read:identity.*' matching 'read:identity.email'
    if (s.endsWith('.*')) {
      const prefix = s.slice(0, -1); // 'read:identity.'
      return requestedScope.startsWith(prefix);
    }

    // Handle simple prefix like 'read:*' matching 'read:identity.email'
    if (s.endsWith(':*')) {
      const prefix = s.slice(0, -1); // 'read:'
      return requestedScope.startsWith(prefix);
    }

    return false;
  });

  if (!hasScope) {
    storage.logAudit('DENY', 'denied', {
      operation: 'local_agent_request',
      details: JSON.stringify({
        service_id: serviceId,
        scope: requestedScope,
        permitted_scopes: normalizedScopes,
        reason: 'scope_not_permitted',
      }),
    });
    // This is the key: skipConsentFlow=true means immediate denial, no consent popup
    return {
      authorized: false,
      agent,
      reason: `Scope '${requestedScope}' is not permitted for agent '${agent.name}'. Permitted scopes: ${normalizedScopes.join(', ')}`,
      skipConsentFlow: true,
    };
  }

  // Update agent last_seen
  storage.recordAgentRequest(serviceId);

  return { authorized: true, agent, preAuthorized: true };
}

/**
 * Get the scope for a relay method
 */
function getScopeForRelayMethod(method: string, params: Record<string, unknown>): string {
  switch (method) {
    case 'get_address':
    case 'vault_get_address':
      return `sign:${params.chain || 'solana'}`;
    case 'vault_read':
      return `read:${params.scope || ''}`;
    case 'vault_write':
      return `write:${params.scope || ''}`;
    case 'vault_sign':
      return `sign:${params.chain || 'solana'}`;
    case 'vault_sign_message':
      return `sign:${params.chain || 'solana'}`;
    case 'vault_sign_x402':
      return `sign:${params.network || 'solana'}`;
    case 'vault_pair':
      return 'config:pair';
    case 'budget_check':
      return `budget:check`;
    default:
      return '';
  }
}

// ============================================================================
// Relay Helpers
// ============================================================================

interface RelayIdentity {
  vaultId: string;
  relayUrl: string;
  hpkeKeyPair: HpkeKeyPair;
  signingKeyPair: SigningKeyPair;
  pairingToken?: string;
}

function decodeKey(base64: string | undefined, expectedLength: number): Buffer | null {
  if (!base64) return null;
  try {
    const buf = Buffer.from(base64, 'base64');
    if (buf.length !== expectedLength) return null;
    return buf;
  } catch {
    return null;
  }
}

function relayHttpUrl(relayUrl: string): string {
  let url = relayUrl.trim();
  if (url.startsWith('wss://')) {
    url = `https://${url.slice('wss://'.length)}`;
  } else if (url.startsWith('ws://')) {
    url = `http://${url.slice('ws://'.length)}`;
  }
  return url.replace(/\/ws\/?$/, '').replace(/\/$/, '');
}

async function registerVpsInviteWithRelay(
  relayUrl: string,
  inviteId: string,
  vaultId: string
): Promise<void> {
  const response = await fetch(`${relayHttpUrl(relayUrl)}/v1/invites/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ invite_id: inviteId, vault_id: vaultId }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Relay invite registration failed: ${response.status}${body ? ` ${body}` : ''}`);
  }
}

async function ensureRelayIdentity(): Promise<RelayIdentity> {
  const config = budget.getConfig();
  let vaultId = config.vault_id;
  if (!vaultId) {
    vaultId = `vault_${crypto.randomUUID()}`;
    budget.setConfig('vault_id', vaultId);
  }

  // Relay URL (env > saved config > core default)
  const effectiveDefault = DEFAULT_RELAY_URL || CORE_DEFAULT_RELAY_URL;
  let relayUrl = config.relay_url || '';
  if (!relayUrl && effectiveDefault) {
    relayUrl = effectiveDefault;
    budget.setConfig('relay_url', relayUrl);
  } else if (DEFAULT_RELAY_URL && DEFAULT_RELAY_URL !== relayUrl) {
    // Env override takes precedence over saved config
    relayUrl = DEFAULT_RELAY_URL;
    budget.setConfig('relay_url', relayUrl);
  }

  let hpkePublic = decodeKey(config.relay_hpke_public_key, 32);
  let hpkePrivate = decodeKey(config.relay_hpke_private_key, 32);
  if (!hpkePublic || !hpkePrivate) {
    const keyPair = await generateKeyPair();
    hpkePublic = keyPair.publicKey;
    hpkePrivate = keyPair.privateKey;
    budget.setConfig('relay_hpke_public_key', hpkePublic.toString('base64'));
    budget.setConfig('relay_hpke_private_key', hpkePrivate.toString('base64'));
  }

  let signingPublic = decodeKey(config.relay_signing_public_key, 32);
  let signingPrivate = decodeKey(config.relay_signing_private_key, 64);
  if (!signingPublic || !signingPrivate) {
    const signing = generateSigningKeyPair();
    signingPublic = signing.publicKey;
    signingPrivate = signing.privateKey;
    budget.setConfig('relay_signing_public_key', signingPublic.toString('base64'));
    budget.setConfig('relay_signing_private_key', signingPrivate.toString('base64'));
  }

  return {
    vaultId,
    relayUrl,
    hpkeKeyPair: { publicKey: hpkePublic, privateKey: hpkePrivate },
    signingKeyPair: { publicKey: signingPublic, privateKey: signingPrivate },
    pairingToken: config.relay_pairing_token,
  };
}

async function handleRelayRequest(
  server: FastifyInstance,
  decryptedPayload: Buffer,
  meta: { request_id: string; action_type: string; vault_id: string; version: string }
): Promise<{ response: string; replyPublicKey: Buffer }> {
  let parsed: {
    method?: string;
    params?: Record<string, unknown>;
    agent_name?: string;
    session_id?: string;
    reply_public_key?: string;
    service_id?: string;
    service_signature?: string;
    timestamp?: string;
    nonce?: string;
  };

  try {
    parsed = JSON.parse(decryptedPayload.toString());
  } catch {
    throw new Error('Invalid relay payload: not JSON');
  }

  if (!parsed.reply_public_key) {
    throw new Error('Invalid relay payload: missing reply_public_key');
  }

  const replyPublicKey = Buffer.from(parsed.reply_public_key, 'base64');
  const method = parsed.method;
  if (!method) {
    throw new Error('Invalid relay payload: missing method');
  }

  if (method === 'vault_pair') {
    const params = (parsed.params || {}) as {
      pairing_token?: string;
      service_public_key?: string;
      service_name?: string;
    };
    const pairingToken = params.pairing_token;
    const serviceId = parsed.service_id;
    const servicePublicKey = params.service_public_key;

    if (!pairingToken || !serviceId || !servicePublicKey) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'pairing_token, service_id, and service_public_key are required',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    const tokenRecord = storage.getPairingToken(pairingToken);
    if (!tokenRecord) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'Pairing token is invalid or expired',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    if (tokenRecord.service_id !== serviceId) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'Pairing token does not match service_id',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    if (!parsed.service_signature) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'service_signature is required for pairing',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    const signatureValid = verifyServiceSignature(
      parsed as Record<string, unknown>,
      serviceId,
      parsed.service_signature,
      servicePublicKey
    );

    if (!signatureValid) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'Invalid service signature',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    const serviceName = params.service_name || serviceId;

    const existing = storage.getTrustedService(serviceId);
    if (existing) {
      storage.updateTrustedService(serviceId, {
        name: serviceName,
        public_key: servicePublicKey,
        scopes: tokenRecord.scopes,
        budget: tokenRecord.budget,
        enabled: true,
      });
    } else {
      storage.addTrustedService({
        service_id: serviceId,
        name: serviceName,
        public_key: servicePublicKey,
        scopes: tokenRecord.scopes,
        budget: tokenRecord.budget,
        verified: false,
      });
    }

    storage.markServiceConnected(serviceId);
    storage.markPairingTokenUsed(pairingToken);

    const okResponse = JSON.stringify({
      ok: true,
      service_id: serviceId,
    });
    return { response: okResponse, replyPublicKey };
  }

  // Get the scope for this method to check authorization
  const requestedScope = getScopeForRelayMethod(method, parsed.params || {});

  // Verify service authorization (protocol spec section B2)
  // Relay requests must include service_id + signature
  if (!parsed.service_id) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ reason: 'missing_service_id', method }),
    });
    const errorResponse = JSON.stringify({
      ok: false,
      error: {
        code: 'VAULT_UNTRUSTED_SERVICE',
        message: 'service_id is required for relay requests',
        action: 'trust_service',
      },
    });
    return { response: errorResponse, replyPublicKey };
  }

  const authResult = verifyServiceAuthorization(
    parsed.service_id,
    parsed.service_signature,
    parsed as Record<string, unknown>,
    requestedScope
  );

  if (!authResult.authorized) {
    // Return error response
    const errorResponse = JSON.stringify({
      ok: false,
      error: {
        code: 'VAULT_UNTRUSTED_SERVICE',
        message: authResult.reason || 'Service not authorized',
        action: 'trust_service',
      },
    });
    return { response: errorResponse, replyPublicKey };
  }

  // Service is authorized - log successful verification
  storage.logAudit('EXECUTE', 'success', {
    operation: 'service_verify',
    details: JSON.stringify({
      service_id: parsed.service_id,
      method,
      scope: requestedScope,
    }),
  });

  const body: Record<string, unknown> = {
    ...(parsed.params || {}),
  };
  if (parsed.agent_name) body.agent_name = parsed.agent_name;
  if (parsed.session_id) body.session_id = parsed.session_id;

  let url = '';
  let httpMethod: 'POST' | 'GET' = 'POST';

  switch (method) {
    case 'get_address':
    case 'vault_get_address': {
      const chain = (body.chain as string | undefined) || 'solana';
      httpMethod = 'GET';
      url = `/address/${chain}`;
      break;
    }
    case 'vault_read':
      url = '/v1/vault/read';
      break;
    case 'vault_write':
      url = '/v1/vault/write';
      break;
    case 'vault_sign':
      url = '/v1/vault/sign';
      break;
    case 'vault_sign_message':
      url = '/v1/vault/sign_message';
      break;
    case 'vault_sign_x402':
      url = '/v1/vault/sign_x402';
      break;
    case 'budget_check':
      httpMethod = 'GET';
      url = `/budget/check?amount=${body.amount ?? ''}&currency=${body.currency ?? ''}&chain=${body.chain ?? ''}`;
      break;
    default:
      throw new Error(`Unknown relay method: ${method}`);
  }

  console.log('[RELAY] Calling endpoint:', httpMethod, url, 'body:', JSON.stringify(body).substring(0, 200));

  const response = await server.inject({
    method: httpMethod,
    url,
    payload: httpMethod === 'POST' ? JSON.stringify(body) : undefined,
    headers: { 'content-type': 'application/json' },
  });

  console.log('[RELAY] Response:', response.statusCode, response.payload?.substring(0, 200));

  return { response: response.payload || '', replyPublicKey };
}

async function startRelayClient(server: FastifyInstance): Promise<void> {
  const identity = await ensureRelayIdentity();

  if (!identity.relayUrl) {
    return;
  }

  if (relayClient) {
    relayClient.destroy();
    relayClient = null;
    relayConnected = false;
  }

  relayClient = new RelayClient({
    relayUrl: identity.relayUrl,
    vaultId: identity.vaultId,
    keyPair: identity.hpkeKeyPair,
    signingKeyPair: identity.signingKeyPair,
    pairingToken: identity.pairingToken,
    autoReconnect: true,
    debug: false,
  });

  relayClient.on('connected', () => {
    relayConnected = true;
  });
  relayClient.on('disconnected', () => {
    relayConnected = false;
  });
  relayClient.on('error', () => {
    // Relay client errors are not always fatal. The websocket can remain open
    // while a request-level or transient transport error is reported. Only mark
    // the relay disconnected when the client is actually no longer connected.
    relayConnected = relayClient?.isConnected() ?? false;
  });

  // Handle pairing claims from VPS agents via relay
  relayClient.on('pairingClaim', (rawClaim: unknown) => {
    const claim = rawClaim as StoredPairingClaim;
    console.log(`[Vault] Received pairing claim: ${claim.claim_id} from ${claim.claim.agent_hostname}`);
    console.log(`[Vault] Verification phrase: ${claim.verification_phrase}`);
    // Store pending claim for Desktop approval
    pendingPairingClaims.set(claim.claim_id, claim);
  });

  let pendingEnvelope: { request_id: string; action_type: string; vault_id: string; version: string } | null = null;
  relayClient.on('request', (rawEnvelope: unknown) => {
    const envelope = rawEnvelope as { request_id: string; action_type: string; vault_id: string; version: string };
    pendingEnvelope = {
      request_id: envelope.request_id,
      action_type: envelope.action_type,
      vault_id: envelope.vault_id,
      version: envelope.version,
    };
  });

  relayClient.setRequestHandler(async (action: string, decryptedPayload: Buffer) => {
    const meta = pendingEnvelope || {
      request_id: '',
      action_type: action,
      vault_id: identity.vaultId,
      version: '1',
    };
    pendingEnvelope = null;
    const { response, replyPublicKey } = await handleRelayRequest(server, decryptedPayload, {
      request_id: meta.request_id,
      action_type: meta.action_type || action,
      vault_id: meta.vault_id || identity.vaultId,
      version: meta.version || '1',
    });
    return { payload: Buffer.from(response), recipientPublicKey: replyPublicKey };
  });

  await relayClient.connect();
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  const port = parseInt(process.env.VAULT_PORT || String(DEFAULT_PORT), 10);

  const server = await buildServer();

  try {
    await server.listen({ port, host: HOST });
    server.log.info(`DCP Vault REST Server running at http://${HOST}:${port}`);
    server.log.info('SECURITY: Bound to localhost only');
    // Only start relay client if vault is initialized
    if (await storage.isProvisioned()) {
      try {
        await startRelayClient(server);
        if (relayConnected) {
          server.log.info('Relay client connected');
        } else {
          server.log.info('Relay client not connected (no relay_url configured)');
        }
      } catch (err) {
        server.log.error(err);
        server.log.error('Relay client failed to start');
      }
    } else {
      server.log.info('Vault not initialized - relay client will start after vault setup');
    }

    // Start consent watcher for Telegram notifications (works for all MCP clients)
    startConsentWatcher();
    server.log.info('Consent watcher started for Telegram notifications');
    startRemoteApprovalWatcher();
    server.log.info('Remote Telegram approval watcher started');
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGINT', () => {
  process.stderr.write('Shutting down...\n');
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.stderr.write('Shutting down...\n');
  process.exit(0);
});

// Export for testing
export { buildServer };

// Start server if run directly (skip during tests)
if (process.env.VITEST !== 'true' && process.env.NODE_ENV !== 'test') {
  main();
}
