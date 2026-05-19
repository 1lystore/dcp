/**
 * Message Store for DCP Relay
 *
 * Handles:
 * - Message storage with TTL (5 minutes)
 * - Idempotency by request_id
 * - Vault connection tracking
 * - Message delivery tracking
 *
 * From protocol spec section 4.1:
 * - Message TTL: 5 minutes
 * - Idempotency by request_id
 */

import type {
  RelayEnvelope,
  RelayResponseEnvelope,
  StoredMessage,
  VaultConnection,
  RelayConfig,
  PairingClaim,
  StoredPairingClaim,
  MobilePairingApprovalRequest,
  MobilePairingRecord,
} from './types.js';
import { RelayError, MESSAGE_TTL_MS } from './types.js';
import { createHash, randomUUID } from 'node:crypto';

// ============================================================================
// Message Store
// ============================================================================

export class MessageStore {
  private messages: Map<string, StoredMessage> = new Map();
  private requestIdIndex: Map<string, string> = new Map(); // request_id -> message key
  private vaultMessages: Map<string, Set<string>> = new Map(); // vault_id -> message keys
  private config: RelayConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: Partial<RelayConfig> = {}) {
    this.config = {
      port: 8422, // Note: 8421 is used by vault, relay uses 8422
      host: '0.0.0.0',
      enableLongPoll: true,
      heartbeatIntervalMs: 30_000,
      messageTtlMs: config.messageTtlMs ?? MESSAGE_TTL_MS,
      maxPendingMessages: config.maxPendingMessages ?? 100,
      debug: config.debug ?? false,
      rateLimitPerMinute: config.rateLimitPerMinute ?? 60,
      rateLimitWindowMs: config.rateLimitWindowMs ?? 60_000,
    };

    // Start cleanup interval
    this.startCleanup();
  }

  // --------------------------------------------------------------------------
  // Message Operations
  // --------------------------------------------------------------------------

  /**
   * Store a new message
   * @throws RelayError if duplicate request_id
   */
  storeMessage(envelope: RelayEnvelope): void {
    const key = this.getMessageKey(envelope.vault_id, envelope.request_id);

    // Check for duplicate request_id (idempotency)
    if (this.requestIdIndex.has(envelope.request_id)) {
      throw new RelayError(
        'RELAY_DUPLICATE_REQUEST',
        `Duplicate request_id: ${envelope.request_id}`,
        { request_id: envelope.request_id }
      );
    }

    // Check message limit per vault
    const vaultMsgs = this.vaultMessages.get(envelope.vault_id);
    if (vaultMsgs && vaultMsgs.size >= this.config.maxPendingMessages) {
      // Remove oldest messages for this vault
      this.pruneVaultMessages(envelope.vault_id);
    }

    // Store message
    const stored: StoredMessage = {
      envelope,
      received_at: Date.now(),
      delivered: false,
    };
    this.messages.set(key, stored);
    this.requestIdIndex.set(envelope.request_id, key);

    // Track per-vault
    if (!this.vaultMessages.has(envelope.vault_id)) {
      this.vaultMessages.set(envelope.vault_id, new Set());
    }
    this.vaultMessages.get(envelope.vault_id)!.add(key);
  }

  /**
   * Get pending messages for a vault
   */
  getPendingMessages(vaultId: string): RelayEnvelope[] {
    const keys = this.vaultMessages.get(vaultId);
    if (!keys) return [];

    const messages: RelayEnvelope[] = [];
    const now = Date.now();

    for (const key of keys) {
      const stored = this.messages.get(key);
      if (!stored) continue;

      // Check if expired
      if (this.isExpired(stored, now)) {
        this.removeMessage(key, stored.envelope.request_id, vaultId);
        continue;
      }

      // Only return undelivered messages
      if (!stored.delivered) {
        messages.push(stored.envelope);
      }
    }

    return messages;
  }

  /**
   * Mark a message as delivered
   */
  markDelivered(requestId: string): boolean {
    const key = this.requestIdIndex.get(requestId);
    if (!key) return false;

    const stored = this.messages.get(key);
    if (!stored) return false;

    stored.delivered = true;
    return true;
  }

  /**
   * Store a response for a request
   */
  storeResponse(requestId: string, response: RelayResponseEnvelope): boolean {
    const key = this.requestIdIndex.get(requestId);
    if (!key) return false;

    const stored = this.messages.get(key);
    if (!stored) return false;

    stored.response = response;
    return true;
  }

  /**
   * Get response for a request (for idempotent replay)
   */
  getResponse(requestId: string): RelayResponseEnvelope | undefined {
    const key = this.requestIdIndex.get(requestId);
    if (!key) return undefined;

    const stored = this.messages.get(key);
    return stored?.response;
  }

  /**
   * Check if a request_id exists (for idempotency check)
   */
  hasRequest(requestId: string): boolean {
    return this.requestIdIndex.has(requestId);
  }

  /**
   * Get a stored message by request_id
   */
  getMessage(requestId: string): StoredMessage | undefined {
    const key = this.requestIdIndex.get(requestId);
    if (!key) return undefined;
    return this.messages.get(key);
  }

  // --------------------------------------------------------------------------
  // Cleanup Operations
  // --------------------------------------------------------------------------

  /**
   * Remove expired messages
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, stored] of this.messages) {
      if (this.isExpired(stored, now)) {
        this.removeMessage(key, stored.envelope.request_id, stored.envelope.vault_id);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Clear all messages for a vault
   */
  clearVault(vaultId: string): void {
    const keys = this.vaultMessages.get(vaultId);
    if (!keys) return;

    for (const key of keys) {
      const stored = this.messages.get(key);
      if (stored) {
        this.requestIdIndex.delete(stored.envelope.request_id);
        this.messages.delete(key);
      }
    }
    this.vaultMessages.delete(vaultId);
  }

  /**
   * Stop cleanup interval
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  // --------------------------------------------------------------------------
  // Stats
  // --------------------------------------------------------------------------

  getStats(): {
    totalMessages: number;
    pendingMessages: number;
    deliveredMessages: number;
    vaultCount: number;
  } {
    let pending = 0;
    let delivered = 0;

    for (const stored of this.messages.values()) {
      if (stored.delivered) {
        delivered++;
      } else {
        pending++;
      }
    }

    return {
      totalMessages: this.messages.size,
      pendingMessages: pending,
      deliveredMessages: delivered,
      vaultCount: this.vaultMessages.size,
    };
  }

  // --------------------------------------------------------------------------
  // Private Helpers
  // --------------------------------------------------------------------------

  private getMessageKey(vaultId: string, requestId: string): string {
    return `${vaultId}:${requestId}`;
  }

  private isExpired(stored: StoredMessage, now: number): boolean {
    // Check envelope expiry
    const expiresAt = new Date(stored.envelope.expires_at).getTime();
    if (now > expiresAt) return true;

    // Check TTL from receive time
    if (now - stored.received_at > this.config.messageTtlMs) return true;

    return false;
  }

  private removeMessage(key: string, requestId: string, vaultId: string): void {
    this.messages.delete(key);
    this.requestIdIndex.delete(requestId);
    this.vaultMessages.get(vaultId)?.delete(key);
  }

  private pruneVaultMessages(vaultId: string): void {
    const keys = this.vaultMessages.get(vaultId);
    if (!keys) return;

    // Convert to array and sort by received_at (oldest first)
    const sorted = Array.from(keys)
      .map((key) => ({ key, stored: this.messages.get(key) }))
      .filter((item) => item.stored !== undefined)
      .sort((a, b) => a.stored!.received_at - b.stored!.received_at);

    // Remove oldest 20% or at least 1
    const toRemove = Math.max(1, Math.floor(sorted.length * 0.2));
    for (let i = 0; i < toRemove; i++) {
      const item = sorted[i];
      if (item.stored) {
        this.removeMessage(item.key, item.stored.envelope.request_id, vaultId);
      }
    }
  }

  private startCleanup(): void {
    // Run cleanup every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60_000);
  }
}

// ============================================================================
// Connection Store
// ============================================================================

export class ConnectionStore {
  private connections: Map<string, VaultConnection> = new Map();

  /**
   * Register a vault connection
   */
  register(vaultId: string, publicKey: string, ws?: unknown): void {
    const conn: VaultConnection = {
      vault_id: vaultId,
      public_key: publicKey,
      connected_at: Date.now(),
      last_heartbeat: Date.now(),
      ws,
    };
    this.connections.set(vaultId, conn);
  }

  /**
   * Unregister a vault connection
   */
  unregister(vaultId: string): void {
    this.connections.delete(vaultId);
  }

  /**
   * Get a vault connection
   */
  get(vaultId: string): VaultConnection | undefined {
    return this.connections.get(vaultId);
  }

  /**
   * Check if a vault is connected
   */
  isConnected(vaultId: string): boolean {
    return this.connections.has(vaultId);
  }

  /**
   * Update heartbeat timestamp
   */
  updateHeartbeat(vaultId: string): boolean {
    const conn = this.connections.get(vaultId);
    if (!conn) return false;
    conn.last_heartbeat = Date.now();
    return true;
  }

  /**
   * Get all connected vault IDs
   */
  getConnectedVaults(): string[] {
    return Array.from(this.connections.keys());
  }

  /**
   * Remove stale connections (no heartbeat for 2x interval)
   */
  removeStale(heartbeatIntervalMs: number): string[] {
    const threshold = Date.now() - heartbeatIntervalMs * 2;
    const stale: string[] = [];

    for (const [vaultId, conn] of this.connections) {
      if (conn.last_heartbeat < threshold) {
        stale.push(vaultId);
        this.connections.delete(vaultId);
      }
    }

    return stale;
  }

  /**
   * Get stats
   */
  getStats(): { connectedVaults: number } {
    return { connectedVaults: this.connections.size };
  }
}

// ============================================================================
// Rate Limiter (protocol spec section C3: 60 req/min per vault)
// ============================================================================

interface RateLimitEntry {
  timestamps: number[];
  lastCleanup: number;
}

export class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map();
  private maxRequests: number;
  private windowMs: number;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(maxRequests: number = 60, windowMs: number = 60_000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;

    // Cleanup stale entries every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60_000);
  }

  /**
   * Check if a request is allowed for a vault_id
   * Returns true if allowed, false if rate limited
   */
  checkLimit(vaultId: string): boolean {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    let entry = this.limits.get(vaultId);

    if (!entry) {
      entry = { timestamps: [], lastCleanup: now };
      this.limits.set(vaultId, entry);
    }

    // Remove timestamps outside the window
    entry.timestamps = entry.timestamps.filter((ts) => ts > windowStart);
    entry.lastCleanup = now;

    // Check if under limit
    if (entry.timestamps.length >= this.maxRequests) {
      return false;
    }

    // Add current timestamp and allow
    entry.timestamps.push(now);
    return true;
  }

  /**
   * Get current request count for a vault_id in the window
   */
  getCount(vaultId: string): number {
    const entry = this.limits.get(vaultId);
    if (!entry) return 0;

    const windowStart = Date.now() - this.windowMs;
    return entry.timestamps.filter((ts) => ts > windowStart).length;
  }

  /**
   * Get remaining requests for a vault_id
   */
  getRemaining(vaultId: string): number {
    return Math.max(0, this.maxRequests - this.getCount(vaultId));
  }

  /**
   * Get time until rate limit resets (in ms)
   */
  getResetTime(vaultId: string): number {
    const entry = this.limits.get(vaultId);
    if (!entry || entry.timestamps.length === 0) return 0;

    const oldestTimestamp = Math.min(...entry.timestamps);
    const resetTime = oldestTimestamp + this.windowMs - Date.now();
    return Math.max(0, resetTime);
  }

  /**
   * Reset rate limit for a vault_id
   */
  reset(vaultId: string): void {
    this.limits.delete(vaultId);
  }

  /**
   * Cleanup entries not accessed in the last 10 minutes
   */
  cleanup(): number {
    const staleThreshold = Date.now() - 10 * 60_000;
    let removed = 0;

    for (const [vaultId, entry] of this.limits) {
      if (entry.lastCleanup < staleThreshold) {
        this.limits.delete(vaultId);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Get stats
   */
  getStats(): {
    trackedVaults: number;
    maxRequests: number;
    windowMs: number;
  } {
    return {
      trackedVaults: this.limits.size,
      maxRequests: this.maxRequests,
      windowMs: this.windowMs,
    };
  }

  /**
   * Stop cleanup interval
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// ============================================================================
// Pairing Claim Store (VPS → Relay → Vault flow)
// ============================================================================

/** Word list for verification phrase generation (matches agent/pairing.ts) */
const WORD_LIST = [
  'apple', 'banana', 'cherry', 'dragon', 'eagle', 'falcon',
  'grape', 'harbor', 'island', 'jungle', 'kettle', 'lemon',
  'mango', 'nectar', 'orange', 'pepper', 'quartz', 'river',
  'sunset', 'tiger', 'umbrella', 'violet', 'walnut', 'xylophone',
  'yellow', 'zebra', 'anchor', 'bridge', 'castle', 'delta',
  'ember', 'forest',
];

/** Pairing claim TTL: 10 minutes */
const PAIRING_CLAIM_TTL_MS = 10 * 60 * 1000;

export class PairingClaimStore {
  /** claim_id -> stored claim */
  private claims: Map<string, StoredPairingClaim> = new Map();
  /** invite_id -> claim_id (for routing claims to vaults) */
  private inviteIndex: Map<string, string> = new Map();
  /** vault_id -> Set<claim_id> (for pushing claims to connected vaults) */
  private vaultClaims: Map<string, Set<string>> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    // Cleanup expired claims every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60_000);
  }

  /**
   * Store a new pairing claim
   *
   * @param claim - The pairing claim from the agent
   * @param vaultId - The vault ID this claim routes to (from invite lookup)
   * @returns claim_id and verification_phrase
   */
  storeClaim(
    claim: PairingClaim,
    vaultId?: string
  ): { claim_id: string; verification_phrase: string } {
    const claimId = `claim_${randomUUID().replace(/-/g, '').slice(0, 16)}`;

    // Generate verification phrase (deterministic from public key + invite)
    const verificationPhrase = this.generateVerificationPhrase(
      claim.agent_public_key,
      claim.invite_id
    );

    const stored: StoredPairingClaim = {
      claim_id: claimId,
      claim,
      verification_phrase: verificationPhrase,
      received_at: Date.now(),
      status: 'pending',
      vault_id: vaultId,
    };

    this.claims.set(claimId, stored);
    this.inviteIndex.set(claim.invite_id, claimId);

    // Track by vault if known
    if (vaultId) {
      if (!this.vaultClaims.has(vaultId)) {
        this.vaultClaims.set(vaultId, new Set());
      }
      this.vaultClaims.get(vaultId)!.add(claimId);
    }

    return { claim_id: claimId, verification_phrase: verificationPhrase };
  }

  /**
   * Get a stored claim by claim_id
   */
  getClaim(claimId: string): StoredPairingClaim | undefined {
    return this.claims.get(claimId);
  }

  /**
   * Get claim by invite_id
   */
  getClaimByInvite(inviteId: string): StoredPairingClaim | undefined {
    const claimId = this.inviteIndex.get(inviteId);
    if (!claimId) return undefined;
    return this.claims.get(claimId);
  }

  /**
   * Get pending claims for a vault
   */
  getPendingClaimsForVault(vaultId: string): StoredPairingClaim[] {
    const claimIds = this.vaultClaims.get(vaultId);
    if (!claimIds) return [];

    const pending: StoredPairingClaim[] = [];
    for (const claimId of claimIds) {
      const claim = this.claims.get(claimId);
      if (claim && claim.status === 'pending') {
        pending.push(claim);
      }
    }
    return pending;
  }

  /**
   * Update claim status (vault approves/denies)
   */
  updateClaimStatus(
    claimId: string,
    status: 'approved' | 'denied',
    agentId?: string
  ): boolean {
    const claim = this.claims.get(claimId);
    if (!claim) return false;

    claim.status = status;
    claim.resolved_at = Date.now();
    if (agentId) {
      claim.agent_id = agentId;
    }

    return true;
  }

  /**
   * Associate a claim with a vault_id (when invite_id is resolved)
   */
  associateWithVault(claimId: string, vaultId: string): boolean {
    const claim = this.claims.get(claimId);
    if (!claim) return false;

    claim.vault_id = vaultId;

    if (!this.vaultClaims.has(vaultId)) {
      this.vaultClaims.set(vaultId, new Set());
    }
    this.vaultClaims.get(vaultId)!.add(claimId);

    return true;
  }

  /**
   * Generate verification phrase (must match agent implementation)
   *
   * Same algorithm as dcp-agent/src/pairing.ts:generateVerificationPhrase
   */
  private generateVerificationPhrase(
    agentPublicKey: string,
    inviteId: string
  ): string {
    // Decode base64 public key
    const publicKeyBytes = Buffer.from(agentPublicKey, 'base64');

    // For relay, we use invite_id instead of full pairing invite
    // This is a simplified version - the agent uses the full invite
    const combined = Buffer.concat([
      publicKeyBytes,
      Buffer.from(inviteId),
    ]);

    const hash = createHash('sha256').update(combined).digest();

    const word1 = WORD_LIST[hash[0] % WORD_LIST.length];
    const word2 = WORD_LIST[hash[1] % WORD_LIST.length];
    const word3 = WORD_LIST[hash[2] % WORD_LIST.length];

    return `${word1}-${word2}-${word3}`;
  }

  /**
   * Cleanup expired claims
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [claimId, claim] of this.claims) {
      // Expire pending claims after TTL
      if (claim.status === 'pending' && now - claim.received_at > PAIRING_CLAIM_TTL_MS) {
        claim.status = 'expired';
        claim.resolved_at = now;
      }

      // Remove resolved claims after 1 hour (for polling)
      if (claim.status !== 'pending' && claim.resolved_at) {
        if (now - claim.resolved_at > 60 * 60 * 1000) {
          this.claims.delete(claimId);
          this.inviteIndex.delete(claim.claim.invite_id);
          if (claim.vault_id) {
            this.vaultClaims.get(claim.vault_id)?.delete(claimId);
          }
          removed++;
        }
      }
    }

    return removed;
  }

  /**
   * Get stats
   */
  getStats(): {
    totalClaims: number;
    pendingClaims: number;
    approvedClaims: number;
    deniedClaims: number;
  } {
    let pending = 0;
    let approved = 0;
    let denied = 0;

    for (const claim of this.claims.values()) {
      switch (claim.status) {
        case 'pending':
          pending++;
          break;
        case 'approved':
          approved++;
          break;
        case 'denied':
          denied++;
          break;
      }
    }

    return {
      totalClaims: this.claims.size,
      pendingClaims: pending,
      approvedClaims: approved,
      deniedClaims: denied,
    };
  }

  /**
   * Stop cleanup interval
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// ============================================================================
// DCP Mobile Pairing Store
// ============================================================================

/** Mobile pairing status TTL: enough time for the QR terminal to poll. */
const MOBILE_PAIRING_TTL_MS = 10 * 60 * 1000;
const MOBILE_PAIRING_RESOLVED_TTL_MS = 60 * 60 * 1000;

export class MobilePairingStore {
  private records: Map<string, MobilePairingRecord> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60_000);
  }

  approve(request: MobilePairingApprovalRequest): MobilePairingRecord {
    const now = Date.now();
    const existing = this.records.get(request.invite.invite_id);
    if (existing && existing.status === 'approved') {
      return existing;
    }

    const record: MobilePairingRecord = {
      invite_id: request.invite.invite_id,
      invite: request.invite,
      received_at: existing?.received_at ?? now,
      status: 'approved',
      vault_id: request.vault_id,
      vault_hpke_public_key: request.vault_hpke_public_key,
      vault_signing_public_key: request.vault_signing_public_key,
      agent_id: request.agent_id,
      approved_scopes: request.approved_scopes,
      approved_budget: request.approved_budget,
      resolved_at: now,
    };

    this.records.set(record.invite_id, record);
    return record;
  }

  deny(inviteId: string, deniedReason?: string): MobilePairingRecord {
    const now = Date.now();
    const existing = this.records.get(inviteId);
    const record: MobilePairingRecord = {
      invite_id: inviteId,
      invite: existing?.invite ?? {
        type: 'dcp_agent_pairing',
        version: '1.0',
        relay_url: '',
        invite_id: inviteId,
        requested_agent_id: '',
        agent_public_key: '',
        agent_name: '',
        agent_client: 'custom',
        environment: 'dev',
        requested_scopes: [],
        requested_budget: { daily: 0, currency: 'USDC', approval_threshold: 0 },
        created_at: new Date(now).toISOString(),
        expires_at: new Date(now + MOBILE_PAIRING_TTL_MS).toISOString(),
        nonce: '',
      },
      received_at: existing?.received_at ?? now,
      status: 'denied',
      resolved_at: now,
      denied_reason: deniedReason,
    };

    this.records.set(inviteId, record);
    return record;
  }

  get(inviteId: string): MobilePairingRecord | undefined {
    const record = this.records.get(inviteId);
    if (!record) return undefined;

    const now = Date.now();
    if (record.status === 'approved' || record.status === 'denied') {
      return record;
    }

    if (now - record.received_at > MOBILE_PAIRING_TTL_MS) {
      record.status = 'expired';
      record.resolved_at = now;
    }

    return record;
  }

  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [inviteId, record] of this.records) {
      if (record.status !== 'approved' && record.status !== 'denied' && now - record.received_at > MOBILE_PAIRING_TTL_MS) {
        record.status = 'expired';
        record.resolved_at = now;
      }

      if (record.resolved_at && now - record.resolved_at > MOBILE_PAIRING_RESOLVED_TTL_MS) {
        this.records.delete(inviteId);
        removed++;
      }
    }

    return removed;
  }

  getStats(): { totalMobilePairings: number; approvedMobilePairings: number; deniedMobilePairings: number } {
    let approved = 0;
    let denied = 0;

    for (const record of this.records.values()) {
      if (record.status === 'approved') approved++;
      if (record.status === 'denied') denied++;
    }

    return {
      totalMobilePairings: this.records.size,
      approvedMobilePairings: approved,
      deniedMobilePairings: denied,
    };
  }

  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
