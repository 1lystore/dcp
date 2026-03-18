/**
 * Message Store for DCP Relay
 *
 * Handles:
 * - Message storage with TTL (5 minutes)
 * - Idempotency by request_id
 * - Vault connection tracking
 * - Message delivery tracking
 *
 * From PRD Section 4.1:
 * - Message TTL: 5 minutes
 * - Idempotency by request_id
 */

import type {
  RelayEnvelope,
  RelayResponseEnvelope,
  StoredMessage,
  VaultConnection,
  RelayConfig,
} from './types.js';
import { RelayError, MESSAGE_TTL_MS } from './types.js';

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
      port: 8421,
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
// Rate Limiter (PRD Section C3: 60 req/min per vault)
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
