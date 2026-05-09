/**
 * Store for DCP Telegram Service (Option B from protocol spec section 15)
 *
 * Provides:
 * - Persistent vault ↔ chat_id pairings (SQLite)
 * - Pending pairing codes
 * - Rate limiting (sliding window)
 * - Notification deduplication
 * - Webhook signature verification cache
 *
 * This is the CLOUD service that works for ALL users with ONE shared bot.
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import type { ApprovalAction, ApprovalCommand, RateLimitState, VaultPairing, PendingPairing } from './types.js';

/**
 * Default rate limit: 30 notifications per hour
 */
const DEFAULT_RATE_LIMIT = 30;

/**
 * Rate limit window: 1 hour in milliseconds
 */
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;

/**
 * Deduplication window: 5 minutes
 * Prevents duplicate notifications for the same consent
 */
const DEDUP_WINDOW_MS = 5 * 60 * 1000;

/**
 * Cleanup interval: 5 minutes
 */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

const APPROVAL_COMMAND_TTL_MS = 5 * 60 * 1000;

/**
 * Rate limiter for Telegram notifications
 */
export class RateLimiter {
  private limits: Map<string, RateLimitState> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.startCleanup();
  }

  /**
   * Check if a chat is rate limited
   *
   * @param chatId - Telegram chat ID
   * @param limit - Max notifications per hour (default: 30)
   * @returns true if rate limited (should NOT send), false if OK to send
   */
  isLimited(chatId: string, limit: number = DEFAULT_RATE_LIMIT): boolean {
    const state = this.getState(chatId);
    const now = Date.now();

    // Check if window has expired
    if (now - state.windowStart >= RATE_LIMIT_WINDOW_MS) {
      // Reset window
      state.count = 0;
      state.windowStart = now;
      state.isLimited = false;
    }

    return state.count >= limit;
  }

  /**
   * Record a notification being sent
   */
  record(chatId: string, limit: number = DEFAULT_RATE_LIMIT): void {
    const state = this.getState(chatId);
    const now = Date.now();

    // Reset if window expired
    if (now - state.windowStart >= RATE_LIMIT_WINDOW_MS) {
      state.count = 0;
      state.windowStart = now;
    }

    state.count++;
    state.isLimited = state.count >= limit;
  }

  /**
   * Get remaining notifications in current window
   */
  getRemaining(chatId: string, limit: number = DEFAULT_RATE_LIMIT): number {
    const state = this.getState(chatId);
    const now = Date.now();

    // Check if window expired
    if (now - state.windowStart >= RATE_LIMIT_WINDOW_MS) {
      return limit;
    }

    return Math.max(0, limit - state.count);
  }

  /**
   * Get time until rate limit resets (in milliseconds)
   */
  getResetTime(chatId: string): number {
    const state = this.limits.get(chatId);
    if (!state) return 0;

    const now = Date.now();
    const elapsed = now - state.windowStart;

    if (elapsed >= RATE_LIMIT_WINDOW_MS) {
      return 0;
    }

    return RATE_LIMIT_WINDOW_MS - elapsed;
  }

  /**
   * Get or create state for a chat
   */
  private getState(chatId: string): RateLimitState {
    let state = this.limits.get(chatId);
    if (!state) {
      state = {
        chatId,
        count: 0,
        windowStart: Date.now(),
        isLimited: false,
      };
      this.limits.set(chatId, state);
    }
    return state;
  }

  /**
   * Start automatic cleanup of stale entries
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, CLEANUP_INTERVAL_MS);
  }

  /**
   * Remove stale entries
   */
  private cleanup(): void {
    const now = Date.now();
    const staleThreshold = now - RATE_LIMIT_WINDOW_MS * 2;

    for (const [chatId, state] of this.limits) {
      if (state.windowStart < staleThreshold) {
        this.limits.delete(chatId);
      }
    }
  }

  /**
   * Get statistics for monitoring
   */
  getStats(): { totalChats: number; limitedChats: number } {
    let limitedChats = 0;
    for (const state of this.limits.values()) {
      if (state.isLimited) limitedChats++;
    }
    return {
      totalChats: this.limits.size,
      limitedChats,
    };
  }

  /**
   * Close and cleanup
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.limits.clear();
  }
}

/**
 * Deduplication store for consent notifications
 * Prevents sending duplicate notifications for the same consent
 */
export class DeduplicationStore {
  private seen: Map<string, number> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.startCleanup();
  }

  /**
   * Check if a consent notification has already been sent
   *
   * @param consentId - Consent request ID
   * @returns true if already sent (should skip), false if not seen
   */
  isDuplicate(consentId: string): boolean {
    const seenAt = this.seen.get(consentId);
    if (!seenAt) return false;

    const now = Date.now();
    if (now - seenAt > DEDUP_WINDOW_MS) {
      // Expired, remove and allow
      this.seen.delete(consentId);
      return false;
    }

    return true;
  }

  /**
   * Mark a consent as notified
   */
  markSeen(consentId: string): void {
    this.seen.set(consentId, Date.now());
  }

  /**
   * Start automatic cleanup
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, CLEANUP_INTERVAL_MS);
  }

  /**
   * Remove expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    const expireThreshold = now - DEDUP_WINDOW_MS;

    for (const [consentId, seenAt] of this.seen) {
      if (seenAt < expireThreshold) {
        this.seen.delete(consentId);
      }
    }
  }

  /**
   * Get statistics
   */
  getStats(): { trackedConsents: number } {
    return { trackedConsents: this.seen.size };
  }

  /**
   * Close and cleanup
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.seen.clear();
  }
}

/**
 * Nonce store for webhook replay protection
 * Prevents replay attacks by tracking used nonces
 */
export class NonceStore {
  private nonces: Map<string, number> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  /** Maximum clock skew allowed (5 minutes) */
  private readonly maxClockSkewMs = 5 * 60 * 1000;

  /** Nonce TTL (2x clock skew for safety) */
  private readonly nonceTtlMs = 10 * 60 * 1000;

  constructor() {
    this.startCleanup();
  }

  /**
   * Check and mark a nonce as used
   *
   * @param nonce - Unique request nonce
   * @param timestamp - Request timestamp
   * @returns true if valid (not replayed), false if replay detected
   */
  checkAndMark(nonce: string, timestamp: string): boolean {
    const now = Date.now();
    const requestTime = new Date(timestamp).getTime();

    // Check timestamp is within acceptable range
    const timeDiff = Math.abs(now - requestTime);
    if (timeDiff > this.maxClockSkewMs) {
      return false; // Timestamp too old or too far in future
    }

    // Check if nonce was already used
    if (this.nonces.has(nonce)) {
      return false; // Replay detected
    }

    // Mark nonce as used
    this.nonces.set(nonce, now);
    return true;
  }

  /**
   * Start automatic cleanup
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, CLEANUP_INTERVAL_MS);
  }

  /**
   * Remove expired nonces
   */
  private cleanup(): void {
    const now = Date.now();
    const expireThreshold = now - this.nonceTtlMs;

    for (const [nonce, seenAt] of this.nonces) {
      if (seenAt < expireThreshold) {
        this.nonces.delete(nonce);
      }
    }
  }

  /**
   * Close and cleanup
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.nonces.clear();
  }
}

/**
 * Persistent pairing store (SQLite)
 * Stores vault_id ↔ chat_id mappings for ALL users
 * This is the core of Option B from protocol spec section 15
 */
export class PairingStore {
  readonly db: Database.Database;

  constructor(dataDir: string = './data') {
    // Ensure data directory exists
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = path.join(dataDir, 'telegram-pairings.db');
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.initTables();
  }

  private initTables(): void {
    // Vault pairings (vault_id ↔ chat_id mappings)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_pairings (
        vault_id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        paired_at TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        muted_until TEXT,
        notification_count INTEGER DEFAULT 0,
        last_notification_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_pairings_chat ON vault_pairings(chat_id);
    `);

    // Pending pairing codes (waiting for user to send to bot)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS pending_pairings (
        code TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pending_vault ON pending_pairings(vault_id);
      CREATE INDEX IF NOT EXISTS idx_pending_expires ON pending_pairings(expires_at);
    `);

    // Vault public keys for webhook signature verification
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_keys (
        vault_id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        registered_at TEXT NOT NULL
      );
    `);
  }

  /**
   * Register a vault's public key for signature verification
   */
  registerVaultKey(vaultId: string, publicKeyBase64: string): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO vault_keys (vault_id, public_key, registered_at)
      VALUES (?, ?, ?)
    `).run(vaultId, publicKeyBase64, new Date().toISOString());
  }

  /**
   * Get a vault's public key
   */
  getVaultKey(vaultId: string): string | null {
    const row = this.db.prepare('SELECT public_key FROM vault_keys WHERE vault_id = ?').get(vaultId) as { public_key: string } | undefined;
    return row?.public_key ?? null;
  }

  /**
   * Get all registered vault keys (for loading into memory on startup)
   */
  getAllVaultKeys(): Array<{ vault_id: string; public_key: string }> {
    return this.db.prepare('SELECT vault_id, public_key FROM vault_keys').all() as Array<{ vault_id: string; public_key: string }>;
  }

  /**
   * Generate a 6-digit pairing code for a vault
   */
  createPairingCode(vaultId: string): PendingPairing {
    // Delete any existing pending codes for this vault
    this.db.prepare('DELETE FROM pending_pairings WHERE vault_id = ?').run(vaultId);

    // Generate 6-digit code
    const code = crypto.randomInt(100000, 999999).toString();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes

    this.db.prepare(`
      INSERT INTO pending_pairings (code, vault_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `).run(code, vaultId, expiresAt.toISOString(), now.toISOString());

    return {
      code,
      vault_id: vaultId,
      expires_at: expiresAt.toISOString(),
      created_at: now.toISOString(),
    };
  }

  /**
   * Validate and consume a pairing code (called when user sends code to bot)
   * Returns vault_id if valid, null if invalid/expired
   */
  consumePairingCode(code: string): string | null {
    // Clean up expired codes first
    this.db.prepare('DELETE FROM pending_pairings WHERE expires_at < ?')
      .run(new Date().toISOString());

    // Find the code
    const pending = this.db.prepare(`
      SELECT vault_id FROM pending_pairings WHERE code = ?
    `).get(code) as { vault_id: string } | undefined;

    if (!pending) {
      return null;
    }

    // Delete the code (single use)
    this.db.prepare('DELETE FROM pending_pairings WHERE code = ?').run(code);

    return pending.vault_id;
  }

  /**
   * Complete pairing: associate vault_id with chat_id
   */
  completePairing(vaultId: string, chatId: string): VaultPairing {
    const now = new Date().toISOString();

    // Upsert pairing
    this.db.prepare(`
      INSERT INTO vault_pairings (vault_id, chat_id, paired_at, enabled)
      VALUES (?, ?, ?, 1)
      ON CONFLICT(vault_id) DO UPDATE SET
        chat_id = excluded.chat_id,
        paired_at = excluded.paired_at,
        enabled = 1,
        muted_until = NULL
    `).run(vaultId, chatId, now);

    return {
      vault_id: vaultId,
      chat_id: chatId,
      paired_at: now,
      enabled: true,
      muted_until: null,
      notification_count: 0,
      last_notification_at: null,
    };
  }

  /**
   * Get pairing by vault_id (used when desktop sends webhook)
   */
  getPairingByVaultId(vaultId: string): VaultPairing | null {
    const row = this.db.prepare(`
      SELECT * FROM vault_pairings WHERE vault_id = ?
    `).get(vaultId) as {
      vault_id: string;
      chat_id: string;
      paired_at: string;
      enabled: number;
      muted_until: string | null;
      notification_count: number;
      last_notification_at: string | null;
    } | undefined;

    if (!row) return null;

    return {
      vault_id: row.vault_id,
      chat_id: row.chat_id,
      paired_at: row.paired_at,
      enabled: row.enabled === 1,
      muted_until: row.muted_until,
      notification_count: row.notification_count,
      last_notification_at: row.last_notification_at,
    };
  }

  /**
   * Get pairing by chat_id (used for status/unlink commands)
   */
  getPairingByChatId(chatId: string): VaultPairing | null {
    const row = this.db.prepare(`
      SELECT * FROM vault_pairings WHERE chat_id = ?
    `).get(chatId) as {
      vault_id: string;
      chat_id: string;
      paired_at: string;
      enabled: number;
      muted_until: string | null;
      notification_count: number;
      last_notification_at: string | null;
    } | undefined;

    if (!row) return null;

    return {
      vault_id: row.vault_id,
      chat_id: row.chat_id,
      paired_at: row.paired_at,
      enabled: row.enabled === 1,
      muted_until: row.muted_until,
      notification_count: row.notification_count,
      last_notification_at: row.last_notification_at,
    };
  }

  /**
   * Delete pairing (unlink)
   */
  deletePairing(vaultId: string): boolean {
    const result = this.db.prepare('DELETE FROM vault_pairings WHERE vault_id = ?').run(vaultId);
    return result.changes > 0;
  }

  /**
   * Delete pairing by chat_id (when user sends /unlink)
   */
  deletePairingByChatId(chatId: string): boolean {
    const result = this.db.prepare('DELETE FROM vault_pairings WHERE chat_id = ?').run(chatId);
    return result.changes > 0;
  }

  /**
   * Mute notifications for a vault
   */
  mutePairing(vaultId: string, until: Date): void {
    this.db.prepare(`
      UPDATE vault_pairings SET muted_until = ? WHERE vault_id = ?
    `).run(until.toISOString(), vaultId);
  }

  /**
   * Unmute notifications for a vault
   */
  unmutePairing(vaultId: string): void {
    this.db.prepare(`
      UPDATE vault_pairings SET muted_until = NULL WHERE vault_id = ?
    `).run(vaultId);
  }

  /**
   * Record a notification was sent
   */
  recordNotification(vaultId: string): void {
    this.db.prepare(`
      UPDATE vault_pairings
      SET notification_count = notification_count + 1,
          last_notification_at = ?
      WHERE vault_id = ?
    `).run(new Date().toISOString(), vaultId);
  }

  /**
   * Check if pairing is muted
   */
  isMuted(vaultId: string): boolean {
    const pairing = this.getPairingByVaultId(vaultId);
    if (!pairing || !pairing.muted_until) return false;
    return new Date(pairing.muted_until) > new Date();
  }

  /**
   * Get statistics
   */
  getStats(): { totalPairings: number; activePairings: number } {
    const total = this.db.prepare('SELECT COUNT(*) as count FROM vault_pairings').get() as { count: number };
    const active = this.db.prepare('SELECT COUNT(*) as count FROM vault_pairings WHERE enabled = 1').get() as { count: number };
    return {
      totalPairings: total.count,
      activePairings: active.count,
    };
  }

  /**
   * Close database
   */
  close(): void {
    this.db.close();
  }
}

/** Approval command TTL: 10 minutes */
const APPROVAL_COMMAND_EXPIRY_MS = 10 * 60 * 1000;

export class ApprovalCommandStore {
  private db: Database.Database;
  /** Service signing key for approval commands (HMAC-SHA256 secret) */
  private serviceSigningKey: Buffer;

  constructor(db: Database.Database, serviceSigningKey?: string) {
    this.db = db;
    // Use provided key or generate a random one
    // In production, this should be set from environment
    this.serviceSigningKey = serviceSigningKey
      ? Buffer.from(serviceSigningKey, 'base64')
      : crypto.randomBytes(32);
    this.initTables();
  }

  private initTables(): void {
    // Check if old table exists without new columns
    const tableInfo = this.db.prepare(`PRAGMA table_info(approval_commands)`).all() as Array<{ name: string }>;
    const hasExpiresAt = tableInfo.some(col => col.name === 'expires_at');

    if (tableInfo.length > 0 && !hasExpiresAt) {
      // Old schema exists, drop and recreate with new columns
      // This is safe in dev/test; for production, use proper migrations
      this.db.exec(`DROP TABLE IF EXISTS approval_commands`);
    }

    // Create table with protocol spec fields
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approval_commands (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        chat_id TEXT NOT NULL,
        consent_id TEXT NOT NULL,
        action TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        pairing_id TEXT NOT NULL,
        service_signature TEXT NOT NULL,
        processed_at TEXT,
        result TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_approval_vault ON approval_commands(vault_id, processed_at);
      CREATE INDEX IF NOT EXISTS idx_approval_chat ON approval_commands(chat_id);
      CREATE INDEX IF NOT EXISTS idx_approval_created ON approval_commands(created_at);
      CREATE INDEX IF NOT EXISTS idx_approval_expires ON approval_commands(expires_at);
    `);
  }

  /**
   * Generate service signature for an approval command
   * Uses HMAC-SHA256 to prove the command came from this service
   */
  private generateServiceSignature(command: {
    id: string;
    vault_id: string;
    consent_id: string;
    action: string;
    expires_at: string;
    pairing_id: string;
  }): string {
    const message = `${command.id}|${command.vault_id}|${command.consent_id}|${command.action}|${command.expires_at}|${command.pairing_id}`;
    const hmac = crypto.createHmac('sha256', this.serviceSigningKey);
    hmac.update(message);
    return hmac.digest('base64');
  }

  /**
   * Get the service public key (for vault verification)
   * Returns base64-encoded HMAC key identifier (not the actual secret)
   */
  getServiceKeyId(): string {
    // Return a hash of the key for identification purposes
    const hash = crypto.createHash('sha256');
    hash.update(this.serviceSigningKey);
    return hash.digest('base64').slice(0, 16);
  }

  createApprovalCommand(
    vaultId: string,
    chatId: string,
    consentId: string,
    action: ApprovalAction,
    pairingId: string
  ): ApprovalCommand {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + APPROVAL_COMMAND_EXPIRY_MS);
    const id = `cmd_${crypto.randomUUID()}`;
    const createdAt = now.toISOString();
    const expiresAtStr = expiresAt.toISOString();

    // Generate service signature
    const serviceSignature = this.generateServiceSignature({
      id,
      vault_id: vaultId,
      consent_id: consentId,
      action,
      expires_at: expiresAtStr,
      pairing_id: pairingId,
    });

    this.db.prepare(`
      INSERT INTO approval_commands (
        id, vault_id, chat_id, consent_id, action, created_at, expires_at,
        pairing_id, service_signature, processed_at, result
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
    `).run(id, vaultId, chatId, consentId, action, createdAt, expiresAtStr, pairingId, serviceSignature);

    return {
      id,
      vault_id: vaultId,
      chat_id: chatId,
      consent_id: consentId,
      action,
      created_at: createdAt,
      expires_at: expiresAtStr,
      pairing_id: pairingId,
      service_signature: serviceSignature,
      processed_at: null,
      result: null,
    };
  }

  getPendingApprovals(vaultId: string): ApprovalCommand[] {
    const now = new Date().toISOString();
    // Mark expired approvals (using expires_at instead of created_at offset)
    this.db.prepare(`
      UPDATE approval_commands
      SET processed_at = ?, result = 'expired'
      WHERE processed_at IS NULL AND expires_at < ?
    `).run(now, now);

    const rows = this.db.prepare(`
      SELECT * FROM approval_commands
      WHERE vault_id = ? AND processed_at IS NULL AND expires_at > ?
      ORDER BY created_at ASC
    `).all(vaultId, now) as Array<{
      id: string;
      vault_id: string;
      chat_id: string;
      consent_id: string;
      action: ApprovalAction;
      created_at: string;
      expires_at: string;
      pairing_id: string;
      service_signature: string;
      processed_at: string | null;
      result: string | null;
    }>;

    return rows.map((row) => ({
      id: row.id,
      vault_id: row.vault_id,
      chat_id: row.chat_id,
      consent_id: row.consent_id,
      action: row.action,
      created_at: row.created_at,
      expires_at: row.expires_at,
      pairing_id: row.pairing_id,
      service_signature: row.service_signature,
      processed_at: row.processed_at,
      result: row.result,
    }));
  }

  markApprovalProcessed(commandId: string, result: string): ApprovalCommand | null {
    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE approval_commands
      SET processed_at = ?, result = ?
      WHERE id = ? AND processed_at IS NULL
    `).run(now, result, commandId);

    return this.getApprovalCommand(commandId);
  }

  getApprovalCommand(commandId: string): ApprovalCommand | null {
    const row = this.db.prepare(`
      SELECT * FROM approval_commands WHERE id = ?
    `).get(commandId) as {
      id: string;
      vault_id: string;
      chat_id: string;
      consent_id: string;
      action: ApprovalAction;
      created_at: string;
      expires_at: string;
      pairing_id: string;
      service_signature: string;
      processed_at: string | null;
      result: string | null;
    } | undefined;

    if (!row) return null;

    return {
      id: row.id,
      vault_id: row.vault_id,
      chat_id: row.chat_id,
      consent_id: row.consent_id,
      action: row.action,
      created_at: row.created_at,
      expires_at: row.expires_at,
      pairing_id: row.pairing_id,
      service_signature: row.service_signature,
      processed_at: row.processed_at,
      result: row.result,
    };
  }

  getStats(): { pendingApprovals: number; processedApprovals: number } {
    const pending = this.db.prepare(`
      SELECT COUNT(*) as count FROM approval_commands WHERE processed_at IS NULL
    `).get() as { count: number };
    const processed = this.db.prepare(`
      SELECT COUNT(*) as count FROM approval_commands WHERE processed_at IS NOT NULL
    `).get() as { count: number };
    return {
      pendingApprovals: pending.count,
      processedApprovals: processed.count,
    };
  }
}

/**
 * Combined store manager
 */
export class TelegramStore {
  readonly pairings: PairingStore;
  readonly approvals: ApprovalCommandStore;
  readonly rateLimiter: RateLimiter;
  readonly deduplication: DeduplicationStore;
  readonly nonceStore: NonceStore;

  constructor(dataDir?: string) {
    this.pairings = new PairingStore(dataDir);
    this.approvals = new ApprovalCommandStore(this.pairings.db);
    this.rateLimiter = new RateLimiter();
    this.deduplication = new DeduplicationStore();
    this.nonceStore = new NonceStore();
  }

  /**
   * Get combined statistics
   */
  getStats() {
    return {
      pairings: this.pairings.getStats(),
      approvals: this.approvals.getStats(),
      rateLimit: this.rateLimiter.getStats(),
      deduplication: this.deduplication.getStats(),
    };
  }

  /**
   * Close all stores
   */
  close(): void {
    this.pairings.close();
    this.rateLimiter.close();
    this.deduplication.close();
    this.nonceStore.close();
  }

  // Vault key methods (delegated to pairings store)
  registerVaultKey(vaultId: string, publicKeyBase64: string): void {
    this.pairings.registerVaultKey(vaultId, publicKeyBase64);
  }

  getVaultKey(vaultId: string): string | null {
    return this.pairings.getVaultKey(vaultId);
  }

  getAllVaultKeys(): Array<{ vault_id: string; public_key: string }> {
    return this.pairings.getAllVaultKeys();
  }
}
