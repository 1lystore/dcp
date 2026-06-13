/**
 * Storage Layer for DCP Vault
 *
 * Implements:
 * - SQLite database management (better-sqlite3)
 * - Master key storage in OS Keychain (keytar)
 * - File fallback for systems without keychain
 * - CRUD operations for all vault tables
 * - Vault initialization
 *
 * SECURITY RULES:
 * 1. Master key is stored in OS Keychain (hardware-backed on macOS)
 * 2. Master key is NEVER stored in SQLite
 * 3. All sensitive data is encrypted before storage
 */

import Database, { Database as DatabaseType } from 'better-sqlite3';
import * as fs from 'fs';

// Lazy-load keytar to avoid crashes in environments without native module support (e.g., Docker)
let keytar: typeof import('keytar') | null = null;
async function getKeytar() {
  if (keytar === null) {
    try {
      keytar = await import('keytar');
    } catch {
      keytar = null;
    }
  }
  return keytar;
}
import * as path from 'path';
import * as os from 'os';
import { randomBytes, randomUUID, createHash, randomInt, timingSafeEqual } from 'crypto';
import {
  VaultRecord,
  AgentSession,
  SpendEvent,
  AuditEvent,
  PendingConsent,
  EncryptedPayload,
  Chain,
  ItemType,
  SensitivityLevel,
  VaultError,
  AuditEventType,
  ConsentMode,
  TrustTier,
  SpendStatus,
  ConsentStatus,
  TrustedService,
  AgentConnection,
  AgentConnectionMode,
  AgentConnectionTier,
  CloudConnectLink,
  CloudConnectLinkStatus,
  TelegramConfig,
  CreateTelegramConfigInput,
  TelegramPairingCode,
  TelegramNotificationLog,
  TelegramRequestCategory,
} from './types.js';
import { generateKey, deriveKeyFromPassphrase, generateSalt, zeroize, encrypt, decrypt, envelopeEncrypt, envelopeDecrypt } from './crypto.js';

type PendingConsentCreateResult = PendingConsent & {
  consent: PendingConsent;
  isNew: boolean;
};

// ============================================================================
// Constants
// ============================================================================

/** Default vault directory */
const DEFAULT_VAULT_DIR =
  process.env.DCP_VAULT_DIR ||
  process.env.VAULT_DIR ||
  path.join(os.homedir(), '.dcp');

/** Keychain service name */
const KEYCHAIN_SERVICE = 'dcp';

/** Keychain account prefix for vault-scoped master keys */
const KEYCHAIN_ACCOUNT_PREFIX = 'master-key:';

/** File permissions for vault.key (owner read/write only) */
const KEY_FILE_MODE = 0o600;

/** Non-secret marker used to distinguish a provisioned vault from bare schema tables */
const INIT_MARKER_FILE = 'vault.initialized';

function generateId(): string {
  if (typeof randomUUID === 'function') {
    return randomUUID();
  }
  return randomBytes(16).toString('hex');
}

// ============================================================================
// Vault Storage Class
// ============================================================================

export class VaultStorage {
  private db: DatabaseType;
  private vaultDir: string;
  private masterKey: Buffer | null = null;

  constructor(vaultDir: string = DEFAULT_VAULT_DIR) {
    this.vaultDir = vaultDir;
    this.db = this.openDatabase();
  }

  // ==========================================================================
  // Database Management
  // ==========================================================================

  private openDatabase(): DatabaseType {
    // Ensure vault directory exists
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }

    const dbPath = path.join(this.vaultDir, 'vault.db');
    const db = new Database(dbPath);

    // Enable WAL mode for better concurrent performance
    db.pragma('journal_mode = WAL');

    // Enable foreign keys
    db.pragma('foreign_keys = ON');

    return db;
  }

  /**
   * Initialize the database schema
   */
  initializeSchema(): void {
    this.db.exec(`
      -- Vault records (encrypted data)
      CREATE TABLE IF NOT EXISTS vault_records (
        id TEXT PRIMARY KEY,
        scope TEXT NOT NULL UNIQUE,
        item_type TEXT NOT NULL,
        sensitivity TEXT NOT NULL,
        ciphertext BLOB NOT NULL,
        nonce BLOB NOT NULL,
        dek_wrapped BLOB NOT NULL,
        dek_nonce BLOB NOT NULL,
        chain TEXT,
        public_address TEXT,
        schema_version TEXT NOT NULL DEFAULT '1.0',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      -- Agent sessions
      CREATE TABLE IF NOT EXISTS agent_sessions (
        id TEXT PRIMARY KEY,
        agent_name TEXT NOT NULL,
        agent_fingerprint TEXT,
        marketplace TEXT,
        trust_tier TEXT NOT NULL DEFAULT 'unknown',
        granted_scopes TEXT NOT NULL,
        purpose TEXT,
        consent_mode TEXT NOT NULL,
        profile_name TEXT,
        token_id TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        revoked_at TEXT
      );

      -- Spend events (budget tracking)
      CREATE TABLE IF NOT EXISTS spend_events (
        id TEXT PRIMARY KEY,
        agent_session_id TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT NOT NULL,
        chain TEXT NOT NULL,
        operation TEXT NOT NULL,
        destination TEXT,
        idempotency_key TEXT UNIQUE,
        status TEXT NOT NULL,
        tx_signature TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (agent_session_id) REFERENCES agent_sessions(id)
      );

      -- Audit events (immutable log)
      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        agent_name TEXT,
        scope TEXT,
        operation TEXT,
        details TEXT,
        outcome TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      -- Pending consents
      CREATE TABLE IF NOT EXISTS pending_consents (
        id TEXT PRIMARY KEY,
        agent_name TEXT NOT NULL,
        action TEXT NOT NULL,
        scope TEXT NOT NULL,
        details TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        resolved_at TEXT
      );

      -- Saved profiles
      CREATE TABLE IF NOT EXISTS saved_profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        allowed_scopes TEXT NOT NULL,
        spending_limit_per_tx TEXT,
        spending_limit_daily TEXT,
        approval_threshold TEXT,
        allowed_purposes TEXT,
        allow_always_expiry_days INTEGER DEFAULT 90,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      -- Trusted services (protocol spec section B2)
      CREATE TABLE IF NOT EXISTS trusted_services (
        service_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        scopes TEXT NOT NULL,
        budget_daily REAL NOT NULL,
        budget_currency TEXT NOT NULL DEFAULT 'USDC',
        budget_auto_approve_under REAL NOT NULL DEFAULT 0,
        trusted_at TEXT NOT NULL,
        connected_at TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        verified INTEGER NOT NULL DEFAULT 0
      );

      -- Agent connections (DCP v1 Agent Connectivity)
      CREATE TABLE IF NOT EXISTS agent_connections (
        agent_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        mode TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        service_id TEXT,
        service_public_key TEXT,
        permission_scopes TEXT NOT NULL,
        budget_daily REAL NOT NULL,
        budget_currency TEXT NOT NULL DEFAULT 'USDC',
        budget_auto_approve_under REAL NOT NULL DEFAULT 0,
        tier TEXT NOT NULL DEFAULT 'free',
        token_hash TEXT,
        created_at TEXT NOT NULL,
        paired_at TEXT,
        last_seen_at TEXT,
        last_request_at TEXT,
        request_count INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT
      );

      -- Create indexes
      CREATE INDEX IF NOT EXISTS idx_vault_records_scope ON vault_records(scope);
      CREATE INDEX IF NOT EXISTS idx_vault_records_chain ON vault_records(chain);
      CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent_name ON agent_sessions(agent_name);
      CREATE INDEX IF NOT EXISTS idx_agent_sessions_expires_at ON agent_sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_spend_events_session ON spend_events(agent_session_id);
      CREATE INDEX IF NOT EXISTS idx_spend_events_created_at ON spend_events(created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
      CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
      CREATE INDEX IF NOT EXISTS idx_pending_consents_status ON pending_consents(status);
      CREATE INDEX IF NOT EXISTS idx_trusted_services_enabled ON trusted_services(enabled);
      CREATE INDEX IF NOT EXISTS idx_trusted_services_connected ON trusted_services(connected_at);
      CREATE INDEX IF NOT EXISTS idx_agent_connections_status ON agent_connections(status);
      CREATE INDEX IF NOT EXISTS idx_agent_connections_service ON agent_connections(service_id);
      CREATE INDEX IF NOT EXISTS idx_agent_connections_last_seen ON agent_connections(last_seen_at);

      -- Pairing tokens (for proxy pairing flow)
      CREATE TABLE IF NOT EXISTS pairing_tokens (
        token_hash TEXT PRIMARY KEY,
        service_id TEXT NOT NULL,
        scopes TEXT NOT NULL,
        budget_daily REAL NOT NULL,
        budget_currency TEXT NOT NULL DEFAULT 'USDC',
        budget_auto_approve_under REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT
      );

      -- Cloud-Connect links (Cloud Agent Connect: one-time, key-pinned bootstrap)
      CREATE TABLE IF NOT EXISTS cloud_connect_links (
        link_id TEXT PRIMARY KEY,
        secret_hash TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        name TEXT NOT NULL,
        permission_scopes TEXT NOT NULL,
        budget_daily REAL NOT NULL DEFAULT 0,
        budget_currency TEXT NOT NULL DEFAULT 'USDC',
        budget_auto_approve_under REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        match_code TEXT,
        redeemer_public_key TEXT,
        source_ip TEXT,
        source_host TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        redeemed_at TEXT,
        consumed_at TEXT,
        revoked_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_cloud_connect_links_status ON cloud_connect_links(status);
      CREATE INDEX IF NOT EXISTS idx_cloud_connect_links_agent ON cloud_connect_links(agent_id);
      CREATE INDEX IF NOT EXISTS idx_cloud_connect_links_expires ON cloud_connect_links(expires_at);

      CREATE INDEX IF NOT EXISTS idx_pairing_tokens_expires ON pairing_tokens(expires_at);

      -- Telegram configuration (protocol spec section 15)
      CREATE TABLE IF NOT EXISTS telegram_configs (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL UNIQUE,
        bot_token_ciphertext BLOB NOT NULL,
        bot_token_nonce BLOB NOT NULL,
        bot_token_dek_wrapped BLOB NOT NULL,
        bot_token_dek_nonce BLOB NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        notify_consent INTEGER NOT NULL DEFAULT 1,
        rate_limit_per_hour INTEGER NOT NULL DEFAULT 30,
        last_notification_at TEXT,
        notifications_this_hour INTEGER NOT NULL DEFAULT 0,
        hour_window_start TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        paired_at TEXT,
        muted_until TEXT
      );

      -- Telegram pairing codes (6-digit codes for linking)
      CREATE TABLE IF NOT EXISTS telegram_pairing_codes (
        code TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_telegram_pairing_expires ON telegram_pairing_codes(expires_at);

      -- Telegram notification log (audit trail)
      CREATE TABLE IF NOT EXISTS telegram_notification_log (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        consent_id TEXT,
        notification_type TEXT NOT NULL,
        category TEXT,
        agent_name TEXT,
        sent_at TEXT NOT NULL,
        delivered_at TEXT,
        error TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_telegram_log_chat ON telegram_notification_log(chat_id);
      CREATE INDEX IF NOT EXISTS idx_telegram_log_sent ON telegram_notification_log(sent_at);
    `);

    // Migration: Add last_used_at column if it doesn't exist (for existing DBs)
    this.migrateSchema();
  }

  /**
   * Run schema migrations for existing databases
   */
  private migrateSchema(): void {
    // Check if last_used_at column exists in agent_sessions
    const sessionsInfo = this.db.pragma('table_info(agent_sessions)') as Array<{ name: string }>;
    const hasLastUsedAt = sessionsInfo.some((col) => col.name === 'last_used_at');

    if (!hasLastUsedAt) {
      this.db.exec('ALTER TABLE agent_sessions ADD COLUMN last_used_at TEXT');
    }

    // Check if session_id column exists in pending_consents
    const consentsInfo = this.db.pragma('table_info(pending_consents)') as Array<{ name: string }>;
    const hasSessionId = consentsInfo.some((col) => col.name === 'session_id');

    if (!hasSessionId) {
      this.db.exec('ALTER TABLE pending_consents ADD COLUMN session_id TEXT');
    }

    // Ensure pairing_tokens table exists (for existing vaults)
    const pairingTable = this.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='pairing_tokens'"
    ).get() as { name?: string } | undefined;

    if (!pairingTable) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS pairing_tokens (
          token_hash TEXT PRIMARY KEY,
          service_id TEXT NOT NULL,
          scopes TEXT NOT NULL,
          budget_daily REAL NOT NULL,
          budget_currency TEXT NOT NULL DEFAULT 'USDC',
          budget_auto_approve_under REAL NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          used_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_pairing_tokens_expires ON pairing_tokens(expires_at);
      `);
    }

    // Ensure cloud_connect_links table exists (for existing vaults)
    const cloudConnectTable = this.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='cloud_connect_links'"
    ).get() as { name?: string } | undefined;

    if (!cloudConnectTable) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS cloud_connect_links (
          link_id TEXT PRIMARY KEY,
          secret_hash TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          name TEXT NOT NULL,
          permission_scopes TEXT NOT NULL,
          budget_daily REAL NOT NULL DEFAULT 0,
          budget_currency TEXT NOT NULL DEFAULT 'USDC',
          budget_auto_approve_under REAL NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'pending',
          match_code TEXT,
          redeemer_public_key TEXT,
          source_ip TEXT,
          source_host TEXT,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          redeemed_at TEXT,
          consumed_at TEXT,
          revoked_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cloud_connect_links_status ON cloud_connect_links(status);
        CREATE INDEX IF NOT EXISTS idx_cloud_connect_links_agent ON cloud_connect_links(agent_id);
        CREATE INDEX IF NOT EXISTS idx_cloud_connect_links_expires ON cloud_connect_links(expires_at);
      `);
    }

    // Ensure agent_connections table exists (for existing vaults)
    const agentConnectionsTable = this.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='agent_connections'"
    ).get() as { name?: string } | undefined;

    if (!agentConnectionsTable) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS agent_connections (
          agent_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          mode TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          service_id TEXT,
          service_public_key TEXT,
          permission_scopes TEXT NOT NULL,
          budget_daily REAL NOT NULL,
          budget_currency TEXT NOT NULL DEFAULT 'USDC',
          budget_auto_approve_under REAL NOT NULL DEFAULT 0,
          tier TEXT NOT NULL DEFAULT 'free',
          token_hash TEXT,
          created_at TEXT NOT NULL,
          paired_at TEXT,
          last_seen_at TEXT,
          last_request_at TEXT,
          request_count INTEGER NOT NULL DEFAULT 0,
          revoked_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_agent_connections_status ON agent_connections(status);
        CREATE INDEX IF NOT EXISTS idx_agent_connections_service ON agent_connections(service_id);
        CREATE INDEX IF NOT EXISTS idx_agent_connections_last_seen ON agent_connections(last_seen_at);
      `);
    } else {
      // Add service_public_key column if it doesn't exist (for existing vaults)
      const columns = this.db.prepare("PRAGMA table_info(agent_connections)").all() as Array<{ name: string }>;
      const hasServicePublicKey = columns.some((col) => col.name === 'service_public_key');
      if (!hasServicePublicKey) {
        this.db.exec(`ALTER TABLE agent_connections ADD COLUMN service_public_key TEXT`);
      }
    }

    // Ensure Telegram tables exist (for existing vaults)
    const telegramConfigsTable = this.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='telegram_configs'"
    ).get() as { name?: string } | undefined;

    if (!telegramConfigsTable) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS telegram_configs (
          id TEXT PRIMARY KEY,
          chat_id TEXT NOT NULL UNIQUE,
          bot_token_ciphertext BLOB NOT NULL,
          bot_token_nonce BLOB NOT NULL,
          bot_token_dek_wrapped BLOB NOT NULL,
          bot_token_dek_nonce BLOB NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          notify_consent INTEGER NOT NULL DEFAULT 1,
          rate_limit_per_hour INTEGER NOT NULL DEFAULT 30,
          last_notification_at TEXT,
          notifications_this_hour INTEGER NOT NULL DEFAULT 0,
          hour_window_start TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          paired_at TEXT,
          muted_until TEXT
        );

        CREATE TABLE IF NOT EXISTS telegram_pairing_codes (
          code TEXT PRIMARY KEY,
          vault_id TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_telegram_pairing_expires ON telegram_pairing_codes(expires_at);

        CREATE TABLE IF NOT EXISTS telegram_notification_log (
          id TEXT PRIMARY KEY,
          chat_id TEXT NOT NULL,
          consent_id TEXT,
          notification_type TEXT NOT NULL,
          category TEXT,
          agent_name TEXT,
          sent_at TEXT NOT NULL,
          delivered_at TEXT,
          error TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_telegram_log_chat ON telegram_notification_log(chat_id);
        CREATE INDEX IF NOT EXISTS idx_telegram_log_sent ON telegram_notification_log(sent_at);
      `);
    }
  }

  // ==========================================================================
  // Master Key Management
  // ==========================================================================

  /**
   * Initialize master key (called during vault init)
   *
   * Security model:
   * 1. Generate 256-bit master key (random)
   * 2. Generate 128-bit salt (random)
   * 3. Derive wrapping key from passphrase + salt using Argon2id
   * 4. Encrypt master key with wrapping key using XChaCha20-Poly1305 (AEAD)
   * 5. Store: encrypted_master_key + nonce + salt
   *
   * The AEAD encryption provides:
   * - Confidentiality: master key is encrypted
   * - Integrity: tampering is detected via authentication tag
   * - Wrong passphrase detection: decryption fails if passphrase is wrong
   *
   * @param passphrase - User's passphrase to protect the master key
   * @returns The master key (caller should store it in memory briefly, then zeroize)
   */
  async initializeMasterKey(passphrase: string): Promise<Buffer> {
    // Generate new master key and salt
    const masterKey = generateKey();
    const salt = generateSalt();

    // Derive wrapping key from passphrase using Argon2id
    const wrappingKey = deriveKeyFromPassphrase(passphrase, salt);

    try {
      // Encrypt master key with AEAD (XChaCha20-Poly1305)
      // This provides integrity - wrong passphrase will fail to decrypt
      const { ciphertext, nonce } = encrypt(masterKey, wrappingKey);

      // Store in OS Keychain first, fall back to file
      const stored = await this.storeMasterKeyInKeychain(ciphertext, nonce, salt);
      if (!stored) {
        this.storeMasterKeyInFile(ciphertext, nonce, salt);
      }
      this.writeInitializationMarker();

      this.masterKey = masterKey;
      return masterKey;
    } finally {
      // CRITICAL: Always zeroize wrapping key
      zeroize(wrappingKey);
    }
  }

  /**
   * Store an existing master key with a new passphrase
   *
   * Used for recovery: the master key is derived from the recovery mnemonic,
   * then encrypted with the user's new passphrase.
   *
   * @param masterKey - The master key (e.g., derived from recovery mnemonic)
   * @param passphrase - User's passphrase to protect the master key
   */
  async storeMasterKeyWithPassphrase(masterKey: Buffer, passphrase: string): Promise<void> {
    const salt = generateSalt();

    // Derive wrapping key from passphrase using Argon2id
    const wrappingKey = deriveKeyFromPassphrase(passphrase, salt);

    try {
      // Encrypt master key with AEAD (XChaCha20-Poly1305)
      const { ciphertext, nonce } = encrypt(masterKey, wrappingKey);

      // Store in OS Keychain first, fall back to file
      const stored = await this.storeMasterKeyInKeychain(ciphertext, nonce, salt);
      if (!stored) {
        this.storeMasterKeyInFile(ciphertext, nonce, salt);
      }
      this.writeInitializationMarker();

      this.masterKey = masterKey;
    } finally {
      // CRITICAL: Always zeroize wrapping key
      zeroize(wrappingKey);
    }
  }

  /**
   * Unlock vault with passphrase
   *
   * @param passphrase - User's passphrase
   * @returns The master key
   * @throws VaultError with code VAULT_NOT_INITIALIZED if vault not set up
   * @throws VaultError with code INTERNAL_ERROR if wrong passphrase (AEAD auth fails)
   */
  async unlock(passphrase: string): Promise<Buffer> {
    // Try keychain first, then file
    let keyData = await this.loadMasterKeyFromKeychain();
    let keySource: 'keychain' | 'file' | null = keyData ? 'keychain' : null;

    if (!keyData) {
      keyData = this.loadMasterKeyFromFile();
      keySource = keyData ? 'file' : null;
    }

    if (!keyData) {
      throw new VaultError('VAULT_NOT_INITIALIZED', 'Vault not initialized. Run dcp init');
    }

    const tryDecrypt = (data: { encryptedKey: Buffer; nonce: Buffer; salt: Buffer }): Buffer => {
      const wrappingKey = deriveKeyFromPassphrase(passphrase, data.salt);
      try {
        return decrypt(data.encryptedKey, data.nonce, wrappingKey);
      } finally {
        // CRITICAL: Always zeroize wrapping key
        zeroize(wrappingKey);
      }
    };

    try {
      // Decrypt master key using AEAD
      // If passphrase is wrong, this will throw (authentication tag mismatch)
      const masterKey = tryDecrypt(keyData);
      this.masterKey = masterKey;
      this.writeInitializationMarker();
      return masterKey;
    } catch (error) {
      // If keychain entry is stale but file exists, try file before failing.
      if (keySource === 'keychain') {
        const fileData = this.loadMasterKeyFromFile();
        if (fileData) {
          try {
            const masterKey = tryDecrypt(fileData);
            this.masterKey = masterKey;
            this.writeInitializationMarker();
            // Refresh keychain to avoid future mismatches
            await this.storeMasterKeyInKeychain(
              fileData.encryptedKey,
              fileData.nonce,
              fileData.salt
            );
            return masterKey;
          } catch {
            // Fall through to error below
          }
        }
      }

      // AEAD decryption failed - wrong passphrase or tampered data
      if (error instanceof VaultError && error.message.includes('Decryption failed')) {
        throw new VaultError(
          'INTERNAL_ERROR',
          'Wrong passphrase or corrupted vault data'
        );
      }
      throw error;
    }
  }

  /**
   * Lock vault (zeroize master key from memory)
   */
  lock(): void {
    if (this.masterKey) {
      zeroize(this.masterKey);
      this.masterKey = null;
    }
  }

  /**
   * Get cached master key (throws if locked)
   */
  getMasterKey(): Buffer {
    if (!this.masterKey) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }
    return this.masterKey;
  }

  /**
   * Set master key directly (used by trusted local session cache)
   *
   * This is intentionally not exposed to agents. It is used by the CLI
   * to restore an already-unlocked master key from a local session cache.
   */
  setMasterKey(masterKey: Buffer): void {
    this.masterKey = masterKey;
  }

  /**
   * Check if vault is unlocked
   */
  isUnlocked(): boolean {
    return this.masterKey !== null;
  }

  /**
   * Store encrypted master key in OS Keychain
   * Returns false if keychain is not available
   */
  private async storeMasterKeyInKeychain(
    encryptedKey: Buffer,
    nonce: Buffer,
    salt: Buffer
  ): Promise<boolean> {
    try {
      const kt = await getKeytar();
      if (!kt) return false;

      // Store as JSON with all components
      const data = JSON.stringify({
        encrypted_key: encryptedKey.toString('base64'),
        nonce: nonce.toString('base64'),
        salt: salt.toString('base64'),
        version: '2.0', // Version 2.0 = AEAD encryption
      });

      await kt.setPassword(KEYCHAIN_SERVICE, this.getKeychainAccount(), data);
      return true;
    } catch {
      // Keychain not available (CI, headless system, etc.)
      return false;
    }
  }

  /**
   * Load encrypted master key from OS Keychain
   * Returns null if not found or keychain not available
   */
  private async loadMasterKeyFromKeychain(): Promise<{
    encryptedKey: Buffer;
    nonce: Buffer;
    salt: Buffer;
  } | null> {
    try {
      const kt = await getKeytar();
      if (!kt) return null;

      const dataStr = await kt.getPassword(KEYCHAIN_SERVICE, this.getKeychainAccount());

      if (!dataStr) {
        return null;
      }

      const data = JSON.parse(dataStr);

      // Check version - only support v2.0 (AEAD)
      if (data.version !== '2.0') {
        // Old format - require re-initialization
        return null;
      }

      return {
        encryptedKey: Buffer.from(data.encrypted_key, 'base64'),
        nonce: Buffer.from(data.nonce, 'base64'),
        salt: Buffer.from(data.salt, 'base64'),
      };
    } catch {
      return null;
    }
  }

  /**
   * Store encrypted master key in file (fallback when keychain unavailable)
   */
  private storeMasterKeyInFile(encryptedKey: Buffer, nonce: Buffer, salt: Buffer): void {
    const keyPath = path.join(this.vaultDir, 'vault.key');
    const data = {
      encrypted_key: encryptedKey.toString('base64'),
      nonce: nonce.toString('base64'),
      salt: salt.toString('base64'),
      version: '2.0', // Version 2.0 = AEAD encryption
    };

    fs.writeFileSync(keyPath, JSON.stringify(data, null, 2), { mode: KEY_FILE_MODE });
  }

  private getInitializationMarkerPath(): string {
    return path.join(this.vaultDir, INIT_MARKER_FILE);
  }

  private getKeychainAccount(): string {
    const normalizedVaultDir = path.resolve(this.vaultDir);
    const vaultHash = createHash('sha256')
      .update(normalizedVaultDir)
      .digest('hex')
      .slice(0, 32);
    return `${KEYCHAIN_ACCOUNT_PREFIX}${vaultHash}`;
  }

  private writeInitializationMarker(): void {
    fs.writeFileSync(
      this.getInitializationMarkerPath(),
      JSON.stringify({ initialized: true, version: '1.0' }, null, 2),
      { mode: KEY_FILE_MODE }
    );
  }

  private hasInitializationMarker(): boolean {
    return fs.existsSync(this.getInitializationMarkerPath());
  }

  private hasLocalInitializationArtifacts(): boolean {
    return this.hasInitializationMarker() || this.loadMasterKeyFromFile() !== null;
  }

  private hasVaultRecords(): boolean {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM vault_records
    `);
    const row = stmt.get() as { count: number };
    return row.count > 0;
  }

  async hasStoredMasterKey(): Promise<boolean> {
    if (this.hasLocalInitializationArtifacts()) {
      return true;
    }

    const keyData = await this.loadMasterKeyFromKeychain();
    if (keyData && this.hasVaultRecords()) {
      this.writeInitializationMarker();
      return true;
    }

    return false;
  }

  async isProvisioned(): Promise<boolean> {
    const dbPath = path.join(this.vaultDir, 'vault.db');
    if (!fs.existsSync(dbPath)) return false;

    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM sqlite_master
      WHERE type='table' AND name='vault_records'
    `);
    const row = stmt.get() as { count: number };
    return row.count > 0 && (await this.hasStoredMasterKey());
  }

  /**
   * Load encrypted master key from file
   * Returns null if file doesn't exist or has wrong format
   */
  private loadMasterKeyFromFile(): {
    encryptedKey: Buffer;
    nonce: Buffer;
    salt: Buffer;
  } | null {
    const keyPath = path.join(this.vaultDir, 'vault.key');

    if (!fs.existsSync(keyPath)) {
      return null;
    }

    try {
      const data = JSON.parse(fs.readFileSync(keyPath, 'utf8'));

      // Check version - only support v2.0 (AEAD)
      if (data.version !== '2.0') {
        // Old format - require re-initialization
        return null;
      }

      return {
        encryptedKey: Buffer.from(data.encrypted_key, 'base64'),
        nonce: Buffer.from(data.nonce, 'base64'),
        salt: Buffer.from(data.salt, 'base64'),
      };
    } catch {
      return null;
    }
  }

  // ==========================================================================
  // Vault Records CRUD
  // ==========================================================================

  /**
   * Store an encrypted vault record
   */
  storeRecord(
    scope: string,
    itemType: ItemType,
    sensitivity: SensitivityLevel,
    encrypted: EncryptedPayload,
    chain?: Chain,
    publicAddress?: string
  ): VaultRecord {
    const now = new Date().toISOString();
    const id = generateId();

    const stmt = this.db.prepare(`
      INSERT INTO vault_records (
        id, scope, item_type, sensitivity, ciphertext, nonce,
        dek_wrapped, dek_nonce, chain, public_address, schema_version,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '1.0', ?, ?)
    `);

    stmt.run(
      id,
      scope,
      itemType,
      sensitivity,
      encrypted.ciphertext,
      encrypted.nonce,
      encrypted.dek_wrapped,
      encrypted.dek_nonce,
      chain || null,
      publicAddress || null,
      now,
      now
    );

    return {
      id,
      scope,
      item_type: itemType,
      sensitivity,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      dek_wrapped: encrypted.dek_wrapped,
      dek_nonce: encrypted.dek_nonce,
      chain,
      public_address: publicAddress,
      schema_version: '1.0',
      created_at: now,
      updated_at: now,
    };
  }

  /**
   * Get a vault record by scope
   */
  getRecord(scope: string): VaultRecord | null {
    const stmt = this.db.prepare('SELECT * FROM vault_records WHERE scope = ?');
    const row = stmt.get(scope) as VaultRecord | undefined;

    if (!row) return null;

    // Convert BLOB fields from Buffer
    return {
      ...row,
      ciphertext: row.ciphertext,
      nonce: row.nonce,
      dek_wrapped: row.dek_wrapped,
      dek_nonce: row.dek_nonce,
    };
  }

  /**
   * Get encrypted payload from a record
   */
  getEncryptedPayload(scope: string): EncryptedPayload | null {
    const record = this.getRecord(scope);
    if (!record) return null;

    return {
      ciphertext: record.ciphertext,
      nonce: record.nonce,
      dek_wrapped: record.dek_wrapped,
      dek_nonce: record.dek_nonce,
    };
  }

  /**
   * List all scopes (metadata only, no values)
   */
  listScopes(): Array<{
    scope: string;
    item_type: ItemType;
    sensitivity: SensitivityLevel;
    chain?: Chain;
    public_address?: string;
  }> {
    const stmt = this.db.prepare(`
      SELECT scope, item_type, sensitivity, chain, public_address
      FROM vault_records
      ORDER BY created_at DESC
    `);

    return stmt.all() as Array<{
      scope: string;
      item_type: ItemType;
      sensitivity: SensitivityLevel;
      chain?: Chain;
      public_address?: string;
    }>;
  }

  /**
   * Get wallets by chain
   */
  getWalletsByChain(chain: Chain): VaultRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM vault_records
      WHERE chain = ? AND item_type = 'WALLET_KEY'
    `);

    return stmt.all(chain) as VaultRecord[];
  }

  /**
   * Delete a vault record
   */
  deleteRecord(scope: string): boolean {
    const stmt = this.db.prepare('DELETE FROM vault_records WHERE scope = ?');
    const result = stmt.run(scope);
    return result.changes > 0;
  }

  /**
   * List all records with full metadata (for CLI)
   * Returns records with created_at/updated_at, but no decrypted data
   */
  listRecords(): Array<{
    id: string;
    scope: string;
    item_type: ItemType;
    sensitivity: SensitivityLevel;
    chain?: Chain;
    public_address?: string;
    created_at: string;
    updated_at: string;
  }> {
    const stmt = this.db.prepare(`
      SELECT id, scope, item_type, sensitivity, chain, public_address, created_at, updated_at
      FROM vault_records
      ORDER BY created_at DESC
    `);

    return stmt.all() as Array<{
      id: string;
      scope: string;
      item_type: ItemType;
      sensitivity: SensitivityLevel;
      chain?: Chain;
      public_address?: string;
      created_at: string;
      updated_at: string;
    }>;
  }

  /**
   * Create a record with automatic encryption (convenience method)
   *
   * @param options - Record options including data to encrypt
   * @returns Created record
   */
  createRecord(options: {
    scope: string;
    item_type: ItemType;
    sensitivity: SensitivityLevel;
    data: Record<string, unknown> | EncryptedPayload;
    chain?: Chain;
    public_address?: string;
  }): VaultRecord {
    const masterKey = this.getMasterKey();

    // If data is already encrypted (EncryptedPayload), use it directly
    let encrypted: EncryptedPayload;
    if ('ciphertext' in options.data && 'nonce' in options.data) {
      encrypted = options.data as EncryptedPayload;
    } else {
      // Encrypt the data
      const plaintext = Buffer.from(JSON.stringify(options.data), 'utf8');
      try {
        encrypted = envelopeEncrypt(plaintext, masterKey);
      } finally {
        // CRITICAL: Zeroize plaintext from memory
        zeroize(plaintext);
      }
    }

    return this.storeRecord(
      options.scope,
      options.item_type,
      options.sensitivity,
      encrypted,
      options.chain,
      options.public_address
    );
  }

  /**
   * Update a record's encrypted data
   *
   * @param recordId - Record ID to update
   * @param data - New data to encrypt
   * @param masterKey - Master key for encryption
   */
  updateRecord(recordId: string, data: Record<string, unknown>, masterKey: Buffer): void {
    const plaintext = Buffer.from(JSON.stringify(data), 'utf8');

    try {
      const encrypted = envelopeEncrypt(plaintext, masterKey);
      const now = new Date().toISOString();

      const stmt = this.db.prepare(`
        UPDATE vault_records SET
          ciphertext = ?,
          nonce = ?,
          dek_wrapped = ?,
          dek_nonce = ?,
          updated_at = ?
        WHERE id = ?
      `);

      stmt.run(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.dek_wrapped,
        encrypted.dek_nonce,
        now,
        recordId
      );
    } finally {
      // CRITICAL: Zeroize plaintext from memory
      zeroize(plaintext);
    }
  }

  /**
   * Update an existing wallet record with an already encrypted private key.
   *
   * Used by owner-only wallet replacement flows. This keeps the stable record
   * scope while updating both encrypted key material and public metadata.
   */
  updateWalletRecord(
    recordId: string,
    encrypted: EncryptedPayload,
    chain: Chain,
    publicAddress: string
  ): void {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE vault_records SET
        ciphertext = ?,
        nonce = ?,
        dek_wrapped = ?,
        dek_nonce = ?,
        chain = ?,
        public_address = ?,
        updated_at = ?
      WHERE id = ?
    `);

    stmt.run(
      encrypted.ciphertext,
      encrypted.nonce,
      encrypted.dek_wrapped,
      encrypted.dek_nonce,
      chain,
      publicAddress,
      now,
      recordId
    );
  }

  // ==========================================================================
  // Agent Sessions CRUD
  // ==========================================================================

  /**
   * Create an agent session
   */
  createSession(
    agentName: string,
    grantedScopes: string[],
    consentMode: ConsentMode,
    expiresAt: Date,
    options?: {
      agentFingerprint?: string;
      marketplace?: string;
      trustTier?: TrustTier;
      purpose?: string;
      profileName?: string;
      tokenId?: string;
    }
  ): AgentSession {
    const now = new Date().toISOString();
    const id = generateId();

    const stmt = this.db.prepare(`
      INSERT INTO agent_sessions (
        id, agent_name, agent_fingerprint, marketplace, trust_tier,
        granted_scopes, purpose, consent_mode, profile_name, token_id,
        expires_at, created_at, last_used_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      agentName,
      options?.agentFingerprint || null,
      options?.marketplace || null,
      options?.trustTier || 'unknown',
      JSON.stringify(grantedScopes),
      options?.purpose || null,
      consentMode,
      options?.profileName || null,
      options?.tokenId || null,
      expiresAt.toISOString(),
      now,
      now // last_used_at = created_at initially
    );

    return {
      id,
      agent_name: agentName,
      agent_fingerprint: options?.agentFingerprint,
      marketplace: options?.marketplace,
      trust_tier: options?.trustTier || 'unknown',
      granted_scopes: grantedScopes,
      purpose: options?.purpose,
      consent_mode: consentMode,
      profile_name: options?.profileName,
      token_id: options?.tokenId,
      expires_at: expiresAt.toISOString(),
      created_at: now,
      last_used_at: now,
    };
  }

  /**
   * Get active session by agent name
   */
  getActiveSession(agentName: string): AgentSession | null {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      SELECT * FROM agent_sessions
      WHERE agent_name = ?
        AND expires_at > ?
        AND revoked_at IS NULL
      ORDER BY created_at DESC
      LIMIT 1
    `);

    const row = stmt.get(agentName, now) as (AgentSession & { granted_scopes: string }) | undefined;

    if (!row) return null;

    return {
      ...row,
      granted_scopes: JSON.parse(row.granted_scopes),
    };
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): AgentSession | null {
    const stmt = this.db.prepare('SELECT * FROM agent_sessions WHERE id = ?');
    const row = stmt.get(sessionId) as (AgentSession & { granted_scopes: string }) | undefined;

    if (!row) return null;

    return {
      ...row,
      granted_scopes: JSON.parse(row.granted_scopes),
    };
  }

  /**
   * Update session last_used_at timestamp (touch)
   */
  touchSession(sessionId: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare('UPDATE agent_sessions SET last_used_at = ? WHERE id = ?');
    const result = stmt.run(now, sessionId);
    return result.changes > 0;
  }

  /**
   * Revoke a session
   */
  revokeSession(sessionId: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare('UPDATE agent_sessions SET revoked_at = ? WHERE id = ?');
    const result = stmt.run(now, sessionId);
    return result.changes > 0;
  }

  /**
   * Revoke all sessions for an agent
   */
  revokeAgentSessions(agentName: string): number {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE agent_sessions
      SET revoked_at = ?
      WHERE agent_name = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(now, agentName);
    return result.changes;
  }

  /**
   * List all active sessions
   */
  listActiveSessions(): AgentSession[] {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      SELECT * FROM agent_sessions
      WHERE expires_at > ? AND revoked_at IS NULL
      ORDER BY created_at DESC
    `);

    const rows = stmt.all(now) as Array<AgentSession & { granted_scopes: string }>;

    return rows.map((row) => ({
      ...row,
      granted_scopes: JSON.parse(row.granted_scopes),
    }));
  }

  /**
   * List all active sessions for a specific agent
   */
  listActiveSessionsForAgent(agentName: string): AgentSession[] {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      SELECT * FROM agent_sessions
      WHERE agent_name = ?
        AND expires_at > ?
        AND revoked_at IS NULL
      ORDER BY created_at DESC
    `);

    const rows = stmt.all(agentName, now) as Array<AgentSession & { granted_scopes: string }>;

    return rows.map((row) => ({
      ...row,
      granted_scopes: JSON.parse(row.granted_scopes),
    }));
  }

  /**
   * List all sessions (including expired and revoked)
   */
  listAllSessions(): AgentSession[] {
    const stmt = this.db.prepare(`
      SELECT * FROM agent_sessions
      ORDER BY created_at DESC
    `);

    const rows = stmt.all() as Array<AgentSession & { granted_scopes: string }>;

    return rows.map((row) => ({
      ...row,
      granted_scopes: JSON.parse(row.granted_scopes),
    }));
  }

  // ==========================================================================
  // Spend Events CRUD
  // ==========================================================================

  /**
   * Record a spend event
   */
  recordSpend(
    sessionId: string,
    amount: number,
    currency: string,
    chain: Chain,
    operation: string,
    status: SpendStatus,
    options?: {
      destination?: string;
      idempotencyKey?: string;
      txSignature?: string;
    }
  ): SpendEvent {
    const now = new Date().toISOString();
    const id = generateId();

    const stmt = this.db.prepare(`
      INSERT INTO spend_events (
        id, agent_session_id, amount, currency, chain, operation,
        destination, idempotency_key, status, tx_signature, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
      stmt.run(
        id,
        sessionId,
        amount,
        currency,
        chain,
        operation,
        options?.destination || null,
        options?.idempotencyKey || null,
        status,
        options?.txSignature || null,
        now
      );
    } catch (error: unknown) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new VaultError('IDEMPOTENCY_CONFLICT', 'Duplicate idempotency key');
      }
      throw error;
    }

    return {
      id,
      agent_session_id: sessionId,
      amount,
      currency,
      chain,
      operation,
      destination: options?.destination,
      idempotency_key: options?.idempotencyKey,
      status,
      tx_signature: options?.txSignature,
      created_at: now,
    };
  }

  /**
   * Get daily spend total for a currency
   */
  getDailySpend(currency: string, chain: Chain): number {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const stmt = this.db.prepare(`
      SELECT COALESCE(SUM(amount), 0) as total
      FROM spend_events
      WHERE currency = ?
        AND chain = ?
        AND status = 'committed'
        AND created_at > ?
    `);

    const row = stmt.get(currency, chain, twentyFourHoursAgo) as { total: number };
    return row.total;
  }

  /**
   * Get spend event by idempotency key
   */
  getSpendByIdempotencyKey(idempotencyKey: string): SpendEvent | null {
    const stmt = this.db.prepare('SELECT * FROM spend_events WHERE idempotency_key = ?');
    return stmt.get(idempotencyKey) as SpendEvent | null;
  }

  // ==========================================================================
  // Audit Events
  // ==========================================================================

  /**
   * Log an audit event
   */
  logAudit(
    eventType: AuditEventType,
    outcome: string,
    options?: {
      agentName?: string;
      scope?: string;
      operation?: string;
      details?: string;
    }
  ): AuditEvent {
    const now = new Date().toISOString();
    const id = generateId();

    const stmt = this.db.prepare(`
      INSERT INTO audit_events (
        id, event_type, agent_name, scope, operation, details, outcome, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      eventType,
      options?.agentName || null,
      options?.scope || null,
      options?.operation || null,
      options?.details || null,
      outcome,
      now
    );

    return {
      id,
      event_type: eventType,
      agent_name: options?.agentName,
      scope: options?.scope,
      operation: options?.operation,
      details: options?.details,
      outcome,
      created_at: now,
    };
  }

  /**
   * Get recent audit events
   */
  getAuditEvents(limit: number = 100, filters?: {
    eventType?: AuditEventType;
    agentName?: string;
    since?: Date;
  }): AuditEvent[] {
    let query = 'SELECT * FROM audit_events WHERE 1=1';
    const params: unknown[] = [];

    if (filters?.eventType) {
      query += ' AND event_type = ?';
      params.push(filters.eventType);
    }

    if (filters?.agentName) {
      query += ' AND agent_name = ?';
      params.push(filters.agentName);
    }

    if (filters?.since) {
      query += ' AND created_at > ?';
      params.push(filters.since.toISOString());
    }

    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(query);
    return stmt.all(...params) as AuditEvent[];
  }

  // ==========================================================================
  // Pending Consents
  // ==========================================================================

  /**
   * Find existing pending consent for same agent/action/scope (deduplication)
   */
  findPendingConsent(agentName: string, action: string, scope: string): PendingConsent | null {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      SELECT * FROM pending_consents
      WHERE agent_name = ? AND action = ? AND scope = ?
        AND status = 'pending' AND expires_at > ?
      ORDER BY created_at DESC
      LIMIT 1
    `);
    return stmt.get(agentName, action, scope, now) as PendingConsent | null;
  }

  /**
   * Create a pending consent request (with deduplication)
   * If an existing pending consent exists for the same agent/action/scope, returns that instead
   * @returns Object with consent and isNew flag (false if deduped)
   */
  createPendingConsent(
    agentName: string,
    action: string,
    scope: string,
    details?: string
  ): PendingConsentCreateResult {
    // DEDUPLICATION: Check if there's already a pending consent for this agent/action/scope
    const existing = this.findPendingConsent(agentName, action, scope);
    if (existing) {
      return { ...existing, consent: existing, isNew: false };
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes
    const id = generateId();

    const stmt = this.db.prepare(`
      INSERT INTO pending_consents (
        id, agent_name, action, scope, details, status, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
    `);

    stmt.run(id, agentName, action, scope, details || null, now.toISOString(), expiresAt.toISOString());

    const consent: PendingConsent = {
      id,
      agent_name: agentName,
      action,
      scope,
      details,
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    return { ...consent, consent, isNew: true };
  }

  /**
   * Get pending consent by ID
   */
  getPendingConsent(id: string): PendingConsent | null {
    const stmt = this.db.prepare('SELECT * FROM pending_consents WHERE id = ?');
    return stmt.get(id) as PendingConsent | null;
  }

  /**
   * Resolve a pending consent
   * @param id - Consent ID
   * @param status - Resolution status
   * @param sessionId - Optional session ID if a session was created during approval
   */
  resolveConsent(id: string, status: ConsentStatus, sessionId?: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE pending_consents
      SET status = ?, resolved_at = ?, session_id = ?
      WHERE id = ? AND status = 'pending'
    `);
    const result = stmt.run(status, now, sessionId || null, id);
    return result.changes > 0;
  }

  /**
   * Find an approved consent for this agent/action/scope and consume it (mark as 'consumed')
   * This implements "approve once" semantics - after one use, the consent cannot be reused
   * @returns The consumed consent if found, null otherwise
   */
  consumeApprovedConsent(agentName: string, action: string, scope: string): PendingConsent | null {
    const now = new Date().toISOString();

    // Find an approved consent for this agent/action/scope
    const findStmt = this.db.prepare(`
      SELECT * FROM pending_consents
      WHERE agent_name = ? AND action = ? AND scope = ?
        AND status = 'approved'
      ORDER BY resolved_at DESC
      LIMIT 1
    `);
    const consent = findStmt.get(agentName, action, scope) as PendingConsent | null;

    if (!consent) {
      return null;
    }

    // Mark it as consumed so it can't be reused
    const updateStmt = this.db.prepare(`
      UPDATE pending_consents
      SET status = 'consumed', resolved_at = ?
      WHERE id = ? AND status = 'approved'
    `);
    const result = updateStmt.run(now, consent.id);

    if (result.changes === 0) {
      // Race condition - someone else consumed it
      return null;
    }

    return { ...consent, status: 'consumed' };
  }

  /**
   * Get pending consents (not expired)
   */
  getPendingConsents(): PendingConsent[] {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      SELECT * FROM pending_consents
      WHERE status = 'pending' AND expires_at > ?
      ORDER BY created_at DESC
    `);
    return stmt.all(now) as PendingConsent[];
  }

  /**
   * Expire old pending consents
   */
  expireOldConsents(): number {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE pending_consents
      SET status = 'expired', resolved_at = ?
      WHERE status = 'pending' AND expires_at < ?
    `);
    const result = stmt.run(now, now);
    return result.changes;
  }

  // ==========================================================================
  // Trusted Services CRUD (protocol spec section B2)
  // ==========================================================================

  /**
   * Add a trusted service
   *
   * @param service - Service configuration
   * @returns Created trusted service
   * @throws VaultError with SERVICE_ALREADY_TRUSTED if service already exists
   */
  addTrustedService(service: Omit<TrustedService, 'trusted_at' | 'enabled' | 'connected_at'>): TrustedService {
    const now = new Date().toISOString();

    // Check if service already exists
    const existing = this.getTrustedService(service.service_id);
    if (existing) {
      throw new VaultError('SERVICE_ALREADY_TRUSTED', `Service '${service.service_id}' is already trusted`);
    }

    const stmt = this.db.prepare(`
      INSERT INTO trusted_services (
        service_id, name, public_key, scopes,
        budget_daily, budget_currency, budget_auto_approve_under,
        trusted_at, enabled, verified
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    `);

    stmt.run(
      service.service_id,
      service.name,
      service.public_key,
      JSON.stringify(service.scopes),
      service.budget.daily,
      service.budget.currency,
      service.budget.auto_approve_under,
      now,
      service.verified ? 1 : 0
    );

    // Log audit event
    this.logAudit('CONFIG', 'success', {
      operation: 'trust_service',
      details: JSON.stringify({
        service_id: service.service_id,
        scopes: service.scopes,
        budget_daily: service.budget.daily,
      }),
    });

    return {
      ...service,
      trusted_at: now,
      enabled: true,
    };
  }

  /**
   * Get a trusted service by ID
   */
  getTrustedService(serviceId: string): TrustedService | null {
    const stmt = this.db.prepare('SELECT * FROM trusted_services WHERE service_id = ?');
    const row = stmt.get(serviceId) as {
      service_id: string;
      name: string;
      public_key: string;
      scopes: string;
      budget_daily: number;
      budget_currency: string;
      budget_auto_approve_under: number;
      trusted_at: string;
      connected_at: string | null;
      enabled: number;
      verified: number;
    } | undefined;

    if (!row) return null;

    return {
      service_id: row.service_id,
      name: row.name,
      public_key: row.public_key,
      scopes: JSON.parse(row.scopes),
      budget: {
        daily: row.budget_daily,
        currency: row.budget_currency,
        auto_approve_under: row.budget_auto_approve_under,
      },
      trusted_at: row.trusted_at,
      connected_at: row.connected_at || undefined,
      enabled: row.enabled === 1,
      verified: row.verified === 1,
    };
  }

  /**
   * List all trusted services
   */
  listTrustedServices(enabledOnly = false): TrustedService[] {
    let query = 'SELECT * FROM trusted_services';
    if (enabledOnly) {
      query += ' WHERE enabled = 1';
    }
    query += ' ORDER BY trusted_at DESC';

    const stmt = this.db.prepare(query);
    const rows = stmt.all() as Array<{
      service_id: string;
      name: string;
      public_key: string;
      scopes: string;
      budget_daily: number;
      budget_currency: string;
      budget_auto_approve_under: number;
      trusted_at: string;
      connected_at: string | null;
      enabled: number;
      verified: number;
    }>;

    return rows.map((row) => ({
      service_id: row.service_id,
      name: row.name,
      public_key: row.public_key,
      scopes: JSON.parse(row.scopes),
      budget: {
        daily: row.budget_daily,
        currency: row.budget_currency,
        auto_approve_under: row.budget_auto_approve_under,
      },
      trusted_at: row.trusted_at,
      connected_at: row.connected_at || undefined,
      enabled: row.enabled === 1,
      verified: row.verified === 1,
    }));
  }

  /**
   * Update a trusted service
   */
  updateTrustedService(
    serviceId: string,
    updates: Partial<Pick<TrustedService, 'name' | 'public_key' | 'scopes' | 'budget' | 'enabled' | 'verified'>>
  ): boolean {
    const existing = this.getTrustedService(serviceId);
    if (!existing) {
      throw new VaultError('SERVICE_NOT_FOUND', `Service '${serviceId}' not found`);
    }

    const fields: string[] = [];
    const values: unknown[] = [];

    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.public_key !== undefined) {
      fields.push('public_key = ?');
      values.push(updates.public_key);
    }
    if (updates.scopes !== undefined) {
      fields.push('scopes = ?');
      values.push(JSON.stringify(updates.scopes));
    }
    if (updates.budget !== undefined) {
      fields.push('budget_daily = ?', 'budget_currency = ?', 'budget_auto_approve_under = ?');
      values.push(updates.budget.daily, updates.budget.currency, updates.budget.auto_approve_under);
    }
    if (updates.enabled !== undefined) {
      fields.push('enabled = ?');
      values.push(updates.enabled ? 1 : 0);
    }
    if (updates.verified !== undefined) {
      fields.push('verified = ?');
      values.push(updates.verified ? 1 : 0);
    }

    if (fields.length === 0) return false;

    values.push(serviceId);
    const stmt = this.db.prepare(`UPDATE trusted_services SET ${fields.join(', ')} WHERE service_id = ?`);
    const result = stmt.run(...values);

    // Log audit event
    this.logAudit('CONFIG', 'success', {
      operation: 'update_service',
      details: JSON.stringify({ service_id: serviceId, updates }),
    });

    return result.changes > 0;
  }

  /**
   * Mark a service as connected (after dcp connect)
   */
  markServiceConnected(serviceId: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare('UPDATE trusted_services SET connected_at = ? WHERE service_id = ?');
    const result = stmt.run(now, serviceId);

    // Log audit event
    this.logAudit('CONFIG', 'success', {
      operation: 'connect_service',
      details: JSON.stringify({ service_id: serviceId }),
    });

    return result.changes > 0;
  }

  /**
   * Revoke (delete) a trusted service
   */
  revokeTrustedService(serviceId: string): boolean {
    const stmt = this.db.prepare('DELETE FROM trusted_services WHERE service_id = ?');
    const result = stmt.run(serviceId);

    if (result.changes > 0) {
      // Log audit event
      this.logAudit('REVOKE', 'success', {
        operation: 'revoke_service',
        details: JSON.stringify({ service_id: serviceId }),
      });
    }

    return result.changes > 0;
  }

  // ==========================================================================
  // Agent Connections CRUD (DCP v1 Agent Connectivity)
  // ==========================================================================

  private rowToAgentConnection(row: {
    agent_id: string;
    name: string;
    mode: AgentConnectionMode;
    status: AgentConnection['status'];
    service_id: string | null;
    service_public_key: string | null;
    permission_scopes: string;
    budget_daily: number;
    budget_currency: string;
    budget_auto_approve_under: number;
    tier: AgentConnectionTier;
    token_hash: string | null;
    created_at: string;
    paired_at: string | null;
    last_seen_at: string | null;
    last_request_at: string | null;
    request_count: number;
    revoked_at: string | null;
  }): AgentConnection {
    return {
      agent_id: row.agent_id,
      name: row.name,
      mode: row.mode,
      status: row.status,
      service_id: row.service_id || undefined,
      service_public_key: row.service_public_key || undefined,
      permission_scopes: JSON.parse(row.permission_scopes),
      budget: {
        daily: row.budget_daily,
        currency: row.budget_currency,
        auto_approve_under: row.budget_auto_approve_under,
      },
      tier: row.tier,
      token_hash: row.token_hash || undefined,
      created_at: row.created_at,
      paired_at: row.paired_at || undefined,
      last_seen_at: row.last_seen_at || undefined,
      last_request_at: row.last_request_at || undefined,
      request_count: row.request_count,
      revoked_at: row.revoked_at || undefined,
    };
  }

  /**
   * Create an agent connection record.
   */
  createAgentConnection(input: {
    agent_id?: string;
    name: string;
    mode: AgentConnectionMode;
    service_id?: string;
    permission_scopes: string[];
    budget: { daily: number; currency: string; auto_approve_under: number };
    tier?: AgentConnectionTier;
    token_hash?: string;
  }): AgentConnection {
    const now = new Date().toISOString();
    const agentId = input.agent_id || `agent_${generateId()}`;
    const tier = input.tier || 'free';

    const stmt = this.db.prepare(`
      INSERT INTO agent_connections (
        agent_id, name, mode, status, service_id, permission_scopes,
        budget_daily, budget_currency, budget_auto_approve_under,
        tier, token_hash, created_at
      ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      agentId,
      input.name,
      input.mode,
      input.service_id || null,
      JSON.stringify(input.permission_scopes),
      input.budget.daily,
      input.budget.currency,
      input.budget.auto_approve_under,
      tier,
      input.token_hash || null,
      now
    );

    this.logAudit('CONFIG', 'success', {
      operation: 'create_agent_connection',
      details: JSON.stringify({
        agent_id: agentId,
        name: input.name,
        mode: input.mode,
        service_id: input.service_id,
      }),
    });

    return {
      agent_id: agentId,
      name: input.name,
      mode: input.mode,
      status: 'pending',
      service_id: input.service_id,
      permission_scopes: input.permission_scopes,
      budget: input.budget,
      tier,
      token_hash: input.token_hash,
      created_at: now,
      request_count: 0,
    };
  }

  /**
   * Get an agent connection by ID.
   */
  getAgentConnection(agentId: string): AgentConnection | null {
    const stmt = this.db.prepare('SELECT * FROM agent_connections WHERE agent_id = ?');
    const row = stmt.get(agentId) as Parameters<typeof this.rowToAgentConnection>[0] | undefined;
    return row ? this.rowToAgentConnection(row) : null;
  }

  /**
   * Get an agent connection by name (for local request permission checking).
   * Returns the most recently active agent with this name.
   */
  getAgentConnectionByName(name: string): AgentConnection | null {
    const stmt = this.db.prepare(`
      SELECT * FROM agent_connections
      WHERE name = ? AND status = 'active' AND revoked_at IS NULL
      ORDER BY last_seen_at DESC, paired_at DESC
      LIMIT 1
    `);
    const row = stmt.get(name) as Parameters<typeof this.rowToAgentConnection>[0] | undefined;
    return row ? this.rowToAgentConnection(row) : null;
  }

  /**
   * List agent connections ordered by most recent activity.
   */
  listAgentConnections(): AgentConnection[] {
    const stmt = this.db.prepare(`
      SELECT * FROM agent_connections
      ORDER BY
        CASE WHEN last_seen_at IS NULL THEN 1 ELSE 0 END,
        last_seen_at DESC,
        created_at DESC
    `);
    const rows = stmt.all() as Array<Parameters<typeof this.rowToAgentConnection>[0]>;
    return rows.map((row) => this.rowToAgentConnection(row));
  }

  /**
   * Mark an agent as paired and active.
   * Per protocol spec section 7.3, stores the agent's service public key for relay authentication.
   */
  markAgentPaired(agentId: string, tokenHash?: string, servicePublicKey?: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE agent_connections
      SET status = 'active',
          paired_at = COALESCE(paired_at, ?),
          last_seen_at = ?,
          token_hash = COALESCE(?, token_hash),
          service_public_key = COALESCE(?, service_public_key)
      WHERE agent_id = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(now, now, tokenHash || null, servicePublicKey || null, agentId);
    return result.changes > 0;
  }

  /**
   * Record agent heartbeat.
   */
  recordAgentHeartbeat(agentId: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE agent_connections
      SET status = 'active', last_seen_at = ?
      WHERE agent_id = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(now, agentId);
    return result.changes > 0;
  }

  /**
   * Record an agent request for dashboard counters.
   * Also updates last_seen_at since a request means the agent is active.
   */
  recordAgentRequest(agentId: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE agent_connections
      SET last_request_at = ?, last_seen_at = ?, request_count = request_count + 1
      WHERE agent_id = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(now, now, agentId);
    return result.changes > 0;
  }

  /**
   * Revoke an agent connection without deleting history.
   */
  revokeAgentConnection(agentId: string): boolean {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE agent_connections
      SET status = 'revoked', revoked_at = ?, token_hash = NULL
      WHERE agent_id = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(now, agentId);

    if (result.changes > 0) {
      this.logAudit('REVOKE', 'success', {
        operation: 'revoke_agent_connection',
        details: JSON.stringify({ agent_id: agentId }),
      });
    }

    return result.changes > 0;
  }

  /**
   * Delete an agent connection completely (revokes and removes from DB).
   */
  deleteAgentConnection(agentId: string): boolean {
    // First revoke to clear the token
    this.revokeAgentConnection(agentId);

    // Then delete from database
    const stmt = this.db.prepare(`
      DELETE FROM agent_connections
      WHERE agent_id = ?
    `);
    const result = stmt.run(agentId);

    if (result.changes > 0) {
      this.logAudit('REVOKE', 'success', {
        operation: 'delete_agent_connection',
        details: JSON.stringify({ agent_id: agentId }),
      });
    }

    return result.changes > 0;
  }

  /**
   * Update an agent connection's permissions and budget.
   * Only allows updating non-revoked agents.
   */
  updateAgentConnection(
    agentId: string,
    updates: {
      permission_scopes?: string[];
      budget_daily?: number;
      budget_currency?: string;
      budget_auto_approve_under?: number;
    }
  ): boolean {
    // Verify agent exists and is not revoked
    const agent = this.getAgentConnection(agentId);
    if (!agent || agent.status === 'revoked') {
      return false;
    }

    // Build dynamic UPDATE statement
    const setClauses: string[] = [];
    const values: (string | number)[] = [];

    if (updates.permission_scopes !== undefined) {
      setClauses.push('permission_scopes = ?');
      values.push(JSON.stringify(updates.permission_scopes));
    }
    if (updates.budget_daily !== undefined) {
      setClauses.push('budget_daily = ?');
      values.push(updates.budget_daily);
    }
    if (updates.budget_currency !== undefined) {
      setClauses.push('budget_currency = ?');
      values.push(updates.budget_currency);
    }
    if (updates.budget_auto_approve_under !== undefined) {
      setClauses.push('budget_auto_approve_under = ?');
      values.push(updates.budget_auto_approve_under);
    }

    if (setClauses.length === 0) {
      return true; // Nothing to update
    }

    values.push(agentId);
    const stmt = this.db.prepare(`
      UPDATE agent_connections
      SET ${setClauses.join(', ')}
      WHERE agent_id = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(...values);

    if (result.changes > 0) {
      this.logAudit('CONFIG', 'success', {
        operation: 'update_agent_connection',
        details: JSON.stringify({ agent_id: agentId, updates }),
      });
    }

    return result.changes > 0;
  }

  // ==========================================================================
  // Pairing Tokens (Proxy Pairing Flow)
  // ==========================================================================

  /**
   * Create a pairing token for a service/proxy
   */
  createPairingToken(input: {
    service_id: string;
    scopes: string[];
    budget: { daily: number; currency: string; auto_approve_under: number };
    ttl_seconds?: number;
  }): { token: string; expires_at: string } {
    const now = new Date();
    const ttlSeconds = input.ttl_seconds ?? 600;
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    const token = randomBytes(32).toString('base64url');
    const tokenHash = createHash('sha256').update(token).digest('hex');

    const stmt = this.db.prepare(`
      INSERT INTO pairing_tokens (
        token_hash, service_id, scopes,
        budget_daily, budget_currency, budget_auto_approve_under,
        created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      tokenHash,
      input.service_id,
      JSON.stringify(input.scopes),
      input.budget.daily,
      input.budget.currency,
      input.budget.auto_approve_under,
      now.toISOString(),
      expiresAt.toISOString()
    );

    this.logAudit('CONFIG', 'success', {
      operation: 'pairing_token',
      details: JSON.stringify({
        service_id: input.service_id,
        scopes: input.scopes,
        expires_at: expiresAt.toISOString(),
      }),
    });

    return { token, expires_at: expiresAt.toISOString() };
  }

  /**
   * Get a pairing token record by plaintext token
   */
  getPairingToken(token: string): {
    service_id: string;
    scopes: string[];
    budget: { daily: number; currency: string; auto_approve_under: number };
    expires_at: string;
    used_at?: string | null;
  } | null {
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const stmt = this.db.prepare('SELECT * FROM pairing_tokens WHERE token_hash = ?');
    const row = stmt.get(tokenHash) as {
      service_id: string;
      scopes: string;
      budget_daily: number;
      budget_currency: string;
      budget_auto_approve_under: number;
      expires_at: string;
      used_at: string | null;
    } | undefined;

    if (!row) return null;

    const now = new Date();
    const expires = new Date(row.expires_at);
    if (expires < now) {
      return null;
    }

    if (row.used_at) {
      return null;
    }

    return {
      service_id: row.service_id,
      scopes: JSON.parse(row.scopes),
      budget: {
        daily: row.budget_daily,
        currency: row.budget_currency,
        auto_approve_under: row.budget_auto_approve_under,
      },
      expires_at: row.expires_at,
      used_at: row.used_at,
    };
  }

  /**
   * Mark a pairing token as used
   */
  markPairingTokenUsed(token: string): boolean {
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const now = new Date().toISOString();
    const stmt = this.db.prepare('UPDATE pairing_tokens SET used_at = ? WHERE token_hash = ?');
    const result = stmt.run(now, tokenHash);
    return result.changes > 0;
  }

  // ==========================================================================
  // Cloud-Connect Links (Cloud Agent Connect feature)
  // ==========================================================================

  private rowToCloudConnectLink(row: {
    link_id: string;
    agent_id: string;
    name: string;
    permission_scopes: string;
    budget_daily: number;
    budget_currency: string;
    budget_auto_approve_under: number;
    status: string;
    match_code: string | null;
    redeemer_public_key: string | null;
    source_ip: string | null;
    source_host: string | null;
    created_at: string;
    expires_at: string;
    redeemed_at: string | null;
    consumed_at: string | null;
    revoked_at: string | null;
  }): CloudConnectLink {
    return {
      link_id: row.link_id,
      agent_id: row.agent_id,
      name: row.name,
      permission_scopes: JSON.parse(row.permission_scopes),
      budget: {
        daily: row.budget_daily,
        currency: row.budget_currency,
        auto_approve_under: row.budget_auto_approve_under,
      },
      status: row.status as CloudConnectLinkStatus,
      match_code: row.match_code || undefined,
      redeemer_public_key: row.redeemer_public_key || undefined,
      source_ip: row.source_ip || undefined,
      source_host: row.source_host || undefined,
      created_at: row.created_at,
      expires_at: row.expires_at,
      redeemed_at: row.redeemed_at || undefined,
      consumed_at: row.consumed_at || undefined,
      revoked_at: row.revoked_at || undefined,
    };
  }

  /** Constant-time compare of two equal-length hex digests. */
  private hexDigestsEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    try {
      return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    } catch {
      return false;
    }
  }

  /**
   * Persist a newly-issued Cloud-Connect link (status='pending').
   * The secret is stored only as a SHA-256 hash; the plaintext lives only in
   * the link token handed to the user.
   */
  createCloudConnectLink(input: {
    link_id: string;
    secret: string;
    agent_id: string;
    name: string;
    permission_scopes: string[];
    budget: { daily: number; currency: string; auto_approve_under: number };
    expires_at: string;
  }): CloudConnectLink {
    const now = new Date().toISOString();
    const secretHash = createHash('sha256').update(input.secret).digest('hex');

    this.db
      .prepare(
        `INSERT INTO cloud_connect_links (
          link_id, secret_hash, agent_id, name, permission_scopes,
          budget_daily, budget_currency, budget_auto_approve_under,
          status, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
      )
      .run(
        input.link_id,
        secretHash,
        input.agent_id,
        input.name,
        JSON.stringify(input.permission_scopes),
        input.budget.daily,
        input.budget.currency,
        input.budget.auto_approve_under,
        now,
        input.expires_at
      );

    this.logAudit('CONFIG', 'success', {
      operation: 'cloud_connect_link_issued',
      details: JSON.stringify({
        link_id: input.link_id,
        agent_id: input.agent_id,
        name: input.name,
      }),
    });

    return this.getCloudConnectLink(input.link_id)!;
  }

  /** Get a Cloud-Connect link by id. */
  getCloudConnectLink(linkId: string): CloudConnectLink | null {
    const row = this.db
      .prepare('SELECT * FROM cloud_connect_links WHERE link_id = ?')
      .get(linkId) as Parameters<typeof this.rowToCloudConnectLink>[0] | undefined;
    return row ? this.rowToCloudConnectLink(row) : null;
  }

  /** Get the most recent Cloud-Connect link for an agent. */
  getCloudConnectLinkByAgent(agentId: string): CloudConnectLink | null {
    const row = this.db
      .prepare(
        'SELECT * FROM cloud_connect_links WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1'
      )
      .get(agentId) as Parameters<typeof this.rowToCloudConnectLink>[0] | undefined;
    return row ? this.rowToCloudConnectLink(row) : null;
  }

  /** List all Cloud-Connect links (newest first). */
  listCloudConnectLinks(): CloudConnectLink[] {
    const rows = this.db
      .prepare('SELECT * FROM cloud_connect_links ORDER BY created_at DESC')
      .all() as Array<Parameters<typeof this.rowToCloudConnectLink>[0]>;
    return rows.map((row) => this.rowToCloudConnectLink(row));
  }

  /** List links awaiting on-device approval (status='redeemed'). */
  listPendingCloudConnectApprovals(): CloudConnectLink[] {
    const rows = this.db
      .prepare(
        "SELECT * FROM cloud_connect_links WHERE status = 'redeemed' ORDER BY redeemed_at DESC"
      )
      .all() as Array<Parameters<typeof this.rowToCloudConnectLink>[0]>;
    return rows.map((row) => this.rowToCloudConnectLink(row));
  }

  /**
   * Redeem a Cloud-Connect link (single-use). Validates the link is pending,
   * unexpired, and the secret matches; then creates a PENDING agent connection
   * (inert until approved — Rule #8) and transitions the link to 'redeemed'.
   * Atomic: the whole thing runs in one transaction.
   */
  redeemCloudConnectLink(input: {
    link_id: string;
    secret: string;
    redeemer_public_key: string;
    match_code: string;
    mode?: AgentConnectionMode;
    source_ip?: string;
    source_host?: string;
  }): { ok: boolean; reason?: string; agent_id?: string; match_code?: string } {
    const presentedHash = createHash('sha256').update(input.secret).digest('hex');

    const txn = this.db.transaction(() => {
      const link = this.getCloudConnectLink(input.link_id);
      if (!link) return { ok: false as const, reason: 'LINK_NOT_FOUND' };
      if (link.status !== 'pending') {
        return { ok: false as const, reason: `LINK_${link.status.toUpperCase()}` };
      }
      if (new Date(link.expires_at) < new Date()) {
        this.db
          .prepare(
            "UPDATE cloud_connect_links SET status='expired' WHERE link_id=? AND status='pending'"
          )
          .run(input.link_id);
        return { ok: false as const, reason: 'LINK_EXPIRED' };
      }

      const secretRow = this.db
        .prepare('SELECT secret_hash FROM cloud_connect_links WHERE link_id = ?')
        .get(input.link_id) as { secret_hash: string } | undefined;
      if (!secretRow || !this.hexDigestsEqual(secretRow.secret_hash, presentedHash)) {
        return { ok: false as const, reason: 'BAD_SECRET' };
      }

      // Create the PENDING agent connection — no authority until approved.
      this.createAgentConnection({
        agent_id: link.agent_id,
        name: link.name,
        mode: input.mode || 'mcp',
        permission_scopes: link.permission_scopes,
        budget: link.budget,
      });

      // Single-use transition (guarded on status to defeat double-redeem races).
      const now = new Date().toISOString();
      const upd = this.db
        .prepare(
          `UPDATE cloud_connect_links
           SET status='redeemed', match_code=?, redeemer_public_key=?,
               source_ip=?, source_host=?, redeemed_at=?
           WHERE link_id=? AND status='pending'`
        )
        .run(
          input.match_code,
          input.redeemer_public_key,
          input.source_ip || null,
          input.source_host || null,
          now,
          input.link_id
        );
      if (upd.changes === 0) return { ok: false as const, reason: 'RACE' };

      return { ok: true as const, agent_id: link.agent_id, match_code: input.match_code };
    });

    const result = txn();
    if (result.ok) {
      this.logAudit('CONFIG', 'success', {
        operation: 'cloud_connect_link_redeemed',
        details: JSON.stringify({ link_id: input.link_id, agent_id: result.agent_id }),
      });
    }
    return result;
  }

  /**
   * Approve a redeemed Cloud-Connect link: bind the agent's presented public key
   * and mark it active. The session token is minted separately when the agent
   * authenticates its status poll (so the plaintext token is never stored).
   */
  approveCloudConnectLink(
    linkId: string
  ): { ok: boolean; reason?: string; agent_id?: string; redeemer_public_key?: string } {
    const link = this.getCloudConnectLink(linkId);
    if (!link) return { ok: false, reason: 'LINK_NOT_FOUND' };
    if (link.status !== 'redeemed') {
      return { ok: false, reason: `LINK_${link.status.toUpperCase()}` };
    }

    this.markAgentPaired(link.agent_id, undefined, link.redeemer_public_key);

    const now = new Date().toISOString();
    const upd = this.db
      .prepare(
        "UPDATE cloud_connect_links SET status='consumed', consumed_at=? WHERE link_id=? AND status='redeemed'"
      )
      .run(now, linkId);
    if (upd.changes === 0) return { ok: false, reason: 'RACE' };

    this.logAudit('GRANT', 'success', {
      operation: 'cloud_connect_link_approved',
      agentName: link.name,
      details: JSON.stringify({ link_id: linkId, agent_id: link.agent_id }),
    });

    return { ok: true, agent_id: link.agent_id, redeemer_public_key: link.redeemer_public_key };
  }

  /** Deny a pending/redeemed link (revokes any pending agent connection). */
  denyCloudConnectLink(
    linkId: string
  ): { ok: boolean; reason?: string; agent_id?: string } {
    const link = this.getCloudConnectLink(linkId);
    if (!link) return { ok: false, reason: 'LINK_NOT_FOUND' };
    if (link.status !== 'redeemed' && link.status !== 'pending') {
      return { ok: false, reason: `LINK_${link.status.toUpperCase()}` };
    }
    const now = new Date().toISOString();
    this.db
      .prepare("UPDATE cloud_connect_links SET status='revoked', revoked_at=? WHERE link_id=?")
      .run(now, linkId);
    if (link.status === 'redeemed') {
      this.revokeAgentConnection(link.agent_id);
    }
    this.logAudit('REVOKE', 'success', {
      operation: 'cloud_connect_link_denied',
      details: JSON.stringify({ link_id: linkId, agent_id: link.agent_id }),
    });
    return { ok: true, agent_id: link.agent_id };
  }

  /**
   * Instantly revoke a Cloud-Connect link and its bound agent (Rule #7).
   * Clears the agent token and marks both link + agent revoked so subsequent
   * inbound requests are rejected.
   */
  revokeCloudConnectLink(
    linkId: string
  ): { ok: boolean; reason?: string; agent_id?: string } {
    const link = this.getCloudConnectLink(linkId);
    if (!link) return { ok: false, reason: 'LINK_NOT_FOUND' };
    const now = new Date().toISOString();
    this.db
      .prepare("UPDATE cloud_connect_links SET status='revoked', revoked_at=? WHERE link_id=?")
      .run(now, linkId);
    this.revokeAgentConnection(link.agent_id);
    this.logAudit('REVOKE', 'success', {
      operation: 'cloud_connect_link_revoked',
      details: JSON.stringify({ link_id: linkId, agent_id: link.agent_id }),
    });
    return { ok: true, agent_id: link.agent_id };
  }

  /**
   * Verify a presented secret against a stored link (constant-time).
   * Used to authenticate the agent's status poll without exposing the hash.
   */
  verifyCloudConnectSecret(linkId: string, secret: string): boolean {
    const row = this.db
      .prepare('SELECT secret_hash FROM cloud_connect_links WHERE link_id = ?')
      .get(linkId) as { secret_hash: string } | undefined;
    if (!row) return false;
    const presented = createHash('sha256').update(secret).digest('hex');
    return this.hexDigestsEqual(row.secret_hash, presented);
  }

  /** Mark expired (unredeemed) links. Returns the number updated. */
  expireStaleCloudConnectLinks(): number {
    const now = new Date().toISOString();
    const r = this.db
      .prepare(
        "UPDATE cloud_connect_links SET status='expired' WHERE status='pending' AND expires_at < ?"
      )
      .run(now);
    return r.changes;
  }

  /**
   * Check if a service is trusted and has permission for a scope
   */
  isServiceAuthorized(serviceId: string, scope: string): { authorized: boolean; service?: TrustedService; reason?: string } {
    const service = this.getTrustedService(serviceId);

    if (!service) {
      return { authorized: false, reason: 'Service not trusted' };
    }

    if (!service.enabled) {
      return { authorized: false, service, reason: 'Service is disabled' };
    }

    // Check if scope is allowed
    const isAllowed = service.scopes.some((allowedScope) => {
      // Exact match
      if (allowedScope === scope) return true;

      // Wildcard match with :* (e.g., 'sign:*' matches 'sign:solana')
      if (allowedScope.endsWith(':*')) {
        const prefix = allowedScope.slice(0, -1); // Remove '*'
        return scope.startsWith(prefix);
      }

      // Wildcard match with .* (e.g., 'read:credentials.api.*' matches 'read:credentials.api.openai')
      if (allowedScope.endsWith('.*')) {
        const prefix = allowedScope.slice(0, -1); // Remove '*', keep '.'
        return scope.startsWith(prefix);
      }

      // Prefix match for credentials (e.g., 'read:credentials.api.1ly' allows 'read:credentials.api.1ly.key')
      if (scope.startsWith(allowedScope + '.')) {
        return true;
      }

      return false;
    });

    if (!isAllowed) {
      return { authorized: false, service, reason: `Scope '${scope}' not allowed for service` };
    }

    return { authorized: true, service };
  }

  // ==========================================================================
  // Telegram Notification Methods (protocol spec section 15)
  // ==========================================================================

  /**
   * Create Telegram configuration.
   * Bot token is stored encrypted using envelope encryption.
   */
  createTelegramConfig(input: CreateTelegramConfigInput): TelegramConfig {
    if (!this.masterKey) {
      throw new VaultError('VAULT_LOCKED', 'Vault must be unlocked to store Telegram config');
    }

    const now = new Date().toISOString();
    const id = `tg_${generateId()}`;

    // Encrypt bot token using envelope encryption
    const botTokenBuffer = Buffer.from(input.bot_token, 'utf8');
    const encrypted = envelopeEncrypt(botTokenBuffer, this.masterKey);

    const stmt = this.db.prepare(`
      INSERT INTO telegram_configs (
        id, chat_id, bot_token_ciphertext, bot_token_nonce,
        bot_token_dek_wrapped, bot_token_dek_nonce,
        enabled, notify_consent, rate_limit_per_hour,
        notifications_this_hour, created_at, updated_at, paired_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
    `);

    stmt.run(
      id,
      input.chat_id,
      encrypted.ciphertext,
      encrypted.nonce,
      encrypted.dek_wrapped,
      encrypted.dek_nonce,
      input.enabled !== false ? 1 : 0,
      input.notify_consent !== false ? 1 : 0,
      input.rate_limit_per_hour ?? 30,
      now,
      now,
      now
    );

    this.logAudit('CONFIG', 'success', {
      operation: 'telegram_config_create',
      details: JSON.stringify({ chat_id: input.chat_id }),
    });

    return {
      id,
      chat_id: input.chat_id,
      enabled: input.enabled !== false,
      notify_consent: input.notify_consent !== false,
      rate_limit_per_hour: input.rate_limit_per_hour ?? 30,
      notifications_this_hour: 0,
      created_at: now,
      updated_at: now,
      paired_at: now,
    };
  }

  /**
   * Get Telegram configuration (without decrypted bot token).
   * Returns null if not configured.
   */
  getTelegramConfig(): TelegramConfig | null {
    const stmt = this.db.prepare('SELECT * FROM telegram_configs LIMIT 1');
    const row = stmt.get() as {
      id: string;
      chat_id: string;
      enabled: number;
      notify_consent: number;
      rate_limit_per_hour: number;
      last_notification_at: string | null;
      notifications_this_hour: number;
      hour_window_start: string | null;
      created_at: string;
      updated_at: string;
      paired_at: string | null;
      muted_until: string | null;
    } | undefined;

    if (!row) return null;

    return {
      id: row.id,
      chat_id: row.chat_id,
      enabled: row.enabled === 1,
      notify_consent: row.notify_consent === 1,
      rate_limit_per_hour: row.rate_limit_per_hour,
      last_notification_at: row.last_notification_at ?? undefined,
      notifications_this_hour: row.notifications_this_hour,
      hour_window_start: row.hour_window_start ?? undefined,
      created_at: row.created_at,
      updated_at: row.updated_at,
      paired_at: row.paired_at ?? undefined,
      muted_until: row.muted_until ?? undefined,
    };
  }

  /**
   * Get decrypted bot token.
   * Requires vault to be unlocked.
   */
  getTelegramBotToken(): string | null {
    if (!this.masterKey) {
      throw new VaultError('VAULT_LOCKED', 'Vault must be unlocked to retrieve bot token');
    }

    const stmt = this.db.prepare(`
      SELECT bot_token_ciphertext, bot_token_nonce, bot_token_dek_wrapped, bot_token_dek_nonce
      FROM telegram_configs LIMIT 1
    `);
    const row = stmt.get() as {
      bot_token_ciphertext: Buffer;
      bot_token_nonce: Buffer;
      bot_token_dek_wrapped: Buffer;
      bot_token_dek_nonce: Buffer;
    } | undefined;

    if (!row) return null;

    const encrypted: EncryptedPayload = {
      ciphertext: row.bot_token_ciphertext,
      nonce: row.bot_token_nonce,
      dek_wrapped: row.bot_token_dek_wrapped,
      dek_nonce: row.bot_token_dek_nonce,
    };

    const decrypted = envelopeDecrypt(encrypted, this.masterKey);
    return decrypted.toString('utf8');
  }

  /**
   * Update Telegram configuration.
   */
  updateTelegramConfig(updates: Partial<Omit<TelegramConfig, 'id' | 'created_at'>>): boolean {
    const now = new Date().toISOString();
    const config = this.getTelegramConfig();
    if (!config) return false;

    const fields: string[] = ['updated_at = ?'];
    const values: (string | number)[] = [now];

    if (updates.enabled !== undefined) {
      fields.push('enabled = ?');
      values.push(updates.enabled ? 1 : 0);
    }
    if (updates.chat_id !== undefined) {
      fields.push('chat_id = ?');
      values.push(updates.chat_id);
    }
    if (updates.notify_consent !== undefined) {
      fields.push('notify_consent = ?');
      values.push(updates.notify_consent ? 1 : 0);
    }
    if (updates.rate_limit_per_hour !== undefined) {
      fields.push('rate_limit_per_hour = ?');
      values.push(updates.rate_limit_per_hour);
    }
    if (updates.muted_until !== undefined) {
      fields.push('muted_until = ?');
      values.push(updates.muted_until ?? '');
    }
    if (updates.paired_at !== undefined) {
      fields.push('paired_at = ?');
      values.push(updates.paired_at ?? '');
    }

    values.push(config.id);

    const stmt = this.db.prepare(`
      UPDATE telegram_configs SET ${fields.join(', ')} WHERE id = ?
    `);
    const result = stmt.run(...values);

    if (result.changes > 0) {
      this.logAudit('CONFIG', 'success', {
        operation: 'telegram_config_update',
        details: JSON.stringify(updates),
      });
    }

    return result.changes > 0;
  }

  /**
   * Delete Telegram configuration (unlink).
   */
  deleteTelegramConfig(): boolean {
    const config = this.getTelegramConfig();
    if (!config) return false;

    this.db.exec('DELETE FROM telegram_configs');
    this.db.exec('DELETE FROM telegram_pairing_codes');

    this.logAudit('CONFIG', 'success', {
      operation: 'telegram_config_delete',
      details: JSON.stringify({ chat_id: config.chat_id }),
    });

    return true;
  }

  /**
   * Create a 6-digit pairing code for Telegram linking.
   * Code expires in 10 minutes.
   */
  createTelegramPairingCode(vaultId: string): TelegramPairingCode {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes

    // Generate 6-digit code (cryptographically secure)
    const code = randomInt(100000, 1000000).toString();

    // Delete any existing unused codes for this vault
    this.db.prepare('DELETE FROM telegram_pairing_codes WHERE vault_id = ? AND used = 0').run(vaultId);

    const stmt = this.db.prepare(`
      INSERT INTO telegram_pairing_codes (code, vault_id, expires_at, used, created_at)
      VALUES (?, ?, ?, 0, ?)
    `);
    stmt.run(code, vaultId, expiresAt.toISOString(), now.toISOString());

    return {
      code,
      vault_id: vaultId,
      expires_at: expiresAt.toISOString(),
      used: false,
      created_at: now.toISOString(),
    };
  }

  /**
   * Validate a pairing code and return the vault ID if valid.
   */
  validateTelegramPairingCode(code: string): { valid: boolean; vault_id?: string } {
    const stmt = this.db.prepare(`
      SELECT * FROM telegram_pairing_codes WHERE code = ? AND used = 0
    `);
    const row = stmt.get(code) as {
      code: string;
      vault_id: string;
      expires_at: string;
      used: number;
    } | undefined;

    if (!row) {
      return { valid: false };
    }

    const now = new Date();
    const expires = new Date(row.expires_at);
    if (expires < now) {
      return { valid: false };
    }

    return { valid: true, vault_id: row.vault_id };
  }

  /**
   * Mark a pairing code as used.
   */
  markTelegramPairingCodeUsed(code: string): boolean {
    const stmt = this.db.prepare('UPDATE telegram_pairing_codes SET used = 1 WHERE code = ?');
    const result = stmt.run(code);
    return result.changes > 0;
  }

  /**
   * Check if Telegram notifications are rate limited.
   * Returns true if rate limited (should NOT send), false if OK to send.
   */
  checkTelegramRateLimit(): boolean {
    const config = this.getTelegramConfig();
    if (!config) return true; // No config = rate limited

    // Check if muted
    if (config.muted_until) {
      const mutedUntil = new Date(config.muted_until);
      if (mutedUntil > new Date()) {
        return true; // Muted = rate limited
      }
    }

    const now = new Date();
    const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    // Check if we need to reset the hour window
    if (!config.hour_window_start || new Date(config.hour_window_start) < hourAgo) {
      // Reset the window
      this.db.prepare(`
        UPDATE telegram_configs
        SET hour_window_start = ?, notifications_this_hour = 0
        WHERE id = ?
      `).run(now.toISOString(), config.id);
      return false; // Fresh window, not rate limited
    }

    // Check if we've hit the limit
    return config.notifications_this_hour >= config.rate_limit_per_hour;
  }

  /**
   * Increment notification counter and record last notification time.
   */
  recordTelegramNotification(): void {
    const config = this.getTelegramConfig();
    if (!config) return;

    const now = new Date().toISOString();

    this.db.prepare(`
      UPDATE telegram_configs
      SET notifications_this_hour = notifications_this_hour + 1,
          last_notification_at = ?
      WHERE id = ?
    `).run(now, config.id);
  }

  /**
   * Log a Telegram notification for audit trail.
   */
  logTelegramNotification(log: Omit<TelegramNotificationLog, 'id' | 'sent_at'>): TelegramNotificationLog {
    const id = `tglog_${generateId()}`;
    const sentAt = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO telegram_notification_log (
        id, chat_id, consent_id, notification_type, category, agent_name, sent_at, delivered_at, error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      log.chat_id,
      log.consent_id ?? null,
      log.notification_type,
      log.category ?? null,
      log.agent_name ?? null,
      sentAt,
      log.delivered_at ?? null,
      log.error ?? null
    );

    return {
      id,
      ...log,
      sent_at: sentAt,
    };
  }

  /**
   * Get recent Telegram notification logs.
   */
  getTelegramNotificationLogs(limit: number = 50): TelegramNotificationLog[] {
    const stmt = this.db.prepare(`
      SELECT * FROM telegram_notification_log ORDER BY sent_at DESC LIMIT ?
    `);
    const rows = stmt.all(limit) as Array<{
      id: string;
      chat_id: string;
      consent_id: string | null;
      notification_type: string;
      category: string | null;
      agent_name: string | null;
      sent_at: string;
      delivered_at: string | null;
      error: string | null;
    }>;

    return rows.map((row) => ({
      id: row.id,
      chat_id: row.chat_id,
      consent_id: row.consent_id ?? undefined,
      notification_type: row.notification_type as TelegramNotificationLog['notification_type'],
      category: row.category as TelegramRequestCategory | undefined,
      agent_name: row.agent_name ?? undefined,
      sent_at: row.sent_at,
      delivered_at: row.delivered_at ?? undefined,
      error: row.error ?? undefined,
    }));
  }

  // ==========================================================================
  // Utility Methods
  // ==========================================================================

  /**
   * Check if vault is initialized
   */
  isInitialized(): boolean {
    const dbPath = path.join(this.vaultDir, 'vault.db');
    if (!fs.existsSync(dbPath)) return false;

    // Check if tables exist
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM sqlite_master
      WHERE type='table' AND name='vault_records'
    `);
    const row = stmt.get() as { count: number };
    return row.count > 0;
  }

  /**
   * Get vault directory path
   */
  getVaultDir(): string {
    return this.vaultDir;
  }

  /**
   * Close database connection
   */
  close(): void {
    this.lock();
    this.db.close();
  }
}

// ============================================================================
// Default Instance
// ============================================================================

let defaultStorage: VaultStorage | null = null;

/**
 * Get the default vault storage instance
 */
export function getStorage(vaultDir?: string): VaultStorage {
  if (!defaultStorage || (vaultDir && vaultDir !== defaultStorage.getVaultDir())) {
    defaultStorage = new VaultStorage(vaultDir);
  }
  return defaultStorage;
}

/**
 * Reset the default storage instance (for testing)
 */
export function resetStorage(): void {
  if (defaultStorage) {
    defaultStorage.close();
    defaultStorage = null;
  }
}
