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
import * as keytar from 'keytar';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { randomBytes, randomUUID } from 'crypto';
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
} from './types.js';
import { generateKey, deriveKeyFromPassphrase, generateSalt, zeroize, encrypt, decrypt, envelopeEncrypt, envelopeDecrypt } from './crypto.js';

// ============================================================================
// Constants
// ============================================================================

/** Default vault directory */
const DEFAULT_VAULT_DIR = path.join(os.homedir(), '.dcp');

/** Keychain service name */
const KEYCHAIN_SERVICE = 'dcp';

/** Keychain account for master key */
const KEYCHAIN_ACCOUNT = 'master-key';

/** Keychain account for salt */
const KEYCHAIN_SALT_ACCOUNT = 'master-salt';

/** File permissions for vault.key (owner read/write only) */
const KEY_FILE_MODE = 0o600;

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
      return masterKey;
    } catch (error) {
      // If keychain entry is stale but file exists, try file before failing.
      if (keySource === 'keychain') {
        const fileData = this.loadMasterKeyFromFile();
        if (fileData) {
          try {
            const masterKey = tryDecrypt(fileData);
            this.masterKey = masterKey;
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
      // Store as JSON with all components
      const data = JSON.stringify({
        encrypted_key: encryptedKey.toString('base64'),
        nonce: nonce.toString('base64'),
        salt: salt.toString('base64'),
        version: '2.0', // Version 2.0 = AEAD encryption
      });

      await keytar.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, data);
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
      const dataStr = await keytar.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);

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
   * Create a pending consent request
   */
  createPendingConsent(
    agentName: string,
    action: string,
    scope: string,
    details?: string
  ): PendingConsent {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes
    const id = generateId();

    const stmt = this.db.prepare(`
      INSERT INTO pending_consents (
        id, agent_name, action, scope, details, status, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
    `);

    stmt.run(id, agentName, action, scope, details || null, now.toISOString(), expiresAt.toISOString());

    return {
      id,
      agent_name: agentName,
      action,
      scope,
      details,
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
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
