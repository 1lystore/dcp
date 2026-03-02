/**
 * Core types for DCP Vault
 * These types define the data structures used throughout the vault
 */

// ============================================================================
// Sensitivity Levels (from PRD Section 6)
// ============================================================================

export type SensitivityLevel = 'standard' | 'sensitive' | 'critical';

// ============================================================================
// Item Types (from PRD Schema Section 4.3)
// ============================================================================

export type ItemType = 'WALLET_KEY' | 'ADDRESS' | 'IDENTITY' | 'PREFERENCES';

// ============================================================================
// Chain Types
// ============================================================================

export type Chain = 'solana' | 'base' | 'ethereum';
export type KeyType = 'ed25519' | 'secp256k1';

// ============================================================================
// Vault Record (stored in SQLite)
// ============================================================================

export interface VaultRecord {
  id: string;
  scope: string;
  item_type: ItemType;
  sensitivity: SensitivityLevel;
  ciphertext: Buffer;
  nonce: Buffer;
  dek_wrapped: Buffer;
  dek_nonce: Buffer;
  chain?: Chain;
  public_address?: string;
  schema_version: string;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// Wallet Types
// ============================================================================

export interface WalletKeyData {
  chain: Chain;
  public_address: string;
  key_type: KeyType;
  private_key: Buffer; // Only in memory, NEVER returned to agents
}

export interface WalletInfo {
  chain: Chain;
  public_address: string;
  key_type: KeyType;
  operations: ('sign_tx' | 'sign_message' | 'get_address')[];
}

export interface SignResult {
  signed_tx: string; // base64
  signature: string;
  chain: Chain;
}

// ============================================================================
// Personal Data Types (from PRD Appendix B)
// ============================================================================

export interface AddressData {
  street: string;
  city: string;
  state?: string;
  zip?: string;
  country: string; // ISO 3166-1 alpha-2
}

export interface IdentityNameData {
  first?: string;
  last?: string;
  full: string;
}

export interface IdentityPhoneData {
  country_code: string;
  number: string;
}

export interface IdentityPassportData {
  number: string;
  expiry: string;
  country: string;
  issuing_authority?: string;
}

export interface PreferencesSizesData {
  shoe?: string;
  shirt?: string;
  pants?: string;
  width?: 'narrow' | 'standard' | 'wide';
  unit?: 'US' | 'UK' | 'EU';
}

export interface PreferencesBrandsData {
  preferred?: string[];
  avoided?: string[];
}

export interface PreferencesDietData {
  restrictions?: string[];
  allergies?: string[];
  preferences?: string[];
}

// ============================================================================
// Encryption Types
// ============================================================================

export interface EncryptedPayload {
  ciphertext: Buffer;
  nonce: Buffer;
  dek_wrapped: Buffer;
  dek_nonce: Buffer;
}

export interface MasterKeyInfo {
  key: Buffer;
  source: 'keychain' | 'file';
}

// ============================================================================
// Agent Session Types (from PRD Schema Section 4.3)
// ============================================================================

export type ConsentMode = 'once' | 'session' | 'always' | 'profile';
export type TrustTier = 'unknown' | 'verified' | 'trusted';

export interface AgentSession {
  id: string;
  agent_name: string;
  agent_fingerprint?: string;
  marketplace?: string;
  trust_tier: TrustTier;
  granted_scopes: string[];
  purpose?: string;
  consent_mode: ConsentMode;
  profile_name?: string;
  token_id?: string;
  expires_at: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
}

// ============================================================================
// Spend Event Types (from PRD Schema Section 4.3)
// ============================================================================

export type SpendStatus = 'committed' | 'pending' | 'failed';

export interface SpendEvent {
  id: string;
  agent_session_id: string;
  amount: number;
  currency: string;
  chain: Chain;
  operation: string;
  destination?: string;
  idempotency_key?: string;
  status: SpendStatus;
  tx_signature?: string;
  created_at: string;
}

// ============================================================================
// Audit Event Types (from PRD Schema Section 4.3)
// ============================================================================

export type AuditEventType = 'GRANT' | 'READ' | 'EXECUTE' | 'DENY' | 'REVOKE' | 'EXPIRE' | 'CONFIG';

export interface AuditEvent {
  id: string;
  event_type: AuditEventType;
  agent_name?: string;
  scope?: string;
  operation?: string;
  details?: string;
  outcome: string;
  created_at: string;
}

// ============================================================================
// Pending Consent Types
// ============================================================================

export type ConsentStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface PendingConsent {
  id: string;
  agent_name: string;
  action: string;
  scope: string;
  details?: string;
  status: ConsentStatus;
  created_at: string;
  expires_at: string;
  resolved_at?: string;
  session_id?: string;
}

// ============================================================================
// Budget Config Types (from PRD Section 17)
// ============================================================================

export interface BudgetConfig {
  daily_budget: Record<string, number>;
  tx_limit: Record<string, number>;
  approval_threshold: Record<string, number>;
}

export interface BudgetCheckResult {
  allowed: boolean;
  requires_approval: boolean;
  remaining_daily: number;
  remaining_tx: number;
  reason?: string;
}

// ============================================================================
// Token Types (PASETO v4, from PRD Section 3.1.8)
// ============================================================================

export interface TokenPayload {
  token_id: string;
  sub: string; // agent identifier
  vault_id: string;
  ops: string[];
  chains: Chain[];
  purpose?: string;
  constraints: {
    exp: string; // ISO timestamp
    max_uses?: number;
    spending_limit_per_tx?: Record<string, number>;
    spending_limit_daily?: Record<string, number>;
    require_confirm_above?: Record<string, number>;
  };
}

// ============================================================================
// Error Types (from PRD Section 7)
// ============================================================================

export type VaultErrorCode =
  | 'VAULT_NOT_INITIALIZED'
  | 'VAULT_LOCKED'
  | 'CONSENT_REQUIRED'
  | 'CONSENT_DENIED'
  | 'CONSENT_EXPIRED'
  | 'CONSENT_TIMEOUT'
  | 'CONSENT_NOT_FOUND'
  | 'SCOPE_VIOLATION'
  | 'BUDGET_EXCEEDED_TX'
  | 'BUDGET_EXCEEDED_DAILY'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_REVOKED'
  | 'INVALID_CHAIN'
  | 'INVALID_TX'
  | 'IDEMPOTENCY_CONFLICT'
  | 'RATE_LIMITED'
  | 'RECORD_NOT_FOUND'
  | 'INTERNAL_ERROR';

export class VaultError extends Error {
  constructor(
    public code: VaultErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'VaultError';
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
      },
    };
  }
}
