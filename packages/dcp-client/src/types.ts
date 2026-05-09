/**
 * DCP Client SDK Types
 *
 * Type definitions for the universal agent SDK.
 * See protocol spec section A3 for API specification.
 */

// ============================================================================
// Chain Types
// ============================================================================

export type Chain = 'solana' | 'base' | 'ethereum';
export type Network = 'solana' | 'base';

// ============================================================================
// Client Configuration (protocol spec A3)
// ============================================================================

export type DcpMode = 'auto' | 'local' | 'relay';

export interface DcpClientConfig {
  /** Transport mode: 'auto' | 'local' | 'relay' (default: 'auto') */
  mode?: DcpMode;

  /** Vault ID for relay mode (required for relay, can be from env DCP_VAULT_ID) */
  vaultId?: string;

  /** Relay server URL (default: from env DCP_RELAY_URL or wss://relay.dcp.1ly.store) */
  relayUrl?: string;

  /** Vault HPKE public key for relay encryption (from env DCP_VAULT_HPKE_PUBLIC_KEY) */
  vaultHpkePublicKey?: string;

  /** Service ID for relay authentication (from env DCP_SERVICE_ID) */
  serviceId?: string;

  /** Service Ed25519 private key for signing relay requests (from env DCP_SERVICE_PRIVATE_KEY) */
  servicePrivateKey?: string;

  /** Agent identifier (optional, for logging) */
  agentId?: string;

  /** Human-readable agent name (from env MCP_AGENT_NAME) */
  agentName?: string;

  /** Request timeout in milliseconds (default: 30000) */
  timeoutMs?: number;

  /** Local DCP server URL (default: http://127.0.0.1:8420) */
  localUrl?: string;

  /** Timeout for local health check in auto mode (default: 100ms) */
  localCheckTimeoutMs?: number;
}

// ============================================================================
// Resolved Configuration (internal)
// ============================================================================

export interface ResolvedConfig {
  mode: DcpMode;
  vaultId: string | undefined;
  relayUrl: string;
  vaultHpkePublicKey: string | undefined;
  serviceId: string | undefined;
  servicePrivateKey: string | undefined;
  agentId: string;
  agentName: string;
  timeoutMs: number;
  localUrl: string;
  localCheckTimeoutMs: number;
}

// ============================================================================
// Method Input Types (protocol spec A3)
// ============================================================================

export interface SignTxInput {
  /** Blockchain to sign for */
  chain: Chain;
  /** Unsigned transaction (base64 for Solana, JSON string for EVM) */
  unsignedTx: string;
  /** Human-readable description for consent UI */
  description?: string;
  /** Transaction amount in currency units */
  amount?: number;
  /** Currency code (e.g., 'SOL', 'USDC', 'ETH') */
  currency?: string;
  /** Destination address */
  destination?: string;
  /** Idempotency key to prevent duplicate transactions */
  idempotencyKey?: string;
}

export interface SignMessageInput {
  /** Blockchain to sign for */
  chain: Chain;
  /** Message to sign */
  message: string;
  /** Message encoding: 'utf8' | 'base64' (default: 'utf8') */
  encoding?: 'utf8' | 'base64';
  /** Human-readable description for consent UI */
  description?: string;
}

export interface SignTypedDataInput {
  /** Blockchain (must be 'base' or 'ethereum') */
  chain: Chain;
  /** EIP-712 typed data object */
  typedData: Record<string, unknown>;
  /** Human-readable description for consent UI */
  description?: string;
}

export interface SignX402Input {
  /** Network: 'solana' | 'base' */
  network: Network;
  /** x402 payload (base64) */
  payload: string;
  /** Payment amount */
  amount?: number | string;
  /** Currency code */
  currency?: string;
  /** Recipient address */
  recipient?: string;
  /** Purpose/description for consent UI */
  purpose?: string;
  /** EIP-712 typed data for EVM (optional) */
  typedData?: Record<string, unknown>;
}

export interface ReadCredentialInput {
  /** Credential scope (e.g., 'credentials.api.openai') */
  scope: string;
  /** Specific fields to return (optional, returns all if not specified) */
  fields?: string[];
}

export interface WriteCredentialInput {
  /** Credential scope */
  scope: string;
  /** Data to write */
  data: Record<string, unknown>;
}

export interface BudgetCheckInput {
  /** Amount to check */
  amount: number;
  /** Currency code */
  currency: string;
  /** Optional chain for chain-specific limits */
  chain?: Chain;
}

export interface PairServiceInput {
  /** Pairing token issued by the vault */
  pairingToken: string;
  /** Service public key (ed25519:base64) */
  servicePublicKey: string;
  /** Optional service display name */
  serviceName?: string;
}

// ============================================================================
// Method Output Types (protocol spec A3)
// ============================================================================

export interface GetAddressResult {
  /** Blockchain */
  chain: Chain;
  /** Public address */
  address: string;
}

export interface SignTxResult {
  /** Signed transaction (base64) */
  signedTx: string;
  /** Transaction signature */
  signature: string;
  /** Blockchain */
  chain: Chain;
  /** Remaining daily budget */
  remainingDaily?: number;
  /** Session ID (if session was created) */
  sessionId?: string;
}

export interface SignMessageResult {
  /** Signature */
  signature: string;
  /** Public key that signed */
  publicKey: string;
  /** Blockchain */
  chain: Chain;
  /** Session ID */
  sessionId?: string;
}

export interface SignTypedDataResult {
  /** Signature */
  signature: string;
  /** Public key that signed */
  publicKey: string;
  /** Blockchain */
  chain: Chain;
  /** Session ID */
  sessionId?: string;
}

export interface SignX402Result {
  /** Signature */
  signature: string;
  /** Public key that signed */
  publicKey: string;
  /** Blockchain */
  chain: Chain;
  /** Session ID */
  sessionId?: string;
}

export interface ReadCredentialResult {
  /** Scope that was read */
  scope: string;
  /** Decrypted data (null for critical data) */
  data: Record<string, unknown> | null;
  /** Sensitivity level */
  sensitivity?: 'standard' | 'sensitive' | 'critical';
  /** Whether this is a reference-only response */
  isReference?: boolean;
  /** Session ID */
  sessionId?: string;
}

export interface WriteCredentialResult {
  /** Scope that was written */
  scope: string;
  /** Whether a new record was created */
  created: boolean;
  /** Whether an existing record was updated */
  updated: boolean;
  /** Sensitivity level */
  sensitivity?: 'standard' | 'sensitive' | 'critical';
  /** Session ID */
  sessionId?: string;
}

export interface BudgetCheckResult {
  /** Whether the transaction is allowed */
  allowed: boolean;
  /** Whether manual approval is required */
  requiresApproval: boolean;
  /** Remaining daily budget */
  remainingDaily: number;
  /** Remaining per-transaction limit */
  remainingTx: number;
  /** Budget limits */
  limits?: {
    perTx: number;
    daily: number;
    approvalThreshold: number;
  };
  /** Reason if not allowed */
  reason?: string;
}

export interface HealthCheckResult {
  /** Whether DCP is available */
  available: boolean;
  /** Whether vault is unlocked */
  unlocked: boolean;
  /** DCP version */
  version?: string;
  /** Current transport mode */
  mode: DcpMode | 'unknown';
}

export interface PairServiceResult {
  ok: boolean;
  serviceId?: string;
}

// ============================================================================
// Transport Interface (internal)
// ============================================================================

export interface Transport {
  /** Check if vault is available */
  isAvailable(): Promise<HealthCheckResult>;

  /** Get wallet address */
  getAddress(chain: Chain): Promise<GetAddressResult>;

  /** Sign a transaction */
  signTx(input: SignTxInput): Promise<SignTxResult>;

  /** Sign a message */
  signMessage(input: SignMessageInput): Promise<SignMessageResult>;

  /** Sign typed data (EIP-712) */
  signTypedData(input: SignTypedDataInput): Promise<SignTypedDataResult>;

  /** Sign x402 payment */
  signX402(input: SignX402Input): Promise<SignX402Result>;

  /** Read credential/data */
  readCredential(scope: string, fields?: string[]): Promise<ReadCredentialResult>;

  /** Write credential/data */
  writeCredential(scope: string, data: Record<string, unknown>): Promise<WriteCredentialResult>;

  /** Check budget */
  budgetCheck(input: BudgetCheckInput): Promise<BudgetCheckResult>;

  /** Cleanup resources */
  close(): Promise<void>;

  /** Get current session ID for a scope */
  getSessionId(scope: string): string | undefined;

  /** Clear session cache */
  clearSession(): void;
}

// ============================================================================
// Session Types (protocol spec A5)
// ============================================================================

export interface SessionInfo {
  sessionId: string;
  scope: string;
  expiresAt: Date;
  lastUsedAt: Date;
}

// ============================================================================
// Relay Envelope Types (protocol spec A4.2)
// ============================================================================

export interface RelayEnvelope {
  version: string;
  vault_id: string;
  request_id: string;
  action_type: string;
  encrypted_payload: string;
  expires_at: string;
}

export interface RelayResponseEnvelope {
  version: string;
  request_id: string;
  encrypted_payload: string;
  timestamp: string;
}

export interface DecryptedRelayPayload {
  method: string;
  params: Record<string, unknown>;
  agent_name: string;
  service_id?: string;
  timestamp: string;
  nonce: string;
  service_signature?: string;
  reply_public_key: string;
}

// ============================================================================
// HPKE Types
// ============================================================================

export interface HpkeKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

export interface EncryptedMessage {
  ephemeralPublicKey: Buffer;
  nonce: Buffer;
  ciphertext: Buffer;
}

export interface EnvelopeAad {
  version: string;
  vault_id: string;
  request_id: string;
  action_type: string;
}

// ============================================================================
// Constants
// ============================================================================

export const DEFAULT_LOCAL_URL = 'http://127.0.0.1:8420';
export const DEFAULT_RELAY_URL = 'wss://relay.dcp.1ly.store';
export const DEFAULT_TIMEOUT_MS = 30000;
export const DEFAULT_LOCAL_CHECK_TIMEOUT_MS = 100;
export const RELAY_VERSION = '1';

// Chain to default currency mapping
export const CHAIN_CURRENCY_MAP: Record<Chain, string> = {
  solana: 'SOL',
  ethereum: 'ETH',
  base: 'BASE_ETH',
};
