/**
 * DCP Client SDK
 *
 * Universal agent SDK for DCP - connect any agent to DCP Vault.
 * Supports local REST and relay transports with auto-detection.
 *
 * See protocol spec section A for full specification.
 *
 * Usage:
 * ```typescript
 * const dcp = new DcpClient({ mode: 'auto' });
 * const address = await dcp.getAddress('solana');
 * const result = await dcp.signTx({ chain: 'solana', unsignedTx: '...' });
 * await dcp.close();
 * ```
 */

import type {
  DcpClientConfig,
  DcpMode,
  ResolvedConfig,
  Transport,
  Chain,
  Network,
  GetAddressResult,
  SignTxInput,
  SignTxResult,
  SignMessageInput,
  SignMessageResult,
  SignX402Input,
  SignX402Result,
  ReadCredentialResult,
  WriteCredentialResult,
  BudgetCheckInput,
  BudgetCheckResult,
  HealthCheckResult,
  PairServiceInput,
  PairServiceResult,
} from './types.js';
import {
  DEFAULT_LOCAL_URL,
  DEFAULT_RELAY_URL,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_LOCAL_CHECK_TIMEOUT_MS,
} from './types.js';
import { DcpError, vaultOffline, vaultLocked, invalidConfig } from './errors.js';
import { LocalTransport } from './local-transport.js';
import { RelayTransport } from './relay-transport.js';

// ============================================================================
// Environment Variable Names (protocol spec A3.1)
// ============================================================================

const ENV_VARS = {
  MODE: 'DCP_MODE',
  VAULT_ID: 'DCP_VAULT_ID',
  RELAY_URL: 'DCP_RELAY_URL',
  VAULT_HPKE_PUBLIC_KEY: 'DCP_VAULT_HPKE_PUBLIC_KEY',
  SERVICE_ID: 'DCP_SERVICE_ID',
  SERVICE_PRIVATE_KEY: 'DCP_SERVICE_PRIVATE_KEY',
  LOCAL_URL: 'DCP_URL',
  AGENT_NAME: 'MCP_AGENT_NAME',
} as const;

// ============================================================================
// DcpClient Implementation
// ============================================================================

export class DcpClient {
  private config: ResolvedConfig;
  private transport: Transport | null = null;
  private resolvedMode: DcpMode | null = null;
  private closed = false;

  constructor(config: DcpClientConfig = {}) {
    this.config = this.resolveConfig(config);
  }

  // --------------------------------------------------------------------------
  // Configuration Resolution (protocol spec A3.1)
  // --------------------------------------------------------------------------

  private resolveConfig(config: DcpClientConfig): ResolvedConfig {
    // Read from env vars with config override
    const mode = (config.mode || this.getEnv(ENV_VARS.MODE) || 'auto') as DcpMode;
    const vaultId = config.vaultId || this.getEnv(ENV_VARS.VAULT_ID);
    const relayUrl = config.relayUrl || this.getEnv(ENV_VARS.RELAY_URL) || DEFAULT_RELAY_URL;
    const vaultHpkePublicKey = config.vaultHpkePublicKey || this.getEnv(ENV_VARS.VAULT_HPKE_PUBLIC_KEY);
    const serviceId = config.serviceId || this.getEnv(ENV_VARS.SERVICE_ID);
    const servicePrivateKey = config.servicePrivateKey || this.getEnv(ENV_VARS.SERVICE_PRIVATE_KEY);
    const agentName = config.agentName || this.getEnv(ENV_VARS.AGENT_NAME) || 'dcp-client';
    const agentId = config.agentId || `agent_${Date.now()}`;
    const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const localUrl = config.localUrl || this.getEnv(ENV_VARS.LOCAL_URL) || DEFAULT_LOCAL_URL;
    const localCheckTimeoutMs = config.localCheckTimeoutMs ?? DEFAULT_LOCAL_CHECK_TIMEOUT_MS;

    return {
      mode,
      vaultId,
      relayUrl,
      vaultHpkePublicKey,
      serviceId,
      servicePrivateKey,
      agentName,
      agentId,
      timeoutMs,
      localUrl,
      localCheckTimeoutMs,
    };
  }

  private getEnv(name: string): string | undefined {
    // Handle both Node.js and browser environments
    if (typeof process !== 'undefined' && process.env) {
      return process.env[name];
    }
    return undefined;
  }

  // --------------------------------------------------------------------------
  // Transport Resolution (protocol spec A4.3 Auto Mode Logic)
  // --------------------------------------------------------------------------

  private async getTransport(): Promise<Transport> {
    if (this.closed) {
      throw invalidConfig('Client has been closed');
    }

    if (this.transport) {
      return this.transport;
    }

    const mode = this.config.mode;

    if (mode === 'local') {
      this.transport = new LocalTransport(this.config);
      this.resolvedMode = 'local';
      return this.transport;
    }

    if (mode === 'relay') {
      this.validateRelayConfig();
      this.transport = new RelayTransport(this.config);
      this.resolvedMode = 'relay';
      return this.transport;
    }

    // Auto mode (protocol spec A4.3)
    return this.autoDetectTransport();
  }

  /**
   * Auto-detect transport based on local DCP availability (protocol spec A4.3)
   *
   * 1. Check http://127.0.0.1:8420/health (100ms timeout)
   * 2. If response.unlocked === true → use local transport
   * 3. If response.unlocked === false → throw VAULT_LOCKED
   * 4. If connection refused / timeout:
   *    a. If DCP_VAULT_ID is set → use relay transport
   *    b. Otherwise → throw VAULT_OFFLINE
   */
  private async autoDetectTransport(): Promise<Transport> {
    // Try local first
    const localTransport = new LocalTransport(this.config);
    const health = await localTransport.isAvailable();

    if (health.available) {
      // Local is available
      if (health.unlocked) {
        // Local is available and unlocked - use it
        this.transport = localTransport;
        this.resolvedMode = 'local';
        return this.transport;
      } else {
        // Local is available but locked - don't silently fall back to relay
        throw vaultLocked('DCP vault is locked. Please unlock first.');
      }
    }

    // Local is not available
    await localTransport.close();

    // Check if we can use relay
    if (this.config.vaultId) {
      try {
        this.validateRelayConfig();
        this.transport = new RelayTransport(this.config);
        this.resolvedMode = 'relay';
        return this.transport;
      } catch (err) {
        // Relay config is invalid, throw vault offline
        throw vaultOffline(
          'DCP vault is not running locally and relay is not configured properly'
        );
      }
    }

    // No relay config, throw vault offline
    throw vaultOffline(
      'DCP vault is not running. Start DCP Desktop or configure relay mode with DCP_VAULT_ID.'
    );
  }

  private validateRelayConfig(): void {
    if (!this.config.vaultId) {
      throw invalidConfig('vaultId (or DCP_VAULT_ID env) is required for relay mode');
    }
    if (!this.config.vaultHpkePublicKey) {
      throw invalidConfig(
        'vaultHpkePublicKey (or DCP_VAULT_HPKE_PUBLIC_KEY env) is required for relay mode'
      );
    }
    if (!this.config.serviceId) {
      throw invalidConfig('serviceId (or DCP_SERVICE_ID env) is required for relay mode');
    }
    if (!this.config.servicePrivateKey) {
      throw invalidConfig(
        'servicePrivateKey (or DCP_SERVICE_PRIVATE_KEY env) is required for relay mode'
      );
    }
  }

  // --------------------------------------------------------------------------
  // Public API (protocol spec A3)
  // --------------------------------------------------------------------------

  /**
   * Get wallet address for a chain
   *
   * @param chain - 'solana'
   * @returns Address result with chain and public address
   */
  async getAddress(chain: Chain): Promise<GetAddressResult> {
    const transport = await this.getTransport();
    return transport.getAddress(chain);
  }

  /**
   * Sign a transaction
   *
   * @param input - Transaction details including chain, unsigned tx, and optional budget info
   * @returns Signed transaction with signature and budget remaining
   * @throws DcpError with CONSENT_REQUIRED if user approval needed
   */
  async signTx(input: SignTxInput): Promise<SignTxResult> {
    const transport = await this.getTransport();
    return transport.signTx(input);
  }

  /**
   * Sign a message
   *
   * @param input - Message details including chain, message, and encoding
   * @returns Signature and public key
   * @throws DcpError with CONSENT_REQUIRED if user approval needed
   */
  async signMessage(input: SignMessageInput): Promise<SignMessageResult> {
    const transport = await this.getTransport();
    return transport.signMessage(input);
  }

  /**
   * Sign x402 payment
   *
   * @param input - x402 payload details including network and payment info
   * @returns Signature and public key
   * @throws DcpError with CONSENT_REQUIRED if user approval needed
   */
  async signX402(input: SignX402Input): Promise<SignX402Result> {
    const transport = await this.getTransport();
    return transport.signX402(input);
  }

  /**
   * Read credential/data from vault
   *
   * @param scope - Credential scope (e.g., 'credentials.api.openai')
   * @param fields - Optional specific fields to return
   * @returns Decrypted data (null for critical data)
   * @throws DcpError with CONSENT_REQUIRED if user approval needed
   */
  async readCredential(scope: string, fields?: string[]): Promise<ReadCredentialResult> {
    const transport = await this.getTransport();
    return transport.readCredential(scope, fields);
  }

  /**
   * Alias for readCredential - read data from vault
   */
  async readData(scope: string, fields?: string[]): Promise<ReadCredentialResult> {
    return this.readCredential(scope, fields);
  }

  /**
   * Write credential/data to vault
   *
   * @param scope - Credential scope
   * @param data - Data to write
   * @returns Write result with created/updated status
   * @throws DcpError with CONSENT_REQUIRED if user approval needed
   */
  async writeCredential(scope: string, data: Record<string, unknown>): Promise<WriteCredentialResult> {
    const transport = await this.getTransport();
    return transport.writeCredential(scope, data);
  }

  /**
   * Check if a transaction is within budget
   *
   * @param input - Budget check parameters
   * @returns Budget check result with allowed status and limits
   */
  async budgetCheck(input: BudgetCheckInput): Promise<BudgetCheckResult> {
    const transport = await this.getTransport();
    return transport.budgetCheck(input);
  }

  /**
   * Pair a service/proxy with the vault (relay mode only)
   */
  async pairService(input: PairServiceInput): Promise<PairServiceResult> {
    const transport = await this.getTransport();
    if (!(transport instanceof RelayTransport)) {
      throw invalidConfig('pairService requires relay mode');
    }
    return transport.pairService(input);
  }

  /**
   * Check if DCP vault is available
   *
   * @returns Health check result with availability and unlock status
   */
  async isAvailable(): Promise<HealthCheckResult> {
    try {
      const transport = await this.getTransport();
      return transport.isAvailable();
    } catch (err) {
      if (err instanceof DcpError) {
        return {
          available: false,
          unlocked: false,
          mode: this.resolvedMode || 'unknown',
        };
      }
      throw err;
    }
  }

  /**
   * Clear all cached sessions
   * Useful for testing or forcing re-consent
   */
  clearSession(): void {
    if (this.transport) {
      this.transport.clearSession();
    }
  }

  /**
   * Get the current transport mode
   */
  getMode(): DcpMode | 'unknown' {
    return this.resolvedMode || 'unknown';
  }

  /**
   * Close the client and cleanup resources
   * IMPORTANT: Call this when done to zeroize any cached key material
   */
  async close(): Promise<void> {
    this.closed = true;
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
  }
}

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Create a new DCP client
 *
 * @param config - Optional configuration (reads from env vars if not provided)
 * @returns DcpClient instance
 *
 * @example
 * // Using env vars
 * const dcp = createDcpClient();
 *
 * @example
 * // With explicit config
 * const dcp = createDcpClient({
 *   mode: 'local',
 *   agentName: 'my-agent',
 * });
 */
export function createDcpClient(config: DcpClientConfig = {}): DcpClient {
  return new DcpClient(config);
}
