/**
 * DCP Agent Connection
 *
 * Handles connection to relay using session tokens.
 */

import { DcpClient } from '@dcprotocol/client';
import type { ConsentStatusResult } from '@dcprotocol/client';
import { AgentConfig, AgentState, AgentError } from './types.js';

// ============================================================================
// Agent Connection
// ============================================================================

/**
 * AgentConnection manages communication with the vault via relay
 */
export class AgentConnection {
  private config: AgentConfig;
  private client: DcpClient | null = null;
  private forceRelay: boolean;
  private state: AgentState = {
    connected: false,
    session_valid: false,
    request_count: 0,
  };

  constructor(config: AgentConfig, options?: { forceRelay?: boolean }) {
    this.config = config;
    // Support both constructor option and environment variable
    this.forceRelay = options?.forceRelay ?? process.env.DCP_FORCE_RELAY === '1';
  }

  /**
   * Connect to the vault
   *
   * Per protocol spec section 7.3, agents use their own Ed25519 keypair for relay authentication.
   * The agent's keypair is generated during pairing and stored in agent.json.
   *
   * Tries local mode first (for testing), falls back to relay mode.
   * Use forceRelay option to skip local detection and always use relay.
   */
  async connect(): Promise<void> {
    if (this.client) {
      await this.close();
    }

    // Try local mode first (for local testing) - unless forceRelay is set
    // Vault server runs on 8421
    if (!this.forceRelay) {
      try {
        const healthCheck = await fetch('http://127.0.0.1:8421/health');
        if (healthCheck.ok) {
          const health = await healthCheck.json() as { unlocked?: boolean };
          if (health.unlocked) {
            // Local vault is available and unlocked - use local mode
            // Include agent credentials for Ed25519 signed requests
            // This enables server-side permission verification
            this.client = new DcpClient({
              mode: 'local',
              localUrl: 'http://127.0.0.1:8421',
              agentName: this.config.agent_name,
              // Sign requests with agent's keypair for permission verification
              serviceId: this.config.agent_id,
              servicePrivateKey: this.config.service_keypair.private,
            });
            this.state.connected = true;
            this.state.session_valid = true;
            return;
          }
        }
      } catch {
        // Local vault not available, fall through to relay mode
      }
    }

    // Use relay mode with agent's keypair for authentication
    // Per protocol spec: agents have their own service_keypair generated during pairing
    this.client = new DcpClient({
      mode: 'relay',
      vaultId: this.config.vault_id,
      relayUrl: this.config.relay_url,
      vaultHpkePublicKey: this.config.vault_hpke_public_key,
      agentName: this.config.agent_name,
      // Agent uses its own keypair as service credentials
      serviceId: this.config.agent_id,
      servicePrivateKey: this.config.service_keypair.private,
    });

    this.state.connected = true;
    this.state.session_valid = true;
  }

  // NOTE: Previous implementation commented for reference (will use for big services like 1ly, ElizaOS):
  // The old approach assumed external service credentials would be provided.
  // async connect_old(): Promise<void> {
  //   this.client = new DcpClient({
  //     mode: 'relay',
  //     vaultId: this.config.vault_id,
  //     relayUrl: this.config.relay_url,
  //     vaultHpkePublicKey: this.config.vault_hpke_public_key,
  //     agentName: this.config.agent_name,
  //     // Missing: serviceId, servicePrivateKey - was for big services
  //   });
  // }

  /**
   * Close the connection
   */
  async close(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
    }
    this.state.connected = false;
  }

  /**
   * Get wallet address
   */
  async getAddress(chain: 'solana'): Promise<{ chain: string; address: string }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.getAddress(chain);
    return { chain: result.chain, address: result.address };
  }

  /**
   * Check budget
   */
  async budgetCheck(params: {
    amount: number;
    currency: string;
    chain?: 'solana';
  }): Promise<{
    allowed: boolean;
    remaining_daily: number;
    remaining_tx: number;
    requires_approval: boolean;
    reason?: string;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.budgetCheck(params);
    return {
      allowed: result.allowed,
      remaining_daily: result.remainingDaily,
      remaining_tx: result.remainingTx,
      requires_approval: result.requiresApproval,
      reason: result.reason,
    };
  }

  /**
   * Sign a transaction
   */
  async signTx(params: {
    chain: 'solana';
    unsignedTx: string;
    amount?: number;
    currency?: string;
    description?: string;
    idempotencyKey?: string;
    destination?: string;
  }): Promise<{
    signed_tx: string;
    signature: string;
    chain: string;
    remaining_daily?: number;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.signTx(params);
    return {
      signed_tx: result.signedTx,
      signature: result.signature,
      chain: result.chain,
      remaining_daily: result.remainingDaily,
    };
  }

  /**
   * Build + sign + submit a transfer. DCP (the vault) builds the transaction
   * itself from the intent, signs it, and submits it to the network.
   */
  async transfer(params: {
    chain: 'solana';
    to: string;
    amount: number;
    currency?: string;
    mint?: string;
    decimals?: number;
    confirm?: 'submitted' | 'confirmed';
    description?: string;
    idempotencyKey?: string;
  }): Promise<{
    chain: string;
    from: string;
    to: string;
    amount: number;
    currency: string;
    signature: string;
    status: string;
    explorer_url: string;
    remaining_daily?: number;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.transfer(params);
    return {
      chain: result.chain,
      from: result.from,
      to: result.to,
      amount: result.amount,
      currency: result.currency,
      signature: result.signature,
      status: result.status,
      explorer_url: result.explorerUrl,
      remaining_daily: result.remainingDaily,
    };
  }

  /**
   * Quote + build + sign + submit a swap via Jupiter.
   */
  async swap(params: {
    chain: 'solana';
    fromToken: string;
    toToken: string;
    amount: number;
    slippageBps?: number;
    fromDecimals?: number;
    toDecimals?: number;
    confirm?: 'submitted' | 'confirmed';
    description?: string;
    idempotencyKey?: string;
  }): Promise<{
    chain: string;
    from_token: string;
    to_token: string;
    amount: number;
    out_amount?: string;
    signature: string;
    status: string;
    explorer_url: string;
    remaining_daily?: number;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.swap(params);
    return {
      chain: result.chain,
      from_token: result.fromToken,
      to_token: result.toToken,
      amount: result.amount,
      out_amount: result.outAmount,
      signature: result.signature,
      status: result.status,
      explorer_url: result.explorerUrl,
      remaining_daily: result.remainingDaily,
    };
  }

  /**
   * Sign a message
   */
  async signMessage(params: {
    chain: 'solana';
    message: string;
    encoding?: 'utf8' | 'base64';
    description?: string;
  }): Promise<{
    signature: string;
    public_key: string;
    chain: string;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.signMessage(params);
    return {
      signature: result.signature,
      public_key: result.publicKey,
      chain: result.chain,
    };
  }

  /**
   * Sign an x402 payment payload
   */
  async signX402(params: {
    network: 'solana';
    payload: string;
    amount?: number | string;
    currency?: string;
    recipient?: string;
    purpose?: string;
  }): Promise<{
    signature: string;
    public_key: string;
    chain: string;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.signX402(params);
    return {
      signature: result.signature,
      public_key: result.publicKey,
      chain: result.chain,
    };
  }

  /**
   * Read credential from vault
   */
  async readCredential(
    scope: string,
    fields?: string[]
  ): Promise<{
    scope: string;
    data: Record<string, unknown> | null;
    sensitivity: string;
    is_reference: boolean;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.readCredential(scope, fields);
    return {
      scope: result.scope,
      data: result.data,
      sensitivity: result.sensitivity ?? 'standard',
      is_reference: result.isReference ?? false,
    };
  }

  /**
   * Write credential to vault
   */
  async writeCredential(
    scope: string,
    data: Record<string, unknown>
  ): Promise<{
    scope: string;
    created: boolean;
    updated: boolean;
    sensitivity: string;
  }> {
    this.ensureConnected();
    this.updateState();
    const result = await this.client!.writeCredential(scope, data);
    return {
      scope: result.scope,
      created: result.created,
      updated: result.updated,
      sensitivity: result.sensitivity ?? 'standard',
    };
  }

  /**
   * Get consent status. Local agents can query the local vault server; remote
   * agents ask through the relay so the VPS does not need the desktop vault on
   * localhost.
   */
  async getConsentStatus(consentId: string): Promise<ConsentStatusResult> {
    this.ensureConnected();
    this.updateState();

    if (this.client!.getMode() === 'relay') {
      return this.client!.getRelayConsentStatus(consentId);
    }

    const response = await fetch(`http://127.0.0.1:8421/consent/${consentId}/status`);
    if (!response.ok) {
      return { status: 'not_found' };
    }

    const data = (await response.json()) as {
      status?: ConsentStatusResult['status'];
      session_id?: string;
      expires_at?: string;
    };

    return {
      status: data.status || 'not_found',
      sessionId: data.session_id,
      expiresAt: data.expires_at,
    };
  }

  /**
   * Get current state
   */
  getState(): AgentState {
    return { ...this.state };
  }

  /**
   * Get config
   */
  getConfig(): AgentConfig {
    return { ...this.config };
  }

  // --------------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------------

  private ensureConnected(): void {
    if (!this.client || !this.state.connected) {
      throw new AgentError('CONNECTION_FAILED', 'Not connected to vault');
    }
  }

  private updateState(): void {
    this.state.last_request_at = new Date().toISOString();
    this.state.request_count++;
  }
}
