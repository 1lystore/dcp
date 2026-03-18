/**
 * Local Transport for DCP Client
 *
 * REST transport to DCP server at localhost:8420.
 * See PRD Section A4.1 for endpoint mapping.
 */

import type {
  Transport,
  ResolvedConfig,
  Chain,
  GetAddressResult,
  SignTxInput,
  SignTxResult,
  SignMessageInput,
  SignMessageResult,
  SignTypedDataInput,
  SignTypedDataResult,
  SignX402Input,
  SignX402Result,
  ReadCredentialResult,
  WriteCredentialResult,
  BudgetCheckInput,
  BudgetCheckResult,
  HealthCheckResult,
  SessionInfo,
} from './types.js';
import { DcpError, parseErrorResponse, vaultOffline, vaultLocked } from './errors.js';

// ============================================================================
// Local Transport Implementation
// ============================================================================

export class LocalTransport implements Transport {
  private config: ResolvedConfig;
  private sessionByScope: Map<string, SessionInfo> = new Map();

  constructor(config: ResolvedConfig) {
    this.config = config;
  }

  // --------------------------------------------------------------------------
  // Health Check
  // --------------------------------------------------------------------------

  async isAvailable(): Promise<HealthCheckResult> {
    try {
      const response = await this.fetch('/health', {
        method: 'GET',
        timeout: this.config.localCheckTimeoutMs,
      });

      const data = await response.json() as {
        status?: string;
        initialized?: boolean;
        unlocked?: boolean;
        version?: string;
      };

      return {
        available: true,
        unlocked: data.unlocked ?? false,
        version: data.version,
        mode: 'local',
      };
    } catch {
      return {
        available: false,
        unlocked: false,
        mode: 'local',
      };
    }
  }

  // --------------------------------------------------------------------------
  // Get Address
  // --------------------------------------------------------------------------

  async getAddress(chain: Chain): Promise<GetAddressResult> {
    const response = await this.fetch(`/address/${chain}`, { method: 'GET' });
    const data = await this.handleResponse<{ chain: Chain; address: string }>(response);

    return {
      chain: data.chain,
      address: data.address,
    };
  }

  // --------------------------------------------------------------------------
  // Sign Transaction
  // --------------------------------------------------------------------------

  async signTx(input: SignTxInput): Promise<SignTxResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const body = {
      chain: input.chain,
      unsigned_tx: input.unsignedTx,
      amount: input.amount,
      currency: input.currency,
      agent_name: this.config.agentName,
      session_id: sessionId,
      description: input.description,
      idempotency_key: input.idempotencyKey,
      destination: input.destination,
    };

    const response = await this.fetch('/v1/vault/sign', {
      method: 'POST',
      body: this.jsonStringify(body),
    });

    const data = await this.handleResponse<{
      signed_tx: string;
      signature: string;
      chain: Chain;
      remaining_daily?: number;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
    }>(response);

    // Handle consent required
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
        approve_url: this.config.localUrl,
      });
    }

    // Cache session if returned
    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signedTx: data.signed_tx,
      signature: data.signature,
      chain: data.chain,
      remainingDaily: data.remaining_daily,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Sign Message
  // --------------------------------------------------------------------------

  async signMessage(input: SignMessageInput): Promise<SignMessageResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const body = {
      chain: input.chain,
      message: input.message,
      encoding: input.encoding || 'utf8',
      agent_name: this.config.agentName,
      session_id: sessionId,
      description: input.description,
    };

    const response = await this.fetch('/v1/vault/sign_message', {
      method: 'POST',
      body: this.jsonStringify(body),
    });

    const data = await this.handleResponse<{
      signature: string;
      public_key: string;
      chain: Chain;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
    }>(response);

    // Handle consent required
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
        approve_url: this.config.localUrl,
      });
    }

    // Cache session if returned
    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signature: data.signature,
      publicKey: data.public_key,
      chain: data.chain,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Sign Typed Data (EIP-712)
  // --------------------------------------------------------------------------

  async signTypedData(input: SignTypedDataInput): Promise<SignTypedDataResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const body = {
      chain: input.chain,
      typed_data: input.typedData,
      agent_name: this.config.agentName,
      session_id: sessionId,
      description: input.description,
    };

    const response = await this.fetch('/v1/vault/sign_typed_data', {
      method: 'POST',
      body: this.jsonStringify(body),
    });

    const data = await this.handleResponse<{
      signature: string;
      public_key: string;
      chain: Chain;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
    }>(response);

    // Handle consent required
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
        approve_url: this.config.localUrl,
      });
    }

    // Cache session if returned
    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signature: data.signature,
      publicKey: data.public_key,
      chain: data.chain,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Sign x402 Payment
  // --------------------------------------------------------------------------

  async signX402(input: SignX402Input): Promise<SignX402Result> {
    const chain = input.network === 'solana' ? 'solana' : 'base';
    const walletScope = `crypto.wallet.${chain}`;
    const sessionId = this.getSessionId(walletScope);

    const body = {
      network: input.network,
      payload: input.payload,
      amount: input.amount,
      currency: input.currency,
      recipient: input.recipient,
      purpose: input.purpose,
      typed_data: input.typedData,
      agent_name: this.config.agentName,
      session_id: sessionId,
    };

    const response = await this.fetch('/v1/vault/sign_x402', {
      method: 'POST',
      body: this.jsonStringify(body),
    });

    const data = await this.handleResponse<{
      signature: string;
      public_key: string;
      chain: Chain;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
    }>(response);

    // Handle consent required
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for x402 signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
        approve_url: this.config.localUrl,
      });
    }

    // Cache session if returned
    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signature: data.signature,
      publicKey: data.public_key,
      chain: data.chain,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Read Credential
  // --------------------------------------------------------------------------

  async readCredential(scope: string, fields?: string[]): Promise<ReadCredentialResult> {
    const sessionId = this.getSessionId(scope);

    const body = {
      scope,
      fields,
      agent_name: this.config.agentName,
      session_id: sessionId,
    };

    const response = await this.fetch('/v1/vault/read', {
      method: 'POST',
      body: this.jsonStringify(body),
    });

    const data = await this.handleResponse<{
      scope: string;
      data?: Record<string, unknown>;
      sensitivity?: 'standard' | 'sensitive' | 'critical';
      is_reference?: boolean;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      session_id?: string;
    }>(response);

    // Handle consent required
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for read', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
        approve_url: this.config.localUrl,
        scope,
      });
    }

    // Cache session if returned
    if (data.session_id) {
      this.cacheSession(scope, data.session_id);
    }

    return {
      scope: data.scope,
      data: data.data ?? null,
      sensitivity: data.sensitivity,
      isReference: data.is_reference,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Write Credential
  // --------------------------------------------------------------------------

  async writeCredential(
    scope: string,
    data: Record<string, unknown>
  ): Promise<WriteCredentialResult> {
    const sessionId = this.getSessionId(scope);

    const body = {
      scope,
      data,
      agent_name: this.config.agentName,
      session_id: sessionId,
    };

    const response = await this.fetch('/v1/vault/write', {
      method: 'POST',
      body: this.jsonStringify(body),
    });

    const result = await this.handleResponse<{
      scope: string;
      created?: boolean;
      updated?: boolean;
      sensitivity?: 'standard' | 'sensitive' | 'critical';
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      session_id?: string;
    }>(response);

    // Handle consent required
    if (result.requires_consent && result.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for write', {
        consent_id: result.consent_id,
        expires_at: result.expires_at,
        approve_url: this.config.localUrl,
        scope,
      });
    }

    // Cache session if returned
    if (result.session_id) {
      this.cacheSession(scope, result.session_id);
    }

    return {
      scope: result.scope,
      created: result.created ?? false,
      updated: result.updated ?? false,
      sensitivity: result.sensitivity,
      sessionId: result.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Budget Check
  // --------------------------------------------------------------------------

  async budgetCheck(input: BudgetCheckInput): Promise<BudgetCheckResult> {
    const params = new URLSearchParams({
      amount: String(input.amount),
      currency: input.currency,
    });

    if (input.chain) {
      params.set('chain', input.chain);
    }

    const response = await this.fetch(`/budget/check?${params.toString()}`, {
      method: 'GET',
    });

    const data = await this.handleResponse<{
      allowed: boolean;
      limits?: {
        per_tx: number;
        daily: number;
        approval_threshold: number;
      };
      remaining?: {
        daily: number;
        per_tx: number;
      };
      requires_approval?: boolean;
      reason?: string;
    }>(response);

    return {
      allowed: data.allowed,
      requiresApproval: data.requires_approval ?? false,
      remainingDaily: data.remaining?.daily ?? 0,
      remainingTx: data.remaining?.per_tx ?? 0,
      limits: data.limits
        ? {
            perTx: data.limits.per_tx,
            daily: data.limits.daily,
            approvalThreshold: data.limits.approval_threshold,
          }
        : undefined,
      reason: data.reason,
    };
  }

  // --------------------------------------------------------------------------
  // Session Management
  // --------------------------------------------------------------------------

  getSessionId(scope: string): string | undefined {
    const session = this.sessionByScope.get(scope);
    if (!session) return undefined;

    // Check if session has expired
    if (session.expiresAt < new Date()) {
      this.sessionByScope.delete(scope);
      return undefined;
    }

    return session.sessionId;
  }

  clearSession(): void {
    this.sessionByScope.clear();
  }

  private cacheSession(scope: string, sessionId: string): void {
    // Default session duration: 4 hours
    const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000);

    this.sessionByScope.set(scope, {
      sessionId,
      scope,
      expiresAt,
      lastUsedAt: new Date(),
    });
  }

  // --------------------------------------------------------------------------
  // Cleanup
  // --------------------------------------------------------------------------

  async close(): Promise<void> {
    this.clearSession();
  }

  // --------------------------------------------------------------------------
  // HTTP Utilities
  // --------------------------------------------------------------------------

  private async fetch(
    path: string,
    options: {
      method: 'GET' | 'POST';
      body?: string;
      timeout?: number;
    }
  ): Promise<Response> {
    const url = `${this.config.localUrl}${path}`;
    const timeout = options.timeout ?? this.config.timeoutMs;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        method: options.method,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: options.body,
        signal: controller.signal,
      });

      return response;
    } catch (err) {
      if (err instanceof Error) {
        if (err.name === 'AbortError') {
          throw vaultOffline('Request timed out - DCP vault may be offline');
        }
        // Connection refused or network error
        if (
          err.message.includes('ECONNREFUSED') ||
          err.message.includes('fetch failed') ||
          err.message.includes('network')
        ) {
          throw vaultOffline('DCP vault is not running');
        }
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const data = await response.json() as Record<string, unknown>;

    if (!response.ok) {
      throw parseErrorResponse(data);
    }

    // Check for locked vault
    if (data.error && typeof data.error === 'object') {
      const errorObj = data.error as { code?: string };
      if (errorObj.code === 'VAULT_LOCKED') {
        throw vaultLocked();
      }
    }

    return data as T;
  }

  /**
   * JSON.stringify with BigInt support
   */
  private jsonStringify(obj: unknown): string {
    return JSON.stringify(obj, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
  }
}
