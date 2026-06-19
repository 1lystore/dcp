/**
 * Relay Transport for DCP Client
 *
 * HPKE-encrypted transport via relay server for cloud agents.
 * See protocol spec section A4.2 for relay protocol specification.
 *
 * This transport:
 * - Encrypts all payloads with HPKE (X25519 + ChaCha20-Poly1305)
 * - Uses AAD binding to envelope metadata
 * - Supports service signature for trusted services
 * - Uses HTTP long-poll (POST + poll GET) for request/response
 */

import WebSocket from 'ws';
import type {
  Transport,
  ResolvedConfig,
  Chain,
  GetAddressResult,
  SignTxInput,
  SignTxResult,
  TransferInput,
  TransferResult,
  SwapInput,
  SwapResult,
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
  ConsentStatusResult,
  RelayEnvelope,
  RelayResponseEnvelope,
  DecryptedRelayPayload,
  EnvelopeAad,
  HpkeKeyPair,
  SessionInfo,
} from './types.js';
import { RELAY_VERSION } from './types.js';
import {
  DcpError,
  relayUnavailable,
  relayTimeout,
  invalidConfig,
  parseErrorResponse,
} from './errors.js';
import {
  encrypt,
  decrypt,
  encodeToBase64,
  decodeFromBase64,
  generateKeyPair,
  decodePublicKey,
  sign,
  zeroize,
  generateRequestId,
} from './crypto.js';

// ============================================================================
// Constants
// ============================================================================

const POLL_INTERVAL_MS = 300;
const MAX_POLL_ATTEMPTS = 100; // 30 seconds max (100 * 300ms)
const WS_CONNECT_TIMEOUT_MS = 5000;

type WsMessageType = 'request' | 'response' | 'ack' | 'error' | 'heartbeat';

interface WsMessage {
  type: WsMessageType;
  payload: unknown;
  timestamp: string;
}

interface PendingWsRequest {
  replyPrivateKey: Buffer;
  aad: EnvelopeAad;
  resolve: (payload: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

// ============================================================================
// Relay Transport Implementation
// ============================================================================

export class RelayTransport implements Transport {
  private config: ResolvedConfig;
  private sessionByScope: Map<string, SessionInfo> = new Map();
  private vaultPublicKey: Buffer | null = null;
  private servicePrivateKey: Buffer | null = null;
  private closed = false;
  private ws: WebSocket | null = null;
  private wsState: 'disconnected' | 'connecting' | 'connected' = 'disconnected';
  private wsConnectPromise: Promise<boolean> | null = null;
  private pendingWsRequests: Map<string, PendingWsRequest> = new Map();

  constructor(config: ResolvedConfig) {
    this.config = config;

    // Parse vault HPKE public key
    if (config.vaultHpkePublicKey) {
      this.vaultPublicKey = decodePublicKey(config.vaultHpkePublicKey);
    }

    // Parse service private key (Ed25519, 64 bytes base64 or hex)
    if (config.servicePrivateKey) {
      try {
        // Try base64 first
        this.servicePrivateKey = Buffer.from(config.servicePrivateKey, 'base64');
        if (this.servicePrivateKey.length !== 64) {
          // Try hex
          this.servicePrivateKey = Buffer.from(config.servicePrivateKey, 'hex');
        }
        if (this.servicePrivateKey.length !== 64) {
          throw new Error('Invalid key length');
        }
      } catch {
        throw invalidConfig('servicePrivateKey must be a 64-byte Ed25519 private key (base64 or hex)');
      }
    }
  }

  // --------------------------------------------------------------------------
  // Health Check
  // --------------------------------------------------------------------------

  async isAvailable(): Promise<HealthCheckResult> {
    // In relay mode, we can't really check if the vault is available
    // without sending a request. We just verify config is valid.
    if (!this.config.vaultId) {
      return {
        available: false,
        unlocked: false,
        mode: 'relay',
      };
    }

    if (!this.vaultPublicKey) {
      return {
        available: false,
        unlocked: false,
        mode: 'relay',
      };
    }

    if (!this.config.serviceId || !this.servicePrivateKey) {
      return {
        available: false,
        unlocked: false,
        mode: 'relay',
      };
    }

    // Try to ping the relay server
    try {
      const relayUrl = this.getHttpUrl();
      const response = await fetch(`${relayUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      if (response.ok) {
        return {
          available: true,
          unlocked: true, // We assume unlocked if relay is reachable
          mode: 'relay',
        };
      }
    } catch {
      // Relay might not have a /health endpoint, that's okay
    }

    return {
      available: true,
      unlocked: true,
      mode: 'relay',
    };
  }

  // --------------------------------------------------------------------------
  // Get Address
  // --------------------------------------------------------------------------

  async getAddress(chain: Chain): Promise<GetAddressResult> {
    const response = await this.relayRequest('get_address', { chain });

    const data = response as { chain?: Chain; address?: string; error?: { code?: string; message?: string } };
    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }
    if (!data.address) {
      throw new DcpError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    return {
      chain: data.chain || chain,
      address: data.address,
    };
  }

  // --------------------------------------------------------------------------
  // Sign Transaction
  // --------------------------------------------------------------------------

  async signTx(input: SignTxInput): Promise<SignTxResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const params = {
      chain: input.chain,
      unsigned_tx: input.unsignedTx,
      amount: input.amount,
      currency: input.currency,
      description: input.description,
      idempotency_key: input.idempotencyKey,
      destination: input.destination,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_sign', params);

    const data = response as {
      signed_tx?: string;
      signature?: string;
      chain?: Chain;
      remaining_daily?: number;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      error?: { code?: string; message?: string };
    };

    // Handle errors in response
    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    // Handle consent required
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
      });
    }

    if (!data.signed_tx || !data.signature) {
      throw new DcpError('INTERNAL_ERROR', 'Invalid response from vault');
    }

    // Cache session if returned
    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signedTx: data.signed_tx,
      signature: data.signature,
      chain: data.chain || input.chain,
      remainingDaily: data.remaining_daily,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Transfer (DCP builds + signs + submits)
  // --------------------------------------------------------------------------

  async transfer(input: TransferInput): Promise<TransferResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const params = {
      chain: input.chain,
      to: input.to,
      amount: input.amount,
      currency: input.currency,
      mint: input.mint,
      decimals: input.decimals,
      confirm: input.confirm,
      description: input.description,
      idempotency_key: input.idempotencyKey,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_transfer', params);

    const data = response as {
      chain?: Chain;
      from?: string;
      to?: string;
      amount?: number;
      currency?: string;
      signature?: string;
      status?: string;
      explorer_url?: string;
      remaining_daily?: number;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for transfer', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
      });
    }

    if (!data.signature) {
      throw new DcpError('INTERNAL_ERROR', 'Invalid response from vault');
    }

    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      chain: data.chain || input.chain,
      from: data.from || '',
      to: data.to || input.to,
      amount: data.amount ?? input.amount,
      currency: data.currency || input.currency || 'SOL',
      signature: data.signature,
      status: data.status || 'submitted',
      explorerUrl: data.explorer_url || `https://solscan.io/tx/${data.signature}`,
      remainingDaily: data.remaining_daily,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Swap (Jupiter)
  // --------------------------------------------------------------------------

  async swap(input: SwapInput): Promise<SwapResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const params = {
      chain: input.chain,
      from_token: input.fromToken,
      to_token: input.toToken,
      amount: input.amount,
      slippage_bps: input.slippageBps,
      from_decimals: input.fromDecimals,
      to_decimals: input.toDecimals,
      confirm: input.confirm,
      description: input.description,
      idempotency_key: input.idempotencyKey,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_swap', params);
    const data = response as {
      chain?: Chain; from_token?: string; to_token?: string; amount?: number; out_amount?: string;
      signature?: string; status?: string; explorer_url?: string; remaining_daily?: number; session_id?: string;
      requires_consent?: boolean; consent_id?: string; expires_at?: string; error?: { code?: string; message?: string };
    };

    if (data.error) throw parseErrorResponse({ error: data.error });
    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for swap', { consent_id: data.consent_id, expires_at: data.expires_at });
    }
    if (!data.signature) throw new DcpError('INTERNAL_ERROR', 'Invalid response from vault');
    if (data.session_id) this.cacheSession(walletScope, data.session_id);

    return {
      chain: data.chain || input.chain, fromToken: data.from_token || input.fromToken, toToken: data.to_token || input.toToken,
      amount: data.amount ?? input.amount, outAmount: data.out_amount, signature: data.signature, status: data.status || 'submitted',
      explorerUrl: data.explorer_url || `https://solscan.io/tx/${data.signature}`, remainingDaily: data.remaining_daily, sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Sign Message
  // --------------------------------------------------------------------------

  async signMessage(input: SignMessageInput): Promise<SignMessageResult> {
    const walletScope = `crypto.wallet.${input.chain}`;
    const sessionId = this.getSessionId(walletScope);

    const params = {
      chain: input.chain,
      message: input.message,
      encoding: input.encoding || 'utf8',
      description: input.description,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_sign_message', params);

    const data = response as {
      signature?: string;
      public_key?: string;
      chain?: Chain;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
      });
    }

    if (!data.signature || !data.public_key) {
      throw new DcpError('INTERNAL_ERROR', 'Invalid response from vault');
    }

    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signature: data.signature,
      publicKey: data.public_key,
      chain: data.chain || input.chain,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Sign x402 Payment
  // --------------------------------------------------------------------------

  async signX402(input: SignX402Input): Promise<SignX402Result> {
    if (input.network !== 'solana') {
      throw new DcpError('INVALID_CHAIN', 'Only solana network is supported');
    }
    const chain: Chain = 'solana';
    const walletScope = `crypto.wallet.${chain}`;
    const sessionId = this.getSessionId(walletScope);

    const params = {
      network: input.network,
      payload: input.payload,
      amount: input.amount,
      currency: input.currency,
      recipient: input.recipient,
      purpose: input.purpose,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_sign_x402', params);

    const data = response as {
      signature?: string;
      public_key?: string;
      chain?: Chain;
      session_id?: string;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for x402 signing', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
      });
    }

    if (!data.signature || !data.public_key) {
      throw new DcpError('INTERNAL_ERROR', 'Invalid response from vault');
    }

    if (data.session_id) {
      this.cacheSession(walletScope, data.session_id);
    }

    return {
      signature: data.signature,
      publicKey: data.public_key,
      chain: data.chain || chain,
      sessionId: data.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Read Credential
  // --------------------------------------------------------------------------

  async readCredential(scope: string, fields?: string[]): Promise<ReadCredentialResult> {
    const sessionId = this.getSessionId(scope);

    const params = {
      scope,
      fields,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_read', params);

    const data = response as {
      scope?: string;
      data?: Record<string, unknown>;
      name?: string;
      value?: unknown;
      sensitivity?: 'standard' | 'sensitive' | 'critical';
      is_reference?: boolean;
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      session_id?: string;
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    if (data.requires_consent && data.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for read', {
        consent_id: data.consent_id,
        expires_at: data.expires_at,
        scope,
      });
    }

    if (data.session_id) {
      this.cacheSession(scope, data.session_id);
    }

    return {
      scope: data.scope || scope,
      data: data.data ?? (data.value !== undefined ? { name: data.name, value: data.value } : null),
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

    const secretValue = typeof data.value === 'string'
      ? data.value
      : typeof data.api_key === 'string'
        ? data.api_key
        : typeof data.token === 'string'
          ? data.token
          : undefined;

    const params = {
      scope,
      data,
      name: typeof data.name === 'string' ? data.name : undefined,
      value: secretValue,
      session_id: sessionId,
    };

    const response = await this.relayRequest('vault_write', params);

    const result = response as {
      scope?: string;
      created?: boolean;
      updated?: boolean;
      ok?: boolean;
      sensitivity?: 'standard' | 'sensitive' | 'critical';
      requires_consent?: boolean;
      consent_id?: string;
      expires_at?: string;
      session_id?: string;
      error?: { code?: string; message?: string };
    };

    if (result.error) {
      throw parseErrorResponse({ error: result.error });
    }

    if (result.requires_consent && result.consent_id) {
      throw new DcpError('CONSENT_REQUIRED', 'User consent required for write', {
        consent_id: result.consent_id,
        expires_at: result.expires_at,
        scope,
      });
    }

    if (result.session_id) {
      this.cacheSession(scope, result.session_id);
    }

    return {
      scope: result.scope || scope,
      created: result.created ?? result.ok === true,
      updated: result.updated ?? false,
      sensitivity: result.sensitivity,
      sessionId: result.session_id,
    };
  }

  // --------------------------------------------------------------------------
  // Budget Check
  // --------------------------------------------------------------------------

  async budgetCheck(input: BudgetCheckInput): Promise<BudgetCheckResult> {
    const params = {
      amount: input.amount,
      currency: input.currency,
      chain: input.chain,
    };

    const response = await this.relayRequest('budget_check', params);

    const data = response as {
      allowed?: boolean;
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
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    return {
      allowed: data.allowed ?? false,
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
  // Pair Service (relay only)
  // --------------------------------------------------------------------------

  async pairService(input: PairServiceInput): Promise<PairServiceResult> {
    const params = {
      pairing_token: input.pairingToken,
      service_public_key: input.servicePublicKey,
      service_name: input.serviceName,
    };

    const response = await this.relayRequest('vault_pair', params);
    const data = response as {
      ok?: boolean;
      service_id?: string;
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    return {
      ok: data.ok ?? true,
      serviceId: data.service_id,
    };
  }

  async getConsentStatus(consentId: string): Promise<ConsentStatusResult> {
    const response = await this.relayRequest('consent_status', {
      consent_id: consentId,
    });

    const data = response as {
      status?: ConsentStatusResult['status'];
      session_id?: string;
      expires_at?: string;
      error?: { code?: string; message?: string };
    };

    if (data.error) {
      throw parseErrorResponse({ error: data.error });
    }

    return {
      status: data.status || 'not_found',
      sessionId: data.session_id,
      expiresAt: data.expires_at,
    };
  }

  // --------------------------------------------------------------------------
  // Session Management
  // --------------------------------------------------------------------------

  getSessionId(scope: string): string | undefined {
    const session = this.sessionByScope.get(scope);
    if (!session) return undefined;

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
    this.closed = true;
    this.clearSession();

    // Close WebSocket connection
    if (this.ws) {
      this.ws.close(1000, 'Client closed');
      this.ws = null;
    }
    this.wsState = 'disconnected';
    this.clearPendingWsRequests(new Error('Client closed'));

    // Zeroize sensitive key material
    if (this.servicePrivateKey) {
      zeroize(this.servicePrivateKey);
      this.servicePrivateKey = null;
    }
  }

  // --------------------------------------------------------------------------
  // Relay Protocol Implementation (protocol spec A4.2)
  // --------------------------------------------------------------------------

  private async relayRequest(method: string, params: Record<string, unknown>): Promise<unknown> {
    if (this.closed) {
      throw relayUnavailable('Client has been closed');
    }

    if (!this.config.vaultId) {
      throw invalidConfig('vaultId is required for relay mode');
    }

    if (!this.vaultPublicKey) {
      throw invalidConfig('vaultHpkePublicKey is required for relay mode');
    }

    if (!this.config.serviceId) {
      throw invalidConfig('serviceId is required for relay mode');
    }

    if (!this.servicePrivateKey) {
      throw invalidConfig('servicePrivateKey is required for relay mode');
    }

    // Generate ephemeral reply keypair for this request
    const replyKeyPair = await generateKeyPair();

    // Build the decrypted payload structure
    const payload: DecryptedRelayPayload = {
      method,
      params,
      agent_name: this.config.agentName,
      service_id: this.config.serviceId,
      timestamp: new Date().toISOString(),
      nonce: generateRequestId(),
      reply_public_key: replyKeyPair.publicKey.toString('base64'),
    };

    // Add service signature if service key is configured
    const payloadForSignature = { ...payload };
    const signatureData = Buffer.from(this.canonicalJson(payloadForSignature));
    payload.service_signature = sign(signatureData, this.servicePrivateKey).toString('base64');

    // Generate request ID
    const requestId = generateRequestId();

    // Determine action type from method
    const actionType = this.methodToActionType(method);

    // Construct AAD for encryption
    const aad: EnvelopeAad = {
      version: RELAY_VERSION,
      vault_id: this.config.vaultId,
      request_id: requestId,
      action_type: actionType,
    };

    // Encrypt payload
    const plaintext = Buffer.from(this.jsonStringify(payload));
    const encrypted = await encrypt(plaintext, this.vaultPublicKey, aad);
    const encryptedPayload = encodeToBase64(encrypted);

    // Build relay envelope
    const envelope: RelayEnvelope = {
      version: RELAY_VERSION,
      vault_id: this.config.vaultId,
      request_id: requestId,
      action_type: actionType,
      encrypted_payload: encryptedPayload,
      expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 minute TTL
    };

    try {
      // Prefer WebSocket, fallback to HTTP long-poll
      let responsePayload: unknown;
      const wsAvailable = await this.ensureWsConnected();
      if (wsAvailable) {
        responsePayload = await this.sendViaWebSocket(envelope, replyKeyPair, aad);
      } else {
        responsePayload = await this.sendAndPoll(envelope, replyKeyPair, aad);
      }

      // Zeroize reply private key
      zeroize(replyKeyPair.privateKey);

      return responsePayload;
    } catch (err) {
      // Zeroize reply private key on error too
      zeroize(replyKeyPair.privateKey);
      throw err;
    }
  }

  /**
   * Send request via WebSocket (primary transport)
   */
  private async sendViaWebSocket(
    envelope: RelayEnvelope,
    replyKeyPair: HpkeKeyPair,
    aad: EnvelopeAad
  ): Promise<unknown> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw relayUnavailable('Relay WebSocket not connected');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingWsRequests.delete(envelope.request_id);
        reject(relayTimeout('Timeout waiting for relay response'));
      }, this.config.timeoutMs);

      this.pendingWsRequests.set(envelope.request_id, {
        replyPrivateKey: replyKeyPair.privateKey,
        aad,
        resolve,
        reject,
        timeout,
      });

      const msg: WsMessage = {
        type: 'request',
        payload: envelope,
        timestamp: new Date().toISOString(),
      };

      try {
        this.ws?.send(JSON.stringify(msg));
      } catch (err) {
        clearTimeout(timeout);
        this.pendingWsRequests.delete(envelope.request_id);
        reject(relayUnavailable(err instanceof Error ? err.message : 'Failed to send request'));
      }
    });
  }

  /**
   * Send request to relay and poll for response (protocol spec A4.2 long-poll fallback)
   */
  private async sendAndPoll(
    envelope: RelayEnvelope,
    replyKeyPair: HpkeKeyPair,
    aad: EnvelopeAad
  ): Promise<unknown> {
    const relayUrl = this.getHttpUrl();

    // POST request to relay
    const postResponse = await fetch(`${relayUrl}/relay/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(envelope),
      signal: AbortSignal.timeout(this.config.timeoutMs),
    });

    if (!postResponse.ok) {
      const errorData = await postResponse.json().catch(() => ({}));
      throw this.handleRelayError(errorData);
    }

    const postData = await postResponse.json() as {
      queued?: boolean;
      accepted?: boolean;
      encrypted_payload?: string;
      error?: { code?: string; message?: string };
    };

    // If response is inline (vault responded immediately), decrypt and return
    if (postData.encrypted_payload) {
      return this.decryptResponse(postData.encrypted_payload, replyKeyPair.privateKey, aad);
    }

    // Otherwise, poll for response
    if (!postData.queued && !postData.accepted) {
      throw relayUnavailable('Relay did not queue request');
    }

    // Poll for response
    let attempts = 0;
    while (attempts < MAX_POLL_ATTEMPTS) {
      await this.sleep(POLL_INTERVAL_MS);
      attempts++;

      const pollResponse = await fetch(`${relayUrl}/relay/response/${envelope.request_id}`, {
        method: 'GET',
        signal: AbortSignal.timeout(10000),
      });

      if (pollResponse.status === 202) {
        // Still waiting
        continue;
      }

      if (pollResponse.status === 404) {
        // Request expired or not found
        throw relayTimeout('Request expired');
      }

      if (!pollResponse.ok) {
        const errorData = await pollResponse.json().catch(() => ({}));
        throw this.handleRelayError(errorData);
      }

      const pollData = await pollResponse.json() as {
        encrypted_payload?: string;
        error?: { code?: string; message?: string };
      };

      if (pollData.error) {
        throw this.handleRelayError(pollData);
      }

      if (pollData.encrypted_payload) {
        return this.decryptResponse(pollData.encrypted_payload, replyKeyPair.privateKey, aad);
      }
    }

    throw relayTimeout('Timeout waiting for vault response');
  }

  /**
   * Decrypt response from vault
   */
  private async decryptResponse(
    encryptedPayload: string,
    privateKey: Buffer,
    aad: EnvelopeAad
  ): Promise<unknown> {
    const encrypted = decodeFromBase64(encryptedPayload);
    const plaintext = await decrypt(encrypted, privateKey, aad);

    try {
      return JSON.parse(plaintext.toString('utf8'));
    } catch {
      throw new DcpError('DECRYPTION_FAILED', 'Failed to parse decrypted response');
    }
  }

  /**
   * Map method name to relay action type
   */
  private methodToActionType(method: string): string {
    switch (method) {
      case 'vault_sign':
      case 'vault_sign_message':
      case 'vault_sign_x402':
        return 'sign';
      case 'vault_read':
        return 'read';
      case 'vault_write':
        return 'write';
      case 'vault_pair':
        return 'write';
      case 'consent_status':
        return 'read';
      case 'budget_check':
        return 'budget';
      case 'get_address':
        return 'read';
      default:
        return 'read';
    }
  }

  /**
   * Get HTTP URL from WebSocket URL
   */
  private getHttpUrl(): string {
    let url = this.config.relayUrl;

    // Convert ws:// to http://
    if (url.startsWith('ws://')) {
      url = url.replace('ws://', 'http://');
    } else if (url.startsWith('wss://')) {
      url = url.replace('wss://', 'https://');
    }

    // Remove /ws suffix if present
    if (url.endsWith('/ws')) {
      url = url.slice(0, -3);
    }
    if (url.endsWith('/ws-client')) {
      url = url.slice(0, -10);
    }

    return url;
  }

  /**
   * Get WebSocket URL for client connections
   */
  private getWsUrl(): string {
    let url = this.config.relayUrl;

    if (url.startsWith('http://')) {
      url = url.replace('http://', 'ws://');
    } else if (url.startsWith('https://')) {
      url = url.replace('https://', 'wss://');
    }

    // Remove /ws suffix if present (vault endpoint)
    if (url.endsWith('/ws')) {
      url = url.slice(0, -3);
    }

    // Ensure /ws-client suffix
    if (!url.endsWith('/ws-client')) {
      url = url.replace(/\/$/, '');
      url = `${url}/ws-client`;
    }

    return url;
  }

  /**
   * Ensure WebSocket is connected
   */
  private async ensureWsConnected(): Promise<boolean> {
    if (this.wsState === 'connected' && this.ws?.readyState === WebSocket.OPEN) {
      return true;
    }

    if (this.wsState === 'connecting' && this.wsConnectPromise) {
      return this.wsConnectPromise;
    }

    if (this.closed) {
      return false;
    }

    this.wsState = 'connecting';

    this.wsConnectPromise = new Promise((resolve) => {
      const wsUrl = this.getWsUrl();
      const ws = new WebSocket(wsUrl);
      let settled = false;

      const finish = (ok: boolean): void => {
        if (settled) return;
        settled = true;
        this.wsConnectPromise = null;
        resolve(ok);
      };

      const timeout = setTimeout(() => {
        if (ws.readyState !== WebSocket.OPEN) {
          ws.close();
          this.wsState = 'disconnected';
          finish(false);
        }
      }, WS_CONNECT_TIMEOUT_MS);

      ws.on('open', () => {
        clearTimeout(timeout);
        this.ws = ws;
        this.wsState = 'connected';
        this.attachWsHandlers(ws);
        finish(true);
      });

      ws.on('error', () => {
        clearTimeout(timeout);
        if (this.ws === ws) {
          this.ws = null;
        }
        this.wsState = 'disconnected';
        finish(false);
      });

      ws.on('close', () => {
        clearTimeout(timeout);
        if (this.ws === ws) {
          this.ws = null;
        }
        this.wsState = 'disconnected';
        finish(false);
      });
    });

    return this.wsConnectPromise;
  }

  private attachWsHandlers(ws: WebSocket): void {
    ws.on('message', (data) => {
      this.handleWsMessage(data.toString());
    });

    ws.on('close', () => {
      this.wsState = 'disconnected';
      this.clearPendingWsRequests(relayUnavailable('Relay WebSocket disconnected'));
    });

    ws.on('error', (err) => {
      this.wsState = 'disconnected';
      this.clearPendingWsRequests(relayUnavailable(err instanceof Error ? err.message : 'Relay WebSocket error'));
    });
  }

  private handleWsMessage(raw: string): void {
    let msg: WsMessage;
    try {
      msg = JSON.parse(raw) as WsMessage;
    } catch {
      return;
    }

    switch (msg.type) {
      case 'response': {
        const payload = msg.payload as RelayResponseEnvelope;
        const pending = this.pendingWsRequests.get(payload.request_id);
        if (!pending) return;
        clearTimeout(pending.timeout);
        this.pendingWsRequests.delete(payload.request_id);
        this.decryptResponse(payload.encrypted_payload, pending.replyPrivateKey, pending.aad)
          .then((data) => {
            pending.resolve(data);
          })
          .catch((err) => {
            pending.reject(err instanceof Error ? err : new Error(String(err)));
          });
        break;
      }

      case 'error': {
        const payload = msg.payload as { code?: string; message?: string; request_id?: string };
        const errorObj = this.handleRelayError({ error: { code: payload.code, message: payload.message } });
        if (payload.request_id) {
          const pending = this.pendingWsRequests.get(payload.request_id);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingWsRequests.delete(payload.request_id);
            pending.reject(errorObj);
          }
          return;
        }

        // If no request_id, reject all pending requests
        this.clearPendingWsRequests(errorObj);
        break;
      }

      case 'ack':
      case 'heartbeat':
      default:
        break;
    }
  }

  private clearPendingWsRequests(error: Error): void {
    for (const [requestId, pending] of this.pendingWsRequests) {
      clearTimeout(pending.timeout);
      pending.reject(error);
      this.pendingWsRequests.delete(requestId);
    }
  }

  /**
   * Handle relay error response
   */
  private handleRelayError(data: unknown): DcpError {
    if (data && typeof data === 'object') {
      const err = data as { error?: { code?: string; message?: string } };
      if (err.error) {
        const code = err.error.code || 'RELAY_UNAVAILABLE';
        const message = err.error.message || 'Relay error';

        if (code === 'RELAY_VAULT_NOT_CONNECTED') {
          return new DcpError('VAULT_OFFLINE', 'Vault is not connected to relay');
        }

        if (code === 'RELAY_RATE_LIMITED') {
          return new DcpError('RELAY_RATE_LIMITED', message);
        }

        return new DcpError('RELAY_UNAVAILABLE', message);
      }
    }

    return relayUnavailable('Unknown relay error');
  }

  /**
   * JSON.stringify with BigInt support
   */
  private jsonStringify(obj: unknown): string {
    return JSON.stringify(obj, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
  }

  /**
   * Canonical JSON (stable key ordering) for signatures
   */
  private canonicalJson(obj: unknown): string {
    const normalize = (value: unknown): unknown => {
      if (value === null || value === undefined) return value;
      if (typeof value === 'bigint') return value.toString();
      if (Array.isArray(value)) return value.map(normalize);
      if (typeof value === 'object') {
        const record = value as Record<string, unknown>;
        const sorted: Record<string, unknown> = {};
        for (const key of Object.keys(record).sort()) {
          sorted[key] = normalize(record[key]);
        }
        return sorted;
      }
      return value;
    };

    return JSON.stringify(normalize(obj));
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
