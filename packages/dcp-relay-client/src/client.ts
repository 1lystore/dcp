/**
 * DCP Relay Client
 *
 * Connects local vaults to the DCP relay with:
 * - WebSocket connection management
 * - Automatic reconnection with exponential backoff + jitter
 * - Heartbeat (30s interval)
 * - RFC 9180 HPKE encryption/decryption with AAD binding
 * - Ed25519 signed registration (defense in depth)
 *
 * From protocol spec Section 4.2:
 * - WebSocket connection management
 * - Reconnect + heartbeat
 * - Encrypt/decrypt payloads
 * - Idempotency handling
 */

import WebSocket from 'ws';
import type {
  RelayEnvelope,
  RelayResponseEnvelope,
  WsMessage,
  ActionType,
  RegisterPayload,
} from '@dcprotocol/relay';
import { RELAY_VERSION } from '@dcprotocol/relay';
import type {
  RelayClientConfig,
  RelayClientEvents,
  RequestHandler,
  ClientState,
  HpkeKeyPair,
  SigningKeyPair,
  EnvelopeAad,
} from './types.js';
import {
  ClientError,
  DEFAULT_CLIENT_CONFIG,
  RECONNECT_MIN_MS,
  RECONNECT_MAX_MS,
  HEARTBEAT_INTERVAL_MS,
} from './types.js';
import {
  encrypt,
  decrypt,
  encodeToBase64,
  decodeFromBase64,
  encodePublicKey,
  zeroize,
  sign,
  generateNonce,
} from './crypto.js';

// ============================================================================
// Event Emitter (Simple Implementation)
// ============================================================================

type EventCallback = (...args: unknown[]) => void;

class SimpleEmitter {
  private listeners: Map<string, Set<EventCallback>> = new Map();

  on(event: string, callback: EventCallback): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }

  off(event: string, callback: EventCallback): void {
    this.listeners.get(event)?.delete(callback);
  }

  emit(event: string, ...args: unknown[]): void {
    for (const callback of this.listeners.get(event) ?? []) {
      try {
        callback(...args);
      } catch (err) {
        console.error(`Error in event listener for ${event}:`, err);
      }
    }
  }
}

// ============================================================================
// Relay Client
// ============================================================================

export class RelayClient extends SimpleEmitter {
  private config: RelayClientConfig;
  private ws: WebSocket | null = null;
  private state: ClientState = 'disconnected';
  private reconnectAttempt = 0;
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private requestHandler: RequestHandler | null = null;
  private pendingResponses: Map<string, RelayResponseEnvelope> = new Map();

  constructor(config: Partial<RelayClientConfig> & Pick<RelayClientConfig, 'relayUrl' | 'vaultId' | 'keyPair' | 'signingKeyPair'>) {
    super();
    this.config = {
      ...DEFAULT_CLIENT_CONFIG,
      ...config,
    } as RelayClientConfig;
  }

  // --------------------------------------------------------------------------
  // Public API
  // --------------------------------------------------------------------------

  /**
   * Connect to the relay server
   */
  async connect(): Promise<void> {
    if (this.state === 'connected' || this.state === 'connecting') {
      throw new ClientError('CLIENT_ALREADY_CONNECTED', 'Client is already connected or connecting');
    }

    this.state = 'connecting';
    await this.doConnect();
  }

  /**
   * Disconnect from the relay server
   */
  disconnect(): void {
    this.clearReconnectTimeout();
    this.clearHeartbeat();

    if (this.ws) {
      // Send unregister message
      this.sendWsMessage({
        type: 'unregister',
        payload: { vault_id: this.config.vaultId },
        timestamp: new Date().toISOString(),
      });

      this.ws.close(1000, 'Client disconnected');
      this.ws = null;
    }

    this.state = 'disconnected';
    this.emit('disconnected', 'Client disconnected');
  }

  /**
   * Set the request handler for incoming relay requests
   */
  setRequestHandler(handler: RequestHandler): void {
    this.requestHandler = handler;
  }

  /**
   * Get current connection state
   */
  getState(): ClientState {
    return this.state;
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.state === 'connected' && this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Encrypt a payload for sending to a recipient with AAD binding
   * Used by MCP clients sending requests to vaults
   */
  async encryptPayload(plaintext: Buffer, recipientPublicKey: Buffer, aad?: EnvelopeAad): Promise<string> {
    const encrypted = await encrypt(plaintext, recipientPublicKey, aad);
    return encodeToBase64(encrypted);
  }

  /**
   * Decrypt a payload received from relay with AAD verification
   */
  async decryptPayload(encryptedBase64: string, aad?: EnvelopeAad): Promise<Buffer> {
    const encrypted = decodeFromBase64(encryptedBase64);
    return decrypt(encrypted, this.config.keyPair.privateKey, aad);
  }

  /**
   * Get HPKE public key for sharing with clients
   */
  getPublicKey(): string {
    return encodePublicKey(this.config.keyPair.publicKey);
  }

  /**
   * Get signing public key for relay authentication
   */
  getSigningPublicKey(): string {
    return this.config.signingKeyPair.publicKey.toString('base64');
  }

  /**
   * Send pairing result back to relay after user approves/denies a claim
   * @param claimId - The claim ID to respond to
   * @param approved - Whether the pairing was approved
   * @param agentId - The assigned agent ID (only if approved)
   */
  sendPairingResult(claimId: string, approved: boolean, agentId?: string): boolean {
    return this.sendWsMessage({
      type: 'pairing_result',
      payload: {
        claim_id: claimId,
        action: approved ? 'approve' : 'deny',
        agent_id: agentId,
        vault_id: this.config.vaultId,
      },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Reply to a Cloud-Connect control message (redeem/status) from the relay.
   * `controlId` correlates the reply to the relay's pending request.
   */
  sendCloudConnectResult(controlId: string, result: Record<string, unknown>): boolean {
    return this.sendWsMessage({
      type: 'cloud_connect_result',
      payload: { control_id: controlId, vault_id: this.config.vaultId, ...result },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    this.disconnect();
    zeroize(this.config.keyPair.privateKey);
    zeroize(this.config.signingKeyPair.privateKey);
  }

  // --------------------------------------------------------------------------
  // Connection Management
  // --------------------------------------------------------------------------

  private async doConnect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        // Convert HTTP URL to WS URL if needed
        let wsUrl = this.config.relayUrl;
        if (wsUrl.startsWith('http://')) {
          wsUrl = wsUrl.replace('http://', 'ws://');
        } else if (wsUrl.startsWith('https://')) {
          wsUrl = wsUrl.replace('https://', 'wss://');
        }
        if (!wsUrl.endsWith('/ws')) {
          wsUrl = wsUrl.replace(/\/?$/, '/ws');
        }

        this.ws = new WebSocket(wsUrl);

        this.ws.on('open', () => {
          this.state = 'connected';
          this.reconnectAttempt = 0;
          this.startHeartbeat();
          this.register();
          this.emit('connected');
          resolve();
        });

        this.ws.on('message', (data: Buffer | string) => {
          this.handleMessage(data);
        });

        this.ws.on('close', (code: number, reason: Buffer) => {
          const reasonStr = reason.toString() || `Code ${code}`;
          this.handleDisconnect(reasonStr);
        });

        this.ws.on('error', (err: Error) => {
          if (this.state === 'connecting') {
            reject(new ClientError('CLIENT_CONNECTION_FAILED', err.message));
          }
          this.emit('error', err);
        });
      } catch (err) {
        reject(new ClientError('CLIENT_CONNECTION_FAILED', err instanceof Error ? err.message : String(err)));
      }
    });
  }

  /**
   * Register with relay using signed authentication
   */
  private register(): void {
    const timestamp = new Date().toISOString();
    const nonce = generateNonce(32);

    // Construct message to sign: vault_id || timestamp || nonce
    const message = Buffer.concat([
      Buffer.from(this.config.vaultId, 'utf8'),
      Buffer.from(timestamp, 'utf8'),
      nonce,
    ]);

    // Sign with Ed25519
    const signature = sign(message, this.config.signingKeyPair.privateKey);

    // Construct authenticated registration payload
    const payload: RegisterPayload = {
      vault_id: this.config.vaultId,
      public_key: this.getPublicKey(),
      signing_public_key: this.getSigningPublicKey(),
      timestamp,
      nonce: nonce.toString('base64'),
      signature: signature.toString('base64'),
      pairing_token: this.config.pairingToken,
    };

    this.sendWsMessage({
      type: 'register',
      payload,
      timestamp: new Date().toISOString(),
    });
  }

  private handleDisconnect(reason: string): void {
    this.clearHeartbeat();
    this.ws = null;

    const wasConnected = this.state === 'connected';
    this.state = 'disconnected';

    if (wasConnected) {
      this.emit('disconnected', reason);
    }

    if (this.config.autoReconnect) {
      this.scheduleReconnect();
    }
  }

  // --------------------------------------------------------------------------
  // Reconnection with Exponential Backoff + Jitter
  // --------------------------------------------------------------------------

  private scheduleReconnect(): void {
    this.reconnectAttempt++;
    const delay = this.calculateBackoff();

    this.state = 'reconnecting';
    this.emit('reconnecting', this.reconnectAttempt, delay);

    if (this.config.debug) {
      console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempt})`);
    }

    this.reconnectTimeout = setTimeout(async () => {
      try {
        this.state = 'connecting';
        await this.doConnect();
      } catch (err) {
        if (this.config.debug) {
          console.error('Reconnect failed:', err);
        }
        this.emit('error', err instanceof Error ? err : new Error(String(err)));
        this.handleDisconnect('Reconnect failed');
      }
    }, delay);
  }

  /**
   * Calculate backoff delay with jitter
   * Formula: min(max, min * 2^attempt) + random jitter
   */
  private calculateBackoff(): number {
    const minDelay = this.config.reconnectMinMs ?? RECONNECT_MIN_MS;
    const maxDelay = this.config.reconnectMaxMs ?? RECONNECT_MAX_MS;

    // Exponential backoff
    const exponentialDelay = minDelay * Math.pow(2, this.reconnectAttempt - 1);
    const baseDelay = Math.min(exponentialDelay, maxDelay);

    // Add jitter (0-25% of base delay)
    const jitter = Math.random() * 0.25 * baseDelay;

    return Math.floor(baseDelay + jitter);
  }

  private clearReconnectTimeout(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
  }

  // --------------------------------------------------------------------------
  // Heartbeat
  // --------------------------------------------------------------------------

  private startHeartbeat(): void {
    this.clearHeartbeat();

    const interval = this.config.heartbeatIntervalMs ?? HEARTBEAT_INTERVAL_MS;

    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected()) {
        this.sendWsMessage({
          type: 'heartbeat',
          payload: {
            vault_id: this.config.vaultId,
            timestamp: new Date().toISOString(),
          },
          timestamp: new Date().toISOString(),
        });
      }
    }, interval);
  }

  private clearHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  // --------------------------------------------------------------------------
  // Message Handling
  // --------------------------------------------------------------------------

  private handleMessage(data: Buffer | string): void {
    try {
      const msg: WsMessage = JSON.parse(data.toString());

      switch (msg.type) {
        case 'request':
          this.handleRequest(msg.payload as RelayEnvelope);
          break;

        case 'ack':
          if (this.config.debug) {
            console.log('Received ack:', msg.payload);
          }
          break;

        case 'heartbeat':
          // Heartbeat ack received
          break;

        case 'error':
          const errPayload = msg.payload as { code: string; message: string };
          this.emit('error', new ClientError(
            errPayload.code as import('./types.js').ClientErrorCode,
            errPayload.message
          ));
          break;

        case 'pairing_claim':
          // Relay forwarding a VPS agent's pairing claim to the vault
          this.emit('pairingClaim', msg.payload as import('@dcprotocol/relay').StoredPairingClaim);
          break;

        case 'cloud_connect_redeem':
          // Relay asking the vault to redeem a Cloud-Connect link for an agent.
          this.emit('cloudConnectControl', { kind: 'redeem', ...(msg.payload as object) });
          break;

        case 'cloud_connect_status':
          // Relay asking the vault for an agent's approval status.
          this.emit('cloudConnectControl', { kind: 'status', ...(msg.payload as object) });
          break;

        default:
          if (this.config.debug) {
            console.log('Unknown message type:', msg.type);
          }
      }
    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to parse message:', err);
      }
    }
  }

  private async handleRequest(envelope: RelayEnvelope): Promise<void> {
    this.emit('request', envelope);

    if (!this.requestHandler) {
      if (this.config.debug) {
        console.log('No request handler set, ignoring request:', envelope.request_id);
      }
      return;
    }

    try {
      // Construct AAD from envelope for decryption verification
      const aad: EnvelopeAad = {
        version: envelope.version,
        vault_id: envelope.vault_id,
        request_id: envelope.request_id,
        action_type: envelope.action_type,
      };

      // Decrypt payload with AAD verification
      const decryptedPayload = await this.decryptPayload(envelope.encrypted_payload, aad);

      // Process request
      const responseData = await this.requestHandler(envelope.action_type, decryptedPayload);

      if (!responseData || !Buffer.isBuffer(responseData.payload) || !Buffer.isBuffer(responseData.recipientPublicKey)) {
        throw new Error('Request handler must return { payload: Buffer, recipientPublicKey: Buffer }');
      }

      // Encrypt response with AAD binding to the requester's public key
      // Note: Response uses same AAD to bind to original request
      const encryptedResponse = await encrypt(responseData.payload, responseData.recipientPublicKey, aad);

      // Send response
      const response: RelayResponseEnvelope = {
        version: RELAY_VERSION,
        request_id: envelope.request_id,
        encrypted_payload: encodeToBase64(encryptedResponse),
        timestamp: new Date().toISOString(),
      };

      this.sendWsMessage({
        type: 'response',
        payload: response,
        timestamp: new Date().toISOString(),
      });

    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to handle request:', err);
      }
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    }
  }

  // --------------------------------------------------------------------------
  // WebSocket Utilities
  // --------------------------------------------------------------------------

  private sendWsMessage(msg: WsMessage): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
      this.ws.send(JSON.stringify(msg));
      return true;
    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to send message:', err);
      }
      return false;
    }
  }
}

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Create a new relay client with authentication
 */
export function createRelayClient(
  relayUrl: string,
  vaultId: string,
  keyPair: HpkeKeyPair,
  signingKeyPair: SigningKeyPair,
  options: Partial<Omit<RelayClientConfig, 'relayUrl' | 'vaultId' | 'keyPair' | 'signingKeyPair'>> = {}
): RelayClient {
  return new RelayClient({
    relayUrl,
    vaultId,
    keyPair,
    signingKeyPair,
    ...options,
  });
}
