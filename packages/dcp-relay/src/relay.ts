/**
 * DCP Relay Server
 *
 * Encrypted message bus between cloud MCP clients and local vaults.
 *
 * From protocol spec Section 4.1:
 * - WebSocket primary; HTTP long-poll fallback
 * - Heartbeat every 30s
 * - Exponential backoff with jitter (1s → 60s)
 * - Message TTL: 5 minutes
 * - Idempotency by request_id
 *
 * SECURITY GUARANTEES:
 * - Relay never sees plaintext (only encrypted payload)
 * - No business logic metadata visible to relay
 * - No method names, amounts, recipients in envelopes
 */

import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { FastifyPluginCallback, FastifyPluginOptions, RouteShorthandOptions } from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyCors from '@fastify/cors';
import type { WebSocket } from 'ws';
import { ed25519 } from '@noble/curves/ed25519';
import type {
  RelayConfig,
  RelayEnvelope,
  RelayResponseEnvelope,
  WsMessage,
  RegisterPayload,
  HeartbeatPayload,
  LongPollRequest,
  LongPollResponse,
  PairingClaim,
  PairingClaimResponse,
  PairingApprovalStatus,
  StoredPairingClaim,
} from './types.js';
import {
  RelayError,
  DEFAULT_RELAY_CONFIG,
  RELAY_VERSION,
} from './types.js';
import { MessageStore, ConnectionStore, RateLimiter, PairingClaimStore } from './store.js';
import { authenticateRegistration, authenticateRequest, closeAuth, type AuthConfig } from './auth.js';

// ============================================================================
// Relay Server
// ============================================================================

export class RelayServer {
  private server: FastifyInstance;
  private messageStore: MessageStore;
  private connectionStore: ConnectionStore;
  private rateLimiter: RateLimiter;
  private pairingClaimStore: PairingClaimStore;
  private config: RelayConfig;
  private authConfig: AuthConfig;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private wsConnections: Map<string, WebSocket> = new Map();
  private clientSockets: Set<WebSocket> = new Set();
  private clientRequestMap: Map<string, WebSocket> = new Map();
  private clientRequestsBySocket: Map<WebSocket, Set<string>> = new Map();
  /** invite_id -> vault_id mapping (populated when vault registers) */
  private inviteVaultMap: Map<string, string> = new Map();

  constructor(config: Partial<RelayConfig> & { authConfig?: AuthConfig } = {}) {
    this.config = { ...DEFAULT_RELAY_CONFIG, ...config };
    this.authConfig = config.authConfig ?? { requirePairingToken: false };
    this.messageStore = new MessageStore(this.config);
    this.connectionStore = new ConnectionStore();
    this.rateLimiter = new RateLimiter(
      this.config.rateLimitPerMinute,
      this.config.rateLimitWindowMs
    );
    this.pairingClaimStore = new PairingClaimStore();

    this.server = Fastify({
      logger: this.config.debug
        ? {
            transport: {
              target: 'pino-pretty',
              options: { colorize: true },
            },
          }
        : false,
    });

    this.setupRoutes();
  }

  // --------------------------------------------------------------------------
  // Server Lifecycle
  // --------------------------------------------------------------------------

  async start(): Promise<void> {
    await this.server.register(
      fastifyCors as unknown as FastifyPluginCallback<FastifyPluginOptions>,
      { origin: true }
    );
    await this.server.register(
      fastifyWebsocket as unknown as FastifyPluginCallback<FastifyPluginOptions>
    );
    this.setupWebSocket();

    await this.server.listen({ port: this.config.port, host: this.config.host });

    // Start heartbeat checker
    this.startHeartbeatChecker();

    if (this.config.debug) {
      console.log(`DCP Relay listening on ${this.config.host}:${this.config.port}`);
    }
  }

  async stop(): Promise<void> {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    // Close all WebSocket connections
    for (const ws of this.wsConnections.values()) {
      ws.close(1000, 'Server shutting down');
    }
    this.wsConnections.clear();

    for (const ws of this.clientSockets) {
      ws.close(1000, 'Server shutting down');
    }
    this.clientSockets.clear();
    this.clientRequestMap.clear();
    this.clientRequestsBySocket.clear();

    this.messageStore.close();
    this.rateLimiter.close();
    this.pairingClaimStore.close();
    closeAuth();
    await this.server.close();
  }

  // --------------------------------------------------------------------------
  // HTTP Routes (REST + Long-Poll)
  // --------------------------------------------------------------------------

  private setupRoutes(): void {
    // Health check
    this.server.get('/health', async () => ({
      status: 'ok',
      version: RELAY_VERSION,
      timestamp: new Date().toISOString(),
    }));

    // Stats (for monitoring)
    this.server.get('/stats', async () => ({
      ...this.messageStore.getStats(),
      ...this.connectionStore.getStats(),
      rateLimit: this.rateLimiter.getStats(),
      pairingClaims: this.pairingClaimStore.getStats(),
      timestamp: new Date().toISOString(),
    }));

    // Detailed metrics endpoint (Prometheus-compatible format option)
    this.server.get<{ Querystring: { format?: string } }>(
      '/metrics',
      async (request, reply) => {
        const messageStats = this.messageStore.getStats();
        const connectionStats = this.connectionStore.getStats();
        const rateLimitStats = this.rateLimiter.getStats();
        const pairingStats = this.pairingClaimStore.getStats();

        const format = request.query.format;

        if (format === 'prometheus') {
          const lines = [
            '# HELP dcp_relay_messages_total Total messages in store',
            '# TYPE dcp_relay_messages_total gauge',
            `dcp_relay_messages_total ${messageStats.totalMessages}`,
            '# HELP dcp_relay_messages_pending Pending messages waiting for delivery',
            '# TYPE dcp_relay_messages_pending gauge',
            `dcp_relay_messages_pending ${messageStats.pendingMessages}`,
            '# HELP dcp_relay_messages_delivered Messages successfully delivered',
            '# TYPE dcp_relay_messages_delivered gauge',
            `dcp_relay_messages_delivered ${messageStats.deliveredMessages}`,
            '# HELP dcp_relay_vaults_connected Currently connected vaults',
            '# TYPE dcp_relay_vaults_connected gauge',
            `dcp_relay_vaults_connected ${connectionStats.connectedVaults}`,
            '# HELP dcp_relay_vaults_tracked Vaults tracked by rate limiter',
            '# TYPE dcp_relay_vaults_tracked gauge',
            `dcp_relay_vaults_tracked ${rateLimitStats.trackedVaults}`,
            '# HELP dcp_relay_rate_limit_max Max requests per window',
            '# TYPE dcp_relay_rate_limit_max gauge',
            `dcp_relay_rate_limit_max ${rateLimitStats.maxRequests}`,
            '# HELP dcp_relay_ws_clients Connected WebSocket clients',
            '# TYPE dcp_relay_ws_clients gauge',
            `dcp_relay_ws_clients ${this.clientSockets.size}`,
            '# HELP dcp_relay_pairing_claims_total Total pairing claims',
            '# TYPE dcp_relay_pairing_claims_total gauge',
            `dcp_relay_pairing_claims_total ${pairingStats.totalClaims}`,
            '# HELP dcp_relay_pairing_claims_pending Pending pairing claims',
            '# TYPE dcp_relay_pairing_claims_pending gauge',
            `dcp_relay_pairing_claims_pending ${pairingStats.pendingClaims}`,
            '',
          ];
          reply.header('Content-Type', 'text/plain; charset=utf-8');
          return lines.join('\n');
        }

        // Default JSON format
        return {
          messages: messageStats,
          connections: connectionStats,
          rateLimit: rateLimitStats,
          pairingClaims: pairingStats,
          websockets: {
            vaultConnections: this.wsConnections.size,
            clientConnections: this.clientSockets.size,
            pendingClientRequests: this.clientRequestMap.size,
          },
          config: {
            rateLimitPerMinute: this.config.rateLimitPerMinute,
            rateLimitWindowMs: this.config.rateLimitWindowMs,
            messageTtlMs: this.config.messageTtlMs,
            heartbeatIntervalMs: this.config.heartbeatIntervalMs,
          },
          uptime: process.uptime(),
          timestamp: new Date().toISOString(),
        };
      }
    );

    // Submit a request (client -> vault)
    this.server.post<{ Body: RelayEnvelope }>(
      '/relay/request',
      async (request, reply) => {
        return this.handleRequest(request.body, reply);
      }
    );

    // Get response (poll for response)
    this.server.get<{ Params: { requestId: string } }>(
      '/relay/response/:requestId',
      async (request, reply) => {
        return this.handleGetResponse(request.params.requestId, reply);
      }
    );

    // Long-poll for vault (vault polls for pending requests)
    if (this.config.enableLongPoll) {
      this.server.post<{ Body: LongPollRequest }>(
        '/relay/poll',
        async (request, reply) => {
          return this.handleLongPoll(request.body, reply);
        }
      );

      // Submit response (vault -> client)
      this.server.post<{ Body: RelayResponseEnvelope }>(
        '/relay/respond',
        async (request, reply) => {
          return this.handleRespond(request.body, reply);
        }
      );
    }

    // ========================================================================
    // Pairing Claim Routes (VPS → Relay → Vault flow)
    // ========================================================================

    // Submit a pairing claim (VPS agent → relay)
    this.server.post<{ Body: PairingClaim }>(
      '/v1/pairing-claims',
      async (request, reply) => {
        return this.handlePairingClaim(request.body, reply);
      }
    );

    // Poll for pairing approval status
    this.server.get<{ Params: { claimId: string } }>(
      '/v1/pairing-claims/:claimId/status',
      async (request, reply) => {
        return this.handlePairingStatus(request.params.claimId, reply);
      }
    );

    // Vault resolves a pairing claim (approve/deny)
    this.server.post<{
      Params: { claimId: string };
      Body: { action: 'approve' | 'deny'; agent_id?: string; vault_id: string };
    }>(
      '/v1/pairing-claims/:claimId/resolve',
      async (request, reply) => {
        return this.handlePairingResolve(
          request.params.claimId,
          request.body,
          reply
        );
      }
    );

    // Register an invite_id → vault_id mapping (called by vault on invite creation)
    this.server.post<{ Body: { invite_id: string; vault_id: string } }>(
      '/v1/invites/register',
      async (request, reply) => {
        const { invite_id, vault_id } = request.body;
        if (!invite_id || !vault_id) {
          return reply.status(400).send({ error: 'Missing invite_id or vault_id' });
        }
        this.inviteVaultMap.set(invite_id, vault_id);
        return reply.send({ success: true });
      }
    );
  }

  private async handleRequest(
    envelope: RelayEnvelope,
    reply: FastifyReply
  ): Promise<unknown> {
    // Validate envelope
    const validationError = this.validateEnvelope(envelope);
    if (validationError) {
      return reply.status(400).send(validationError.toJSON());
    }

    // Authenticate request (pairing token)
    try {
      const authHeader = reply.request.headers['authorization'];
      const tokenHeader = reply.request.headers['x-dcp-pairing-token'];
      const authToken = this.extractAuthToken(authHeader, tokenHeader);
      authenticateRequest(authToken, envelope.vault_id, this.authConfig);
    } catch (err) {
      if (err instanceof RelayError) {
        return reply.status(401).send(err.toJSON());
      }
      throw err;
    }

    // Check idempotency - if already exists, return cached response
    const existingResponse = this.messageStore.getResponse(envelope.request_id);
    if (existingResponse) {
      return reply.send(existingResponse);
    }

    // Rate limit check (protocol spec section C3: 60 req/min per vault)
    if (!this.rateLimiter.checkLimit(envelope.vault_id)) {
      const resetTime = this.rateLimiter.getResetTime(envelope.vault_id);
      reply.header('X-RateLimit-Limit', this.config.rateLimitPerMinute.toString());
      reply.header('X-RateLimit-Remaining', '0');
      reply.header('X-RateLimit-Reset', Math.ceil(resetTime / 1000).toString());
      reply.header('Retry-After', Math.ceil(resetTime / 1000).toString());

      return reply.status(429).send(
        new RelayError(
          'RELAY_RATE_LIMITED',
          `Rate limit exceeded for vault ${envelope.vault_id}. Try again in ${Math.ceil(resetTime / 1000)} seconds.`,
          {
            vault_id: envelope.vault_id,
            limit: this.config.rateLimitPerMinute,
            window_ms: this.config.rateLimitWindowMs,
            retry_after_ms: resetTime,
          }
        ).toJSON()
      );
    }

    // Add rate limit headers to successful responses
    reply.header('X-RateLimit-Limit', this.config.rateLimitPerMinute.toString());
    reply.header('X-RateLimit-Remaining', this.rateLimiter.getRemaining(envelope.vault_id).toString());

    // Check if vault is connected
    if (!this.connectionStore.isConnected(envelope.vault_id)) {
      return reply.status(503).send(
        new RelayError(
          'RELAY_VAULT_NOT_CONNECTED',
          `Vault ${envelope.vault_id} is not connected`
        ).toJSON()
      );
    }

    // Store message
    try {
      this.messageStore.storeMessage(envelope);
    } catch (err) {
      if (err instanceof RelayError) {
        return reply.status(409).send(err.toJSON());
      }
      throw err;
    }

    // Try to deliver via WebSocket
    const ws = this.wsConnections.get(envelope.vault_id);
    if (ws && ws.readyState === 1) { // WebSocket.OPEN
      const wsMsg: WsMessage = {
        type: 'request',
        payload: envelope,
        timestamp: new Date().toISOString(),
      };
      ws.send(JSON.stringify(wsMsg));
      this.messageStore.markDelivered(envelope.request_id);
    }

    return reply.status(202).send({
      queued: true,
      accepted: true,
      request_id: envelope.request_id,
      message: 'Request queued for delivery',
    });
  }

  private extractAuthToken(
    authHeader: string | string[] | undefined,
    tokenHeader: string | string[] | undefined
  ): string | undefined {
    const tokenValue = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;
    if (tokenValue && tokenValue.trim()) {
      return tokenValue.trim();
    }

    const authValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
    if (!authValue) {
      return undefined;
    }

    const match = authValue.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : undefined;
  }

  private async handleGetResponse(
    requestId: string,
    reply: FastifyReply
  ): Promise<unknown> {
    const response = this.messageStore.getResponse(requestId);
    if (response) {
      return reply.send(response);
    }

    // Check if request exists
    const message = this.messageStore.getMessage(requestId);
    if (!message) {
      return reply.status(404).send(
        new RelayError('RELAY_TIMEOUT', 'Request not found or expired').toJSON()
      );
    }

    // Request exists but no response yet
    return reply.status(202).send({
      pending: true,
      request_id: requestId,
      message: 'Response not yet available',
    });
  }

  private async handleLongPoll(
    req: LongPollRequest,
    reply: FastifyReply
  ): Promise<unknown> {
    const timeoutMs = Math.min(req.timeout_ms ?? 30000, 60000);
    const startTime = Date.now();

    // Poll loop
    while (Date.now() - startTime < timeoutMs) {
      const messages = this.messageStore.getPendingMessages(req.vault_id);
      if (messages.length > 0) {
        // Mark as delivered
        for (const msg of messages) {
          this.messageStore.markDelivered(msg.request_id);
        }

        const response: LongPollResponse = {
          messages,
          last_message_id: messages[messages.length - 1].request_id,
        };
        return reply.send(response);
      }

      // Wait a bit before polling again
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    // Timeout - return empty
    const response: LongPollResponse = {
      messages: [],
      last_message_id: req.last_message_id ?? '',
    };
    return reply.send(response);
  }

  private async handleRespond(
    response: RelayResponseEnvelope,
    reply: FastifyReply
  ): Promise<unknown> {
    const stored = this.messageStore.storeResponse(response.request_id, response);
    if (!stored) {
      return reply.status(404).send(
        new RelayError('RELAY_TIMEOUT', 'Original request not found or expired').toJSON()
      );
    }

    this.notifyClientResponse(response);

    return reply.send({ success: true, request_id: response.request_id });
  }

  // --------------------------------------------------------------------------
  // Pairing Claim Handlers
  // --------------------------------------------------------------------------

  /**
   * Handle pairing claim submission from VPS agent
   *
   * Flow:
   * 1. Receive claim from agent
   * 2. Look up vault_id from invite_id
   * 3. Store claim with verification phrase
   * 4. Push claim to connected vault via WebSocket (if connected)
   * 5. Return claim_id for polling
   */
  private async handlePairingClaim(
    claim: PairingClaim,
    reply: FastifyReply
  ): Promise<unknown> {
    // Validate required fields
    if (!claim.invite_id || !claim.agent_public_key || !claim.signature) {
      return reply.status(400).send({
        success: false,
        error: 'Missing required fields (invite_id, agent_public_key, signature)',
      } satisfies PairingClaimResponse);
    }

    // Check timestamp freshness (within 5 minutes)
    const now = Date.now();
    if (Math.abs(now - claim.timestamp) > 5 * 60 * 1000) {
      return reply.status(400).send({
        success: false,
        error: 'Claim timestamp too old or in the future',
      } satisfies PairingClaimResponse);
    }

    // Verify Ed25519 signature
    // The claim is signed over the canonical JSON of the payload (excluding signature)
    try {
      const payload: Record<string, unknown> = {
        invite_id: claim.invite_id,
        agent_public_key: claim.agent_public_key,
        agent_hostname: claim.agent_hostname,
        agent_version: claim.agent_version,
        timestamp: claim.timestamp,
        nonce: claim.nonce,
      };
      // Include vault_id if present (v2.0.1+ agents include it for self-routing)
      if (claim.vault_id) {
        payload.vault_id = claim.vault_id;
      }
      const canonical = JSON.stringify(payload, Object.keys(payload).sort());
      const message = Buffer.from(canonical, 'utf8');
      const signature = Buffer.from(claim.signature, 'base64');
      const publicKey = Buffer.from(claim.agent_public_key, 'base64');

      const isValid = ed25519.verify(signature, message, publicKey);
      if (!isValid) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid signature - claim not signed by the provided public key',
        } satisfies PairingClaimResponse);
      }
    } catch (err) {
      return reply.status(400).send({
        success: false,
        error: 'Failed to verify signature: ' + (err instanceof Error ? err.message : 'unknown error'),
      } satisfies PairingClaimResponse);
    }

    // Look up vault_id from invite_id, fallback to claim.vault_id (self-routing)
    // This ensures claims work even after relay restarts when inviteVaultMap is cleared
    const vaultId = this.inviteVaultMap.get(claim.invite_id) ?? claim.vault_id;

    // Store the claim
    const { claim_id, verification_phrase } = this.pairingClaimStore.storeClaim(
      claim,
      vaultId
    );

    // Push to connected vault via WebSocket
    if (vaultId) {
      const ws = this.wsConnections.get(vaultId);
      if (ws && ws.readyState === 1) {
        const storedClaim = this.pairingClaimStore.getClaim(claim_id);
        if (storedClaim) {
          const wsMsg: WsMessage = {
            type: 'pairing_claim',
            payload: storedClaim,
            timestamp: new Date().toISOString(),
          };
          ws.send(JSON.stringify(wsMsg));

          if (this.config.debug) {
            console.log(`Pushed pairing claim ${claim_id} to vault ${vaultId}`);
          }
        }
      }
    }

    if (this.config.debug) {
      console.log(
        `Pairing claim received: ${claim_id} (invite: ${claim.invite_id}, vault: ${vaultId ?? 'unknown'})`
      );
    }

    return reply.status(201).send({
      success: true,
      claim_id,
      verification_phrase,
    } satisfies PairingClaimResponse);
  }

  /**
   * Handle pairing status polling from agent
   */
  private async handlePairingStatus(
    claimId: string,
    reply: FastifyReply
  ): Promise<unknown> {
    const claim = this.pairingClaimStore.getClaim(claimId);

    if (!claim) {
      return reply.status(404).send({
        status: 'not_found',
        error: 'Claim not found or expired',
      } satisfies PairingApprovalStatus);
    }

    return reply.send({
      status: claim.status,
      agent_id: claim.agent_id,
      vault_id: claim.vault_id,
    } satisfies PairingApprovalStatus);
  }

  /**
   * Handle pairing resolution from vault (approve/deny)
   */
  private async handlePairingResolve(
    claimId: string,
    body: { action: 'approve' | 'deny'; agent_id?: string; vault_id: string },
    reply: FastifyReply
  ): Promise<unknown> {
    const { action, agent_id, vault_id } = body;

    const claim = this.pairingClaimStore.getClaim(claimId);
    if (!claim) {
      return reply.status(404).send({ error: 'Claim not found' });
    }

    // Verify vault_id matches
    if (claim.vault_id && claim.vault_id !== vault_id) {
      return reply.status(403).send({ error: 'Vault ID mismatch' });
    }

    // Update claim status
    const status = action === 'approve' ? 'approved' : 'denied';
    const updated = this.pairingClaimStore.updateClaimStatus(claimId, status, agent_id);

    if (!updated) {
      return reply.status(500).send({ error: 'Failed to update claim status' });
    }

    if (this.config.debug) {
      console.log(`Pairing claim ${claimId} ${status} by vault ${vault_id}`);
    }

    return reply.send({
      success: true,
      claim_id: claimId,
      status,
      agent_id,
    });
  }

  // --------------------------------------------------------------------------
  // WebSocket Handler
  // --------------------------------------------------------------------------

  private setupWebSocket(): void {
    const websocketRoute = { websocket: true } as RouteShorthandOptions & { websocket: true };

    this.server.get('/ws', websocketRoute, (socket, _req) => {
      const ws = socket as unknown as WebSocket;
      let vaultId: string | null = null;

      ws.on('message', (data: Buffer | string) => {
        try {
          const msg: WsMessage = JSON.parse(data.toString());
          this.handleWsMessage(ws, msg, (id) => {
            vaultId = id;
          });
        } catch (err) {
          this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', 'Invalid message format');
        }
      });

      ws.on('close', () => {
        if (vaultId) {
          this.connectionStore.unregister(vaultId);
          this.wsConnections.delete(vaultId);
          if (this.config.debug) {
            console.log(`Vault ${vaultId} disconnected`);
          }
        }
      });

      ws.on('error', (err) => {
        if (this.config.debug) {
          console.error('WebSocket error:', err);
        }
      });
    });

    // Client WebSocket endpoint (agents/services)
    this.server.get('/ws-client', websocketRoute, (socket, _req) => {
      const ws = socket as unknown as WebSocket;
      this.clientSockets.add(ws);

      ws.on('message', (data: Buffer | string) => {
        try {
          const msg: WsMessage = JSON.parse(data.toString());
          this.handleClientWsMessage(ws, msg);
        } catch {
          this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', 'Invalid message format');
        }
      });

      ws.on('close', () => {
        this.cleanupClientRequests(ws);
        this.clientSockets.delete(ws);
      });

      ws.on('error', (err) => {
        if (this.config.debug) {
          console.error('Client WebSocket error:', err);
        }
      });
    });
  }

  private handleWsMessage(
    ws: WebSocket,
    msg: WsMessage,
    setVaultId: (id: string) => void
  ): void {
    switch (msg.type) {
      case 'register': {
        const payload = msg.payload as RegisterPayload;

        // Validate required fields
        if (!payload.vault_id || !payload.public_key) {
          this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', 'Missing vault_id or public_key');
          return;
        }
        if (!payload.signing_public_key || !payload.timestamp || !payload.nonce || !payload.signature) {
          this.sendWsError(ws, 'RELAY_UNAUTHORIZED', 'Missing authentication fields (signing_public_key, timestamp, nonce, signature)');
          return;
        }

        // Authenticate registration (signature + optional token)
        try {
          authenticateRegistration(payload, this.authConfig);
        } catch (err) {
          if (err instanceof RelayError) {
            this.sendWsError(ws, err.code, err.message);
          } else {
            this.sendWsError(ws, 'RELAY_UNAUTHORIZED', 'Authentication failed');
          }
          return;
        }

        // Register vault (authenticated)
        this.connectionStore.register(payload.vault_id, payload.public_key, ws);
        this.wsConnections.set(payload.vault_id, ws);
        setVaultId(payload.vault_id);

        // Send ack
        const ack: WsMessage = {
          type: 'ack',
          payload: { vault_id: payload.vault_id, registered: true },
          timestamp: new Date().toISOString(),
        };
        ws.send(JSON.stringify(ack));

        // Send any pending messages
        const pending = this.messageStore.getPendingMessages(payload.vault_id);
        for (const envelope of pending) {
          const reqMsg: WsMessage = {
            type: 'request',
            payload: envelope,
            timestamp: new Date().toISOString(),
          };
          ws.send(JSON.stringify(reqMsg));
          this.messageStore.markDelivered(envelope.request_id);
        }

        // Send any pending pairing claims
        const pendingClaims = this.pairingClaimStore.getPendingClaimsForVault(payload.vault_id);
        for (const claim of pendingClaims) {
          const claimMsg: WsMessage = {
            type: 'pairing_claim',
            payload: claim,
            timestamp: new Date().toISOString(),
          };
          ws.send(JSON.stringify(claimMsg));
        }

        if (this.config.debug) {
          console.log(
            `Vault ${payload.vault_id} registered (authenticated) - ` +
            `${pending.length} pending messages, ${pendingClaims.length} pending claims`
          );
        }
        break;
      }

      case 'heartbeat': {
        const payload = msg.payload as HeartbeatPayload;
        if (payload.vault_id) {
          this.connectionStore.updateHeartbeat(payload.vault_id);
        }

        // Send heartbeat ack
        const ack: WsMessage = {
          type: 'heartbeat',
          payload: { timestamp: new Date().toISOString() },
          timestamp: new Date().toISOString(),
        };
        ws.send(JSON.stringify(ack));
        break;
      }

      case 'response': {
        const response = msg.payload as RelayResponseEnvelope;
        if (!response.request_id || !response.encrypted_payload) {
          this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', 'Invalid response envelope');
          return;
        }

        this.messageStore.storeResponse(response.request_id, response);
        this.notifyClientResponse(response);

        // Send ack
        const ack: WsMessage = {
          type: 'ack',
          payload: { request_id: response.request_id, stored: true },
          timestamp: new Date().toISOString(),
        };
        ws.send(JSON.stringify(ack));
        break;
      }

      case 'unregister': {
        const payload = msg.payload as { vault_id: string };
        if (payload.vault_id) {
          this.connectionStore.unregister(payload.vault_id);
          this.wsConnections.delete(payload.vault_id);
          setVaultId('');
        }
        break;
      }

      case 'pairing_result': {
        // Vault pushing pairing approval/denial result
        const payload = msg.payload as {
          claim_id: string;
          action: 'approve' | 'deny';
          agent_id?: string;
          vault_id: string;
        };

        if (!payload.claim_id || !payload.action || !payload.vault_id) {
          this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', 'Invalid pairing_result payload');
          return;
        }

        const status = payload.action === 'approve' ? 'approved' : 'denied';
        const updated = this.pairingClaimStore.updateClaimStatus(
          payload.claim_id,
          status,
          payload.agent_id
        );

        // Send ack
        const ack: WsMessage = {
          type: 'ack',
          payload: {
            claim_id: payload.claim_id,
            status: updated ? status : 'not_found',
          },
          timestamp: new Date().toISOString(),
        };
        ws.send(JSON.stringify(ack));

        if (this.config.debug && updated) {
          console.log(`Pairing claim ${payload.claim_id} ${status} via WebSocket`);
        }
        break;
      }

      default:
        this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', `Unknown message type: ${msg.type}`);
    }
  }

  private handleClientWsMessage(ws: WebSocket, msg: WsMessage): void {
    switch (msg.type) {
      case 'request': {
        const envelope = msg.payload as RelayEnvelope;
        this.handleClientRequest(ws, envelope);
        break;
      }

      case 'heartbeat': {
        const ack: WsMessage = {
          type: 'heartbeat',
          payload: { timestamp: new Date().toISOString() },
          timestamp: new Date().toISOString(),
        };
        this.sendWsMessage(ws, ack);
        break;
      }

      default:
        this.sendWsError(ws, 'RELAY_INVALID_ENVELOPE', `Unknown message type: ${msg.type}`);
    }
  }

  private handleClientRequest(ws: WebSocket, envelope: RelayEnvelope): void {
    const validationError = this.validateEnvelope(envelope);
    if (validationError) {
      this.sendWsError(ws, validationError.code, validationError.message, envelope.request_id);
      return;
    }

    // If response already exists, return it immediately
    const existingResponse = this.messageStore.getResponse(envelope.request_id);
    if (existingResponse) {
      const responseMsg: WsMessage = {
        type: 'response',
        payload: existingResponse,
        timestamp: new Date().toISOString(),
      };
      this.sendWsMessage(ws, responseMsg);
      return;
    }

    // If request already exists, just register this ws for the response
    if (this.messageStore.hasRequest(envelope.request_id)) {
      this.registerClientRequest(envelope.request_id, ws);
      this.sendWsMessage(ws, {
        type: 'ack',
        payload: { request_id: envelope.request_id, accepted: true },
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // Rate limit check (protocol spec section C3: 60 req/min per vault)
    if (!this.rateLimiter.checkLimit(envelope.vault_id)) {
      const resetTime = this.rateLimiter.getResetTime(envelope.vault_id);
      this.sendWsError(
        ws,
        'RELAY_RATE_LIMITED',
        `Rate limit exceeded for vault ${envelope.vault_id}. Try again in ${Math.ceil(resetTime / 1000)} seconds.`,
        envelope.request_id
      );
      return;
    }

    // Check if vault is connected
    if (!this.connectionStore.isConnected(envelope.vault_id)) {
      this.sendWsError(
        ws,
        'RELAY_VAULT_NOT_CONNECTED',
        `Vault ${envelope.vault_id} is not connected`,
        envelope.request_id
      );
      return;
    }

    // Store new message
    try {
      this.messageStore.storeMessage(envelope);
    } catch (err) {
      if (err instanceof RelayError) {
        this.sendWsError(ws, err.code, err.message, envelope.request_id);
        return;
      }
      this.sendWsError(ws, 'RELAY_UNAVAILABLE', 'Failed to store message', envelope.request_id);
      return;
    }

    this.registerClientRequest(envelope.request_id, ws);

    // Try to deliver via WebSocket to vault
    const vaultWs = this.wsConnections.get(envelope.vault_id);
    if (vaultWs && vaultWs.readyState === 1) {
      const wsMsg: WsMessage = {
        type: 'request',
        payload: envelope,
        timestamp: new Date().toISOString(),
      };
      vaultWs.send(JSON.stringify(wsMsg));
      this.messageStore.markDelivered(envelope.request_id);
    }

    this.sendWsMessage(ws, {
      type: 'ack',
      payload: { request_id: envelope.request_id, accepted: true },
      timestamp: new Date().toISOString(),
    });
  }

  private registerClientRequest(requestId: string, ws: WebSocket): void {
    this.clientRequestMap.set(requestId, ws);
    if (!this.clientRequestsBySocket.has(ws)) {
      this.clientRequestsBySocket.set(ws, new Set());
    }
    this.clientRequestsBySocket.get(ws)!.add(requestId);
  }

  private unregisterClientRequest(requestId: string): void {
    const ws = this.clientRequestMap.get(requestId);
    if (!ws) return;
    this.clientRequestMap.delete(requestId);
    const set = this.clientRequestsBySocket.get(ws);
    if (set) {
      set.delete(requestId);
      if (set.size === 0) {
        this.clientRequestsBySocket.delete(ws);
      }
    }
  }

  private cleanupClientRequests(ws: WebSocket): void {
    const set = this.clientRequestsBySocket.get(ws);
    if (!set) return;
    for (const requestId of set) {
      this.clientRequestMap.delete(requestId);
    }
    this.clientRequestsBySocket.delete(ws);
  }

  private notifyClientResponse(response: RelayResponseEnvelope): void {
    const ws = this.clientRequestMap.get(response.request_id);
    if (!ws) return;
    if (ws.readyState === 1) {
      const msg: WsMessage = {
        type: 'response',
        payload: response,
        timestamp: new Date().toISOString(),
      };
      this.sendWsMessage(ws, msg);
    }
    this.unregisterClientRequest(response.request_id);
  }

  private sendWsMessage(ws: WebSocket, msg: WsMessage): void {
    try {
      ws.send(JSON.stringify(msg));
    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to send WebSocket message:', err);
      }
    }
  }

  private sendWsError(
    ws: WebSocket,
    code: string,
    message: string,
    requestId?: string
  ): void {
    const errMsg: WsMessage = {
      type: 'error',
      payload: { code, message, request_id: requestId },
      timestamp: new Date().toISOString(),
    };
    this.sendWsMessage(ws, errMsg);
  }

  // --------------------------------------------------------------------------
  // Heartbeat Checker
  // --------------------------------------------------------------------------

  private startHeartbeatChecker(): void {
    this.heartbeatInterval = setInterval(() => {
      // Remove stale connections
      const stale = this.connectionStore.removeStale(this.config.heartbeatIntervalMs);
      for (const vaultId of stale) {
        const ws = this.wsConnections.get(vaultId);
        if (ws) {
          ws.close(1000, 'Heartbeat timeout');
          this.wsConnections.delete(vaultId);
        }
        if (this.config.debug) {
          console.log(`Vault ${vaultId} removed (heartbeat timeout)`);
        }
      }

      // Run message cleanup
      this.messageStore.cleanup();
    }, this.config.heartbeatIntervalMs);
  }

  // --------------------------------------------------------------------------
  // Validation
  // --------------------------------------------------------------------------

  private validateEnvelope(envelope: RelayEnvelope): RelayError | null {
    if (!envelope.version) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Missing version');
    }
    if (!envelope.vault_id) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Missing vault_id');
    }
    if (!envelope.request_id) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Missing request_id');
    }
    if (!envelope.action_type) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Missing action_type');
    }
    if (!['sign', 'read', 'write', 'budget'].includes(envelope.action_type)) {
      return new RelayError('RELAY_INVALID_ENVELOPE', `Invalid action_type: ${envelope.action_type}`);
    }
    if (!envelope.encrypted_payload) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Missing encrypted_payload');
    }
    if (!envelope.expires_at) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Missing expires_at');
    }

    // Check expiry
    const expiresAt = new Date(envelope.expires_at).getTime();
    if (isNaN(expiresAt)) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'Invalid expires_at format');
    }
    if (Date.now() > expiresAt) {
      return new RelayError('RELAY_MESSAGE_EXPIRED', 'Message has expired');
    }

    // Check TTL is reasonable (max 5 minutes as per the protocol spec)
    const ttl = expiresAt - Date.now();
    if (ttl > this.config.messageTtlMs) {
      return new RelayError('RELAY_INVALID_ENVELOPE', 'TTL too long (max 5 minutes)', {
        ttl_ms: ttl,
        max_ttl_ms: this.config.messageTtlMs,
      });
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // Getters (for testing)
  // --------------------------------------------------------------------------

  getMessageStore(): MessageStore {
    return this.messageStore;
  }

  getConnectionStore(): ConnectionStore {
    return this.connectionStore;
  }
}
