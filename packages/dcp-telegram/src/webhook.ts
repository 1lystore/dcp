/**
 * Webhook Server for DCP Telegram Service (Option B from protocol spec section 15)
 *
 * Cloud service that:
 * - Stores vault_id ↔ chat_id pairings
 * - Receives webhooks from ALL user desktops
 * - Sends notifications using ONE shared bot
 * - Handles pairing flow
 */

import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';
import { verify as cryptoVerify, createHmac, timingSafeEqual } from 'crypto';
import { canonicalJson, type TelegramConsentPayload } from '@dcprotocol/core';
import type { ApprovalAction, TelegramServiceConfig } from './types.js';
import { TelegramError, DEFAULT_SERVICE_CONFIG } from './types.js';
import { DcpTelegramBot } from './bot.js';
import { TelegramStore, NonceStore } from './store.js';

/**
 * Budget exceeded notification payload
 */
interface BudgetExceededPayload {
  agent_name: string;
  amount: number;
  currency: string;
  chain: string;
  error_code: 'BUDGET_EXCEEDED_TX' | 'BUDGET_EXCEEDED_DAILY';
  remaining_daily: number;
  remaining_tx: number;
  limit_daily: number;
  limit_tx: number;
  message: string;
}

/**
 * Consent webhook payload from desktop
 */
interface ConsentWebhookPayload {
  vault_id: string;
  event: 'consent_created' | 'test';
  data: TelegramConsentPayload;
  timestamp: string;
  nonce: string;
  signature: string;
}

/**
 * Budget webhook payload from desktop
 */
interface BudgetWebhookPayload {
  vault_id: string;
  event: 'budget_exceeded';
  data: BudgetExceededPayload;
  timestamp: string;
  nonce: string;
  signature: string;
}

/**
 * Webhook payload from desktop (simplified - no chat_id needed)
 * protocol spec: Every desktop-to-Telegram request must include:
 * vault ID, timestamp, nonce, signature
 */
type DesktopWebhookPayload = ConsentWebhookPayload | BudgetWebhookPayload;

/**
 * Pairing start request from desktop
 * protocol spec: Desktop creates signed pairing start request
 */
interface PairingStartRequest {
  vault_id: string;
  /** ISO timestamp for freshness check */
  timestamp: string;
  /** Unique nonce for replay protection */
  nonce: string;
  /** Ed25519 signature over vault_id, timestamp, nonce */
  signature: string;
}

interface ApprovalProcessedRequest {
  command_id: string;
  result: string;
  /** Vault whose command is being acknowledged (used to look up the signing key) */
  vault_id: string;
  /** ISO timestamp for freshness check */
  timestamp: string;
  /** Unique nonce for replay protection */
  nonce: string;
  /** Ed25519 signature over {vault_id, command_id, result, timestamp, nonce} */
  signature: string;
}

/** Vault key registration request (public_key required; signature required only to rotate an existing key) */
interface RegisterRequest {
  vault_id: string;
  public_key: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
}

/**
 * Verify Ed25519 signature using Node.js crypto
 */
export function verifyEd25519(
  message: Buffer,
  signature: Buffer,
  publicKey: Buffer
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }

  try {
    const spkiPrefix = Buffer.from([
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    const spkiKey = Buffer.concat([spkiPrefix, publicKey]);
    return cryptoVerify(null, message, { key: spkiKey, format: 'der', type: 'spki' }, signature);
  } catch {
    return false;
  }
}

/**
 * Validate Telegram webhook update signature
 *
 * protocol spec: Webhook Signature Validation
 *
 * When using Telegram webhooks (instead of polling), Telegram sends
 * a secret_token header (X-Telegram-Bot-Api-Secret-Token) that must
 * be validated to ensure the update came from Telegram's servers.
 *
 * CRITICAL: Uses timing-safe comparison to prevent timing attacks.
 *
 * @param body - The raw request body (string)
 * @param signature - The X-Telegram-Bot-Api-Secret-Token header value
 * @param secretToken - The secret_token you configured with setWebhook
 * @returns true if signature is valid, false otherwise
 */
export function validateTelegramUpdate(
  body: string,
  signature: string,
  secretToken: string
): boolean {
  // Missing signature must be rejected
  if (!signature) {
    return false;
  }

  // For Telegram webhook validation, the secret_token header
  // should match exactly what was configured in setWebhook
  // Use HMAC to create a verification hash
  const expected = createHmac('sha256', secretToken)
    .update(body)
    .digest('hex');

  try {
    // Timing-safe comparison to prevent timing attacks
    return timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    // Buffers of different lengths will throw
    return false;
  }
}

/**
 * Webhook server for receiving events from desktop apps
 */
export class WebhookServer {
  private server: FastifyInstance;
  private config: TelegramServiceConfig;
  private bot: DcpTelegramBot;
  private store: TelegramStore;
  private nonceStore: NonceStore;
  private vaultPublicKeys: Map<string, Buffer> = new Map();
  private isRunning = false;

  constructor(
    bot: DcpTelegramBot,
    store: TelegramStore,
    config: Partial<TelegramServiceConfig> = {}
  ) {
    this.config = { ...DEFAULT_SERVICE_CONFIG, ...config };
    this.bot = bot;
    this.store = store;
    this.nonceStore = new NonceStore();

    this.server = Fastify({
      logger: this.config.debug,
    });

    // HTTP-level rate limiting on every route (per client IP). The signed webhook /
    // approval / register routes verify Ed25519 vault signatures, so auth can't be
    // forged — this caps request volume to close the DoS surface (unbounded
    // signature-verify + DB lookups). Registered before routes so the global hook
    // applies to all of them. Tunable via DCP_TELEGRAM_RATE_LIMIT (per minute).
    const rateMax = parseInt(process.env.DCP_TELEGRAM_RATE_LIMIT || '', 10) || 240;
    void this.server.register(fastifyRateLimit, {
      global: true,
      max: rateMax,
      timeWindow: '1 minute',
    });

    // Load persisted vault keys from database into memory cache
    this.loadVaultKeys();

    this.setupRoutes();
  }

  /**
   * Load all vault keys from persistent storage into memory cache
   */
  private loadVaultKeys(): void {
    const keys = this.store.getAllVaultKeys();
    for (const { vault_id, public_key } of keys) {
      try {
        const keyBuffer = Buffer.from(public_key, 'base64');
        if (keyBuffer.length === 32) {
          this.vaultPublicKeys.set(vault_id, keyBuffer);
        }
      } catch {
        // Skip invalid keys
      }
    }
    if (keys.length > 0) {
      console.log(`[WEBHOOK] Loaded ${keys.length} vault keys from storage`);
    }
  }

  /**
   * Register a vault's public key for signature verification
   * Persists to database and caches in memory
   */
  registerVaultKey(vaultId: string, publicKey: string): void {
    const keyBuffer = Buffer.from(publicKey, 'base64');
    if (keyBuffer.length !== 32) {
      throw new TelegramError('WEBHOOK_VERIFICATION_FAILED', 'Invalid public key length');
    }
    // Persist to database
    this.store.registerVaultKey(vaultId, publicKey);
    // Cache in memory
    this.vaultPublicKeys.set(vaultId, keyBuffer);
  }

  /**
   * Get a vault's public key (from memory cache or database)
   */
  private getVaultPublicKey(vaultId: string): Buffer | null {
    // Check memory cache first
    const cached = this.vaultPublicKeys.get(vaultId);
    if (cached) return cached;

    // Try loading from database
    const storedKey = this.store.getVaultKey(vaultId);
    if (storedKey) {
      try {
        const keyBuffer = Buffer.from(storedKey, 'base64');
        if (keyBuffer.length === 32) {
          // Cache it for future use
          this.vaultPublicKeys.set(vaultId, keyBuffer);
          return keyBuffer;
        }
      } catch {
        // Invalid key format
      }
    }
    return null;
  }

  /**
   * Verify an Ed25519-signed request against a vault's registered key.
   *
   * Enforces the same gauntlet as the consent/budget webhooks: presence of
   * timestamp/nonce/signature, a known vault key, timestamp freshness + nonce
   * replay protection, and a valid signature over the canonical `signedData`.
   *
   * @returns an error descriptor to send back, or `null` when the request is authorized.
   */
  private verifySignedVaultRequest(
    vaultId: string,
    signedData: Record<string, unknown>,
    signature: string | undefined,
    timestamp: string | undefined,
    nonce: string | undefined
  ): { status: number; error: string; message: string } | null {
    if (!vaultId) {
      return { status: 400, error: 'INVALID_PAYLOAD', message: 'vault_id is required' };
    }
    if (!timestamp || !nonce || !signature) {
      return {
        status: 401,
        error: 'MISSING_SIGNATURE',
        message: 'timestamp, nonce, and signature are required',
      };
    }

    const publicKey = this.getVaultPublicKey(vaultId);
    if (!publicKey) {
      return {
        status: 401,
        error: 'UNKNOWN_VAULT_KEY',
        message: 'Vault public key not registered. Call /register first.',
      };
    }

    if (!this.nonceStore.checkAndMark(nonce, timestamp)) {
      return { status: 400, error: 'REPLAY_DETECTED', message: 'Stale timestamp or reused nonce' };
    }

    const message = Buffer.from(canonicalJson(signedData), 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');
    if (!verifyEd25519(message, signatureBuffer, publicKey)) {
      return { status: 401, error: 'INVALID_SIGNATURE', message: 'Signature verification failed' };
    }

    return null;
  }

  /**
   * Set up routes
   */
  private setupRoutes(): void {
    // Health check
    this.server.get('/health', async () => {
      return {
        status: 'ok',
        service: 'dcp-telegram-cloud',
        timestamp: new Date().toISOString(),
        stats: this.store.getStats(),
      };
    });

    // Stats endpoint
    this.server.get('/stats', async () => {
      return {
        stats: this.store.getStats(),
        bot: this.bot.getStats(),
      };
    });

    // === PAIRING ENDPOINTS ===

    // Desktop calls this to start pairing
    this.server.post<{ Body: PairingStartRequest }>(
      '/api/pair/start',
      async (request, reply) => {
        return this.handlePairingStart(request, reply);
      }
    );

    // Desktop polls this to check pairing status
    this.server.get<{ Params: { vaultId: string } }>(
      '/api/pair/status/:vaultId',
      async (request, reply) => {
        return this.handlePairingStatus(request, reply);
      }
    );

    // Desktop calls this to unlink
    this.server.delete<{ Params: { vaultId: string } }>(
      '/api/pair/:vaultId',
      async (request, reply) => {
        return this.handleUnlink(request, reply);
      }
    );

    // === REMOTE APPROVAL ENDPOINTS ===

    this.server.get<{ Params: { vaultId: string } }>(
      '/api/approvals/:vaultId',
      async (request, reply) => {
        return this.handlePendingApprovals(request, reply);
      }
    );

    this.server.post<{ Body: ApprovalProcessedRequest }>(
      '/api/approvals/processed',
      async (request, reply) => {
        return this.handleApprovalProcessed(request, reply);
      }
    );

    // === WEBHOOK ENDPOINTS ===

    // Consent webhook from desktop (no chat_id needed - we look it up)
    this.server.post<{ Body: ConsentWebhookPayload }>(
      '/webhook/consent',
      async (request, reply) => {
        return this.handleConsentWebhook(request, reply);
      }
    );

    // Budget exceeded webhook from desktop
    this.server.post<{ Body: BudgetWebhookPayload }>(
      '/webhook/budget',
      async (request, reply) => {
        return this.handleBudgetWebhook(request, reply);
      }
    );

    // Register vault public key
    this.server.post<{ Body: { vault_id: string; public_key: string } }>(
      '/register',
      async (request, reply) => {
        return this.handleRegister(request, reply);
      }
    );
  }

  /**
   * Handle pairing start (desktop → cloud)
   * Returns a 6-digit code for user to send to bot
   *
   * protocol spec: Desktop creates signed pairing start request,
   * service verifies vault signature
   */
  private async handlePairingStart(
    request: FastifyRequest<{ Body: PairingStartRequest }>,
    reply: FastifyReply
  ) {
    const { vault_id, timestamp, nonce, signature } = request.body;

    // Validate required fields
    if (!vault_id) {
      return reply.status(400).send({
        error: 'INVALID_PAYLOAD',
        message: 'vault_id is required',
      });
    }

    // protocol spec: Require signature, timestamp, nonce
    if (!timestamp || !nonce || !signature) {
      return reply.status(400).send({
        error: 'INVALID_PAYLOAD',
        message: 'timestamp, nonce, and signature are required',
      });
    }

    // Check for registered vault key (checks memory cache and database)
    const publicKey = this.getVaultPublicKey(vault_id);
    if (!publicKey) {
      return reply.status(401).send({
        error: 'UNKNOWN_VAULT_KEY',
        message: 'Vault public key not registered. Call /register first.',
      });
    }

    // Check timestamp freshness and nonce replay
    if (!this.nonceStore.checkAndMark(nonce, timestamp)) {
      return reply.status(400).send({
        error: 'REPLAY_DETECTED',
        message: 'Stale timestamp or reused nonce',
      });
    }

    // Verify signature over vault_id + timestamp + nonce
    const messageData = { vault_id, timestamp, nonce };
    const message = Buffer.from(canonicalJson(messageData), 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');
    if (!verifyEd25519(message, signatureBuffer, publicKey)) {
      return reply.status(401).send({
        error: 'INVALID_SIGNATURE',
        message: 'Signature verification failed',
      });
    }

    // Generate pairing code (CSPRNG per the protocol spec)
    const pending = this.store.pairings.createPairingCode(vault_id);

    console.log(`[PAIRING] Code created for vault ${vault_id.slice(0, 8)}...`);

    return reply.send({
      code: pending.code,
      expires_at: pending.expires_at,
      instructions: `Send this code to the DCP Telegram bot: ${pending.code}`,
    });
  }

  /**
   * Handle pairing status check (desktop polling)
   */
  private async handlePairingStatus(
    request: FastifyRequest<{ Params: { vaultId: string } }>,
    reply: FastifyReply
  ) {
    const { vaultId } = request.params;

    const pairing = this.store.pairings.getPairingByVaultId(vaultId);

    if (pairing) {
      return reply.send({
        paired: true,
        chat_id: pairing.chat_id,
        paired_at: pairing.paired_at,
        enabled: pairing.enabled,
      });
    }

    return reply.send({
      paired: false,
    });
  }

  /**
   * Handle unlink request (desktop → cloud)
   * Deletes the pairing for the given vault
   */
  private async handleUnlink(
    request: FastifyRequest<{ Params: { vaultId: string } }>,
    reply: FastifyReply
  ) {
    const { vaultId } = request.params;

    // Require the vault's signature — otherwise anyone who knows a vault_id could
    // unlink someone else's Telegram pairing (griefing / notification DoS).
    const timestamp = request.headers['x-dcp-timestamp'] as string | undefined;
    const nonce = request.headers['x-dcp-nonce'] as string | undefined;
    const signature = request.headers['x-dcp-signature'] as string | undefined;
    const authError = this.verifySignedVaultRequest(
      vaultId,
      { vault_id: vaultId, timestamp, nonce },
      signature,
      timestamp,
      nonce
    );
    if (authError) {
      return reply.status(authError.status).send({ error: authError.error, message: authError.message });
    }

    const deleted = this.store.pairings.deletePairing(vaultId);

    console.log(`[UNLINK] Vault ${vaultId} unlinked: ${deleted}`);

    return reply.send({
      success: deleted,
    });
  }

  private async handlePendingApprovals(
    request: FastifyRequest<{ Params: { vaultId: string } }>,
    reply: FastifyReply
  ) {
    const { vaultId } = request.params;

    // Require an Ed25519 signature from the vault's registered key. Only the
    // desktop that owns this vault may enumerate its pending approvals.
    const timestamp = request.headers['x-dcp-timestamp'] as string | undefined;
    const nonce = request.headers['x-dcp-nonce'] as string | undefined;
    const signature = request.headers['x-dcp-signature'] as string | undefined;
    const authError = this.verifySignedVaultRequest(
      vaultId,
      { vault_id: vaultId, timestamp, nonce },
      signature,
      timestamp,
      nonce
    );
    if (authError) {
      return reply.status(authError.status).send({ error: authError.error, message: authError.message });
    }

    const pairing = this.store.pairings.getPairingByVaultId(vaultId);

    if (!pairing) {
      return reply.status(404).send({
        error: 'NOT_PAIRED',
        message: 'Vault is not paired with Telegram.',
      });
    }

    if (!pairing.enabled) {
      return reply.status(403).send({
        error: 'DISABLED',
        message: 'Telegram notifications are disabled for this vault.',
      });
    }

    const commands = this.store.approvals.getPendingApprovals(vaultId).map((command) => ({
      id: command.id,
      consent_id: command.consent_id,
      action: command.action,
      created_at: command.created_at,
    }));

    if (commands.length > 0) {
      console.log(
        `[APPROVAL] Returning ${commands.length} pending command(s) for vault ${vaultId}: ${commands.map((command) => command.id).join(', ')}`
      );
    }

    return reply.send({ commands });
  }

  private async handleApprovalProcessed(
    request: FastifyRequest<{ Body: ApprovalProcessedRequest }>,
    reply: FastifyReply
  ) {
    const { command_id, result, vault_id, timestamp, nonce, signature } = request.body || {};

    if (!command_id || !result || !vault_id) {
      return reply.status(400).send({
        error: 'INVALID_PAYLOAD',
        message: 'command_id, result, and vault_id are required',
      });
    }

    // Require an Ed25519 signature from the vault's registered key over the exact
    // command being acknowledged — prevents anyone from forging "processed"
    // notifications or spoofing arbitrary result text into the user's Telegram.
    const authError = this.verifySignedVaultRequest(
      vault_id,
      { vault_id, command_id, result, timestamp, nonce },
      signature,
      timestamp,
      nonce
    );
    if (authError) {
      return reply.status(authError.status).send({ error: authError.error, message: authError.message });
    }

    // Authorization: the command must belong to the vault that signed the request,
    // so a valid signature for vault A cannot process vault B's command.
    const existing = this.store.approvals.getApprovalCommand(command_id);
    if (!existing || existing.vault_id !== vault_id) {
      return reply.status(404).send({
        error: 'COMMAND_NOT_FOUND',
        message: 'Approval command not found',
      });
    }

    const command = this.store.approvals.markApprovalProcessed(command_id, result);
    if (!command) {
      console.warn(`[APPROVAL] Processed callback for missing command ${command_id}`);
      return reply.status(404).send({
        error: 'COMMAND_NOT_FOUND',
        message: 'Approval command not found',
      });
    }

    console.log(
      `[APPROVAL] Processed command ${command.id} for vault ${command.vault_id}, consent ${command.consent_id}: ${result}`
    );

    const notification = await this.bot.sendApprovalProcessedNotification(
      command.chat_id,
      command.consent_id,
      command.action as ApprovalAction,
      result
    );
    if (!notification.success) {
      console.warn(
        `[APPROVAL] Processed notification failed for command ${command.id}: ${notification.error || 'unknown error'}`
      );
    }

    return reply.send({
      processed: true,
      command_id,
      result,
    });
  }

  /**
   * Handle consent webhook from desktop
   * Looks up chat_id from vault_id (no chat_id in payload)
   *
   * protocol spec: Telegram service must reject:
   * - missing signature
   * - invalid signature
   * - unknown vault key
   * - stale timestamp
   * - reused nonce
   */
  private async handleConsentWebhook(
    request: FastifyRequest<{ Body: ConsentWebhookPayload }>,
    reply: FastifyReply
  ) {
    const payload = request.body;

    // Validate required fields including security fields (protocol spec)
    if (!payload.vault_id || !payload.event || !payload.data || !payload.timestamp) {
      return reply.status(400).send({
        error: 'INVALID_PAYLOAD',
        message: 'Missing required fields: vault_id, event, data, timestamp',
      });
    }

    // protocol spec: Reject missing nonce
    if (!payload.nonce) {
      return reply.status(400).send({
        error: 'MISSING_NONCE',
        message: 'Nonce is required for replay protection',
      });
    }

    // protocol spec: Reject missing signature
    if (!payload.signature) {
      return reply.status(400).send({
        error: 'MISSING_SIGNATURE',
        message: 'Signature is required',
      });
    }

    // protocol spec: Reject unknown vault key (checks memory cache and database)
    const publicKey = this.getVaultPublicKey(payload.vault_id);
    if (!publicKey) {
      return reply.status(401).send({
        error: 'UNKNOWN_VAULT_KEY',
        message: 'Vault public key not registered. Call /register first.',
      });
    }

    // protocol spec: Reject stale timestamp and reused nonce
    if (!this.nonceStore.checkAndMark(payload.nonce, payload.timestamp)) {
      return reply.status(400).send({
        error: 'REPLAY_DETECTED',
        message: 'Stale timestamp or reused nonce',
      });
    }

    // protocol spec: Verify signature (REQUIRED, not optional)
    const { signature, ...dataToVerify } = payload;
    const message = Buffer.from(canonicalJson(dataToVerify), 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');
    if (!verifyEd25519(message, signatureBuffer, publicKey)) {
      return reply.status(401).send({
        error: 'INVALID_SIGNATURE',
        message: 'Signature verification failed',
      });
    }

    // Look up pairing for this vault (after security checks pass)
    const pairing = this.store.pairings.getPairingByVaultId(payload.vault_id);

    if (!pairing) {
      return reply.status(404).send({
        error: 'NOT_PAIRED',
        message: 'Vault is not paired with Telegram. User needs to pair first.',
      });
    }

    if (!pairing.enabled) {
      return reply.status(403).send({
        error: 'DISABLED',
        message: 'Telegram notifications are disabled for this vault',
      });
    }

    // Check if muted
    if (this.store.pairings.isMuted(payload.vault_id)) {
      return reply.send({
        sent: false,
        reason: 'muted',
        consent_id: payload.data.consent_id,
      });
    }

    // Check rate limit
    if (this.store.rateLimiter.isLimited(pairing.chat_id)) {
      return reply.status(429).send({
        error: 'RATE_LIMITED',
        message: 'Too many notifications. Please wait.',
        reset_in: this.store.rateLimiter.getResetTime(pairing.chat_id),
      });
    }

    // Check deduplication
    if (this.store.deduplication.isDuplicate(payload.data.consent_id)) {
      return reply.send({
        sent: false,
        reason: 'duplicate',
        consent_id: payload.data.consent_id,
      });
    }

    // Handle event
    switch (payload.event) {
      case 'consent_created':
        return this.handleConsentCreated(payload.vault_id, pairing.chat_id, payload.data, reply);

      case 'test':
        return this.handleTestEvent(pairing.chat_id, reply);

      default:
        return reply.status(400).send({
          error: 'UNKNOWN_EVENT',
          message: `Unknown event type: ${payload.event}`,
        });
    }
  }

  /**
   * Handle consent_created event
   */
  private async handleConsentCreated(
    vaultId: string,
    chatId: string,
    data: TelegramConsentPayload,
    reply: FastifyReply
  ) {
    // Send notification
    const result = await this.bot.sendConsentNotification(chatId, data);

    if (!result.success) {
      return reply.status(500).send({
        error: 'SEND_FAILED',
        message: result.error || 'Failed to send notification',
        consent_id: data.consent_id,
      });
    }

    // Record success
    this.store.rateLimiter.record(chatId);
    this.store.deduplication.markSeen(data.consent_id);
    this.store.pairings.recordNotification(vaultId);

    console.log(`[WEBHOOK] Sent notification for consent ${data.consent_id} to chat ${chatId}`);

    return reply.send({
      sent: true,
      consent_id: data.consent_id,
      message_id: result.messageId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle test event
   */
  private async handleTestEvent(chatId: string, reply: FastifyReply) {
    const result = await this.bot.sendTestNotification(chatId);

    if (!result.success) {
      return reply.status(500).send({
        error: 'SEND_FAILED',
        message: result.error || 'Failed to send test notification',
      });
    }

    return reply.send({
      sent: true,
      event: 'test',
      message_id: result.messageId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle budget exceeded webhook from desktop
   * Notifies admin when daily/tx budget is exceeded
   */
  private async handleBudgetWebhook(
    request: FastifyRequest<{ Body: BudgetWebhookPayload }>,
    reply: FastifyReply
  ) {
    const payload = request.body;

    // Validate required fields including security fields
    if (!payload.vault_id || !payload.event || !payload.data || !payload.timestamp) {
      return reply.status(400).send({
        error: 'INVALID_PAYLOAD',
        message: 'Missing required fields: vault_id, event, data, timestamp',
      });
    }

    // Reject missing nonce
    if (!payload.nonce) {
      return reply.status(400).send({
        error: 'MISSING_NONCE',
        message: 'Nonce is required for replay protection',
      });
    }

    // Reject missing signature
    if (!payload.signature) {
      return reply.status(400).send({
        error: 'MISSING_SIGNATURE',
        message: 'Signature is required',
      });
    }

    // Reject unknown vault key
    const publicKey = this.getVaultPublicKey(payload.vault_id);
    if (!publicKey) {
      return reply.status(401).send({
        error: 'UNKNOWN_VAULT_KEY',
        message: 'Vault public key not registered. Call /register first.',
      });
    }

    // Reject stale timestamp and reused nonce
    if (!this.nonceStore.checkAndMark(payload.nonce, payload.timestamp)) {
      return reply.status(400).send({
        error: 'REPLAY_DETECTED',
        message: 'Stale timestamp or reused nonce',
      });
    }

    // Verify signature
    const { signature, ...dataToVerify } = payload;
    const message = Buffer.from(canonicalJson(dataToVerify), 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');
    if (!verifyEd25519(message, signatureBuffer, publicKey)) {
      return reply.status(401).send({
        error: 'INVALID_SIGNATURE',
        message: 'Signature verification failed',
      });
    }

    // Look up pairing for this vault
    const pairing = this.store.pairings.getPairingByVaultId(payload.vault_id);

    if (!pairing) {
      return reply.status(404).send({
        error: 'NOT_PAIRED',
        message: 'Vault is not paired with Telegram. User needs to pair first.',
      });
    }

    if (!pairing.enabled) {
      return reply.status(403).send({
        error: 'DISABLED',
        message: 'Telegram notifications are disabled for this vault',
      });
    }

    // Check rate limit
    if (this.store.rateLimiter.isLimited(pairing.chat_id)) {
      return reply.status(429).send({
        error: 'RATE_LIMITED',
        message: 'Too many notifications. Please wait.',
        reset_in: this.store.rateLimiter.getResetTime(pairing.chat_id),
      });
    }

    // Send budget exceeded notification
    const result = await this.bot.sendBudgetExceededNotification(pairing.chat_id, payload.data);

    if (!result.success) {
      return reply.status(500).send({
        error: 'SEND_FAILED',
        message: result.error || 'Failed to send notification',
      });
    }

    // Record success
    this.store.rateLimiter.record(pairing.chat_id);
    this.store.pairings.recordNotification(payload.vault_id);

    console.log(`[WEBHOOK] Sent budget exceeded notification to chat ${pairing.chat_id}`);

    return reply.send({
      sent: true,
      event: 'budget_exceeded',
      message_id: result.messageId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle vault key registration
   */
  private async handleRegister(
    request: FastifyRequest<{ Body: RegisterRequest }>,
    reply: FastifyReply
  ) {
    const { vault_id, public_key, timestamp, nonce, signature } = request.body;

    if (!vault_id || !public_key) {
      return reply.status(400).send({
        error: 'INVALID_PAYLOAD',
        message: 'vault_id and public_key are required',
      });
    }

    // Trust-anchor protection: the first key registered for a vault wins (TOFU),
    // and idempotent re-registration of the SAME key is always allowed. Replacing
    // an existing key with a DIFFERENT one is a rotation that must be signed by the
    // currently-registered key — otherwise anyone who knows a vault_id could
    // overwrite its trust anchor and forge every downstream webhook.
    const existing = this.store.getVaultKey(vault_id);
    if (existing && existing !== public_key) {
      const authError = this.verifySignedVaultRequest(
        vault_id,
        { vault_id, public_key, timestamp, nonce },
        signature,
        timestamp,
        nonce
      );
      if (authError) {
        // A rotation attempt without a valid signature from the existing key is a
        // takeover attempt — surface it distinctly from a first-time registration.
        return reply.status(authError.status === 401 ? 403 : authError.status).send({
          error: authError.error === 'MISSING_SIGNATURE' ? 'KEY_ALREADY_REGISTERED' : authError.error,
          message:
            authError.error === 'MISSING_SIGNATURE'
              ? 'A different key is already registered for this vault; rotation must be signed by the existing key'
              : authError.message,
        });
      }
    }

    try {
      this.registerVaultKey(vault_id, public_key);
      return reply.send({
        registered: true,
        vault_id,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      return reply.status(400).send({
        error: 'INVALID_KEY',
        message: err instanceof Error ? err.message : 'Invalid public key',
      });
    }
  }

  /**
   * Start the webhook server
   */
  async start(): Promise<void> {
    if (this.isRunning) return;

    await this.server.listen({
      port: this.config.port,
      host: this.config.host,
    });

    this.isRunning = true;
    console.log(`[WEBHOOK] Server listening on ${this.config.host}:${this.config.port}`);
  }

  /**
   * Stop the webhook server
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;

    await this.server.close();
    this.nonceStore.close();
    this.isRunning = false;
    console.log('[WEBHOOK] Server stopped');
  }

  /**
   * Get the Fastify instance for testing
   */
  getServer(): FastifyInstance {
    return this.server;
  }
}
