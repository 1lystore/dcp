#!/usr/bin/env node
/**
 * DCP Vault REST Server
 *
 * REST API for AI agents and browser UIs to interact with the vault.
 * SECURITY: Binds to 127.0.0.1 only - never exposed to network (PRD R1).
 *
 * Endpoints (PRD R2):
 * - GET  /health               - Health check
 * - GET  /scopes               - List available scopes
 * - GET  /address/:chain       - Get wallet address
 * - GET  /budget/check         - Check budget
 * - GET  /agents               - List active sessions
 * - GET  /consent              - List pending consents
 * - POST /consent/:id/approve  - Approve consent
 * - POST /consent/:id/deny     - Deny consent
 * - POST /revoke/:agent        - Revoke agent sessions
 *
 * v1 API Endpoints:
 * - POST /v1/vault/read        - Read data (with consent flow)
 * - POST /v1/vault/sign        - Sign transaction (with consent + budget)
 * - GET  /v1/vault/activity    - Get audit events
 * - POST /v1/vault/agents/:id/revoke - Revoke specific session
 */

import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import {
  VaultStorage,
  BudgetEngine,
  getStorage,
  getBudgetEngine,
  VaultError,
  Chain,
  AuditEventType,
  envelopeDecrypt,
  signTransaction,
} from '@dcprotocol/core';

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_PORT = 8420;
const HOST = '127.0.0.1'; // SECURITY: localhost only

// ============================================================================
// Server Setup
// ============================================================================

let storage: VaultStorage;
let budget: BudgetEngine;

async function buildServer(): Promise<FastifyInstance> {
  const server = Fastify({
    logger: {
      level: 'info',
      transport: {
        target: 'pino-pretty',
        options: {
          translateTime: 'HH:MM:ss',
          ignore: 'pid,hostname',
        },
      },
    },
  });

  // CORS for browser UI access
  await server.register(cors, {
    origin: true, // Allow all origins (localhost only anyway)
    methods: ['GET', 'POST', 'DELETE'],
  });

  // Initialize vault storage (respects VAULT_DIR env for testing)
  const vaultDir = process.env.VAULT_DIR;
  storage = getStorage(vaultDir);
  budget = getBudgetEngine(storage, vaultDir);

  // Error handler
  server.setErrorHandler((error: Error, request, reply) => {
    if (error instanceof VaultError) {
      reply.status(400).send(error.toJSON());
    } else {
      server.log.error(error);
      reply.status(500).send({
        error: {
          code: 'INTERNAL_ERROR',
          message: error.message,
        },
      });
    }
  });

  // ============================================================================
  // Health Check
  // ============================================================================

  server.get('/health', async () => {
    return {
      status: 'ok',
      unlocked: storage.isUnlocked(),
      version: '0.1.0',
    };
  });

  // ============================================================================
  // Scopes
  // ============================================================================

  server.get('/scopes', async () => {
    const records = storage.listRecords();

    return {
      scopes: records.map((r) => ({
        scope: r.scope,
        type: r.item_type,
        sensitivity: r.sensitivity,
        chain: r.chain,
        public_address: r.public_address,
      })),
    };
  });

  // ============================================================================
  // Address
  // ============================================================================

  server.get<{ Params: { chain: Chain } }>('/address/:chain', async (request, reply) => {
    const { chain } = request.params;

    const records = storage.listRecords();
    const wallet = records.find((r) => r.item_type === 'WALLET_KEY' && r.chain === chain);

    if (!wallet || !wallet.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    return {
      chain,
      address: wallet.public_address,
    };
  });

  // ============================================================================
  // Budget Check
  // ============================================================================

  server.get<{ Querystring: { amount: string; currency: string } }>(
    '/budget/check',
    async (request) => {
      const amount = parseFloat(request.query.amount);
      const currency = request.query.currency;

      if (isNaN(amount) || !currency) {
        throw new VaultError('INTERNAL_ERROR', 'amount and currency are required');
      }

      const limits = budget.getLimits(currency);
      const chain = getChainForCurrency(currency);
      const result = budget.checkBudget(amount, currency, chain);

      return {
        allowed: result.allowed,
        limits: {
          per_tx: limits.tx_limit,
          daily: limits.daily_budget,
          approval_threshold: limits.approval_threshold,
        },
        remaining: {
          daily: result.remaining_daily,
          per_tx: result.remaining_tx,
        },
        requires_approval: result.requires_approval,
        reason: result.reason,
      };
    }
  );

  // ============================================================================
  // Agents (Sessions)
  // ============================================================================

  server.get('/agents', async () => {
    const sessions = storage.listActiveSessions();

    return {
      agents: sessions.map((s) => ({
        id: s.id,
        agent_name: s.agent_name,
        granted_scopes: s.granted_scopes,
        consent_mode: s.consent_mode,
        expires_at: s.expires_at,
        created_at: s.created_at,
        last_used_at: s.last_used_at,
      })),
    };
  });

  // ============================================================================
  // Consent - List Pending
  // ============================================================================

  server.get('/consent', async () => {
    const pending = storage.getPendingConsents();

    return {
      pending: pending.map((c) => {
        let details: Record<string, unknown> = {};
        try {
          if (c.details) {
            details = JSON.parse(c.details);
          }
        } catch {
          // Ignore
        }

        return {
          id: c.id,
          agent_name: c.agent_name,
          action: c.action,
          scope: c.scope,
          details,
          status: c.status,
          created_at: c.created_at,
          expires_at: c.expires_at,
        };
      }),
    };
  });

  // ============================================================================
  // Consent - Approve
  // ============================================================================

  server.post<{ Params: { id: string }; Body: { session?: boolean } }>(
    '/consent/:id/approve',
    async (request) => {
      const { id } = request.params;
      const { session: createSession } = request.body || {};

      const consent = storage.getPendingConsent(id);

      if (!consent) {
        throw new VaultError('CONSENT_NOT_FOUND', `Consent not found: ${id}`);
      }

      if (consent.status !== 'pending') {
        throw new VaultError('INTERNAL_ERROR', `Consent already ${consent.status}`);
      }

      if (new Date(consent.expires_at) < new Date()) {
        storage.resolveConsent(id, 'expired');
        throw new VaultError('CONSENT_TIMEOUT', 'Consent has expired');
      }

      // Create session first if requested (need ID for resolveConsent)
      let sessionId: string | undefined;
      if (createSession) {
        const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000); // 4 hours max
        const newSession = storage.createSession(
          consent.agent_name,
          [consent.scope],
          'session',
          expiresAt
        );
        sessionId = newSession.id;
      }

      // Approve (with session_id if created)
      storage.resolveConsent(id, 'approved', sessionId);

      // Log to audit
      storage.logAudit('GRANT', 'success', {
        agentName: consent.agent_name,
        scope: consent.scope,
        operation: createSession ? 'session_grant' : 'once_grant',
        details: sessionId ? JSON.stringify({ session_id: sessionId }) : undefined,
      });

      return {
        approved: true,
        session_id: sessionId,
      };
    }
  );

  // ============================================================================
  // Consent - Deny
  // ============================================================================

  server.post<{ Params: { id: string } }>('/consent/:id/deny', async (request) => {
    const { id } = request.params;

    const consent = storage.getPendingConsent(id);

    if (!consent) {
      throw new VaultError('CONSENT_NOT_FOUND', `Consent not found: ${id}`);
    }

    if (consent.status !== 'pending') {
      throw new VaultError('INTERNAL_ERROR', `Consent already ${consent.status}`);
    }

    // Deny
    storage.resolveConsent(id, 'denied');

    // Log to audit
    storage.logAudit('DENY', 'denied', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: consent.action,
      details: 'Denied via REST API',
    });

    return {
      denied: true,
    };
  });

  // ============================================================================
  // Revoke Agent Sessions
  // ============================================================================

  server.post<{ Params: { agent: string } }>('/revoke/:agent', async (request) => {
    const { agent } = request.params;

    const count = storage.revokeAgentSessions(agent);

    if (count > 0) {
      storage.logAudit('REVOKE', 'success', {
        agentName: agent,
        operation: 'revoke_agent',
        details: JSON.stringify({ sessions_revoked: count }),
      });
    }

    return {
      revoked: count,
    };
  });

  // ============================================================================
  // V1 API: Vault Read (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/read', async (request) => {
    const { scope, agent_name, session_id, description } = request.body;

    if (!scope || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope and agent_name are required');
    }

    // Check if vault is unlocked
    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Check for valid session
    let hasSession = false;
    if (session_id) {
      const session = storage.getSession(session_id);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(scope) || session.granted_scopes.some(s => scope.startsWith(s.replace('.*', '')))) {
          hasSession = true;
          storage.touchSession(session_id);
        }
      }
    }

    // If no valid session, create pending consent
    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'read',
        scope,
        description ? JSON.stringify({ description }) : undefined
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    // Get the record
    const record = storage.getRecord(scope);
    if (!record) {
      throw new VaultError('RECORD_NOT_FOUND', `No record found for scope: ${scope}`);
    }

    // Decrypt if it's not a CRITICAL item
    if (record.sensitivity === 'critical') {
      // Don't return critical data - return reference only
      storage.logAudit('READ', 'success', {
        agentName: agent_name,
        scope,
        operation: 'read_reference',
      });

      return {
        scope,
        type: record.item_type,
        sensitivity: record.sensitivity,
        note: 'Critical data cannot be read directly. Use vault_sign_tx for signing operations.',
      };
    }

    // Decrypt and return
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(scope);
    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No encrypted data for scope: ${scope}`);
    }

    const decrypted = envelopeDecrypt(payload, masterKey);
    const data = JSON.parse(decrypted.toString('utf-8'));

    storage.logAudit('READ', 'success', {
      agentName: agent_name,
      scope,
      operation: 'read_data',
    });

    return {
      scope,
      data,
    };
  });

  // ============================================================================
  // V1 API: Vault Sign (with consent + budget)
  // ============================================================================

  server.post<{
    Body: {
      chain: Chain;
      unsigned_tx: string;
      amount?: number;
      currency?: string;
      agent_name: string;
      session_id?: string;
      description?: string;
      idempotency_key?: string;
    };
  }>('/v1/vault/sign', async (request) => {
    const { chain, unsigned_tx, amount, currency, agent_name, session_id, description, idempotency_key } = request.body;

    if (!chain || !unsigned_tx || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'chain, unsigned_tx, and agent_name are required');
    }

    // Check if vault is unlocked
    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Determine currency from chain if not provided
    const txCurrency = currency || (chain === 'solana' ? 'SOL' : chain === 'ethereum' ? 'ETH' : 'BASE_ETH');

    // Budget check if amount is provided
    if (amount !== undefined && amount > 0) {
      const budgetResult = budget.checkBudget(amount, txCurrency, chain);

      if (!budgetResult.allowed) {
        storage.logAudit('EXECUTE', 'denied', {
          agentName: agent_name,
          scope: `crypto.wallet.${chain === 'solana' ? 'sol' : chain}`,
          operation: 'sign_tx',
          details: JSON.stringify({ reason: budgetResult.reason, amount, currency: txCurrency }),
        });

        const errorCode = budgetResult.reason?.includes('BUDGET_EXCEEDED_TX')
          ? 'BUDGET_EXCEEDED_TX'
          : 'BUDGET_EXCEEDED_DAILY';

        throw new VaultError(errorCode, budgetResult.reason || 'Budget exceeded', {
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
        });
      }

      // If above approval threshold, always require consent
      if (budgetResult.requires_approval) {
        const consent = storage.createPendingConsent(
          agent_name,
          'sign_tx',
          `crypto.wallet.${chain === 'solana' ? 'sol' : chain}`,
          JSON.stringify({ description, amount, currency: txCurrency, chain })
        );

        return {
          requires_consent: true,
          consent_id: consent.id,
          expires_at: consent.expires_at,
          reason: 'Amount exceeds approval threshold',
          message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
        };
      }
    }

    // Get wallet scope
    const walletScope = `crypto.wallet.${chain === 'solana' ? 'sol' : chain}`;

    // Check for valid session
    let hasSession = false;
    if (session_id) {
      const session = storage.getSession(session_id);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(session_id);
        }
      }
    }

    // If no valid session, create pending consent
    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'sign_tx',
        walletScope,
        JSON.stringify({ description, amount, currency: txCurrency, chain })
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    // Get wallet and sign
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(walletScope);

    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    // Sign the transaction (signTransaction expects base64 string for Solana, JSON string for EVM)
    const signResult = await signTransaction(payload, masterKey, chain, unsigned_tx);

    // Record spend event if amount provided
    if (amount !== undefined && amount > 0 && session_id) {
      storage.recordSpend(session_id, amount, txCurrency, chain, 'sign_tx', 'committed', {
        idempotencyKey: idempotency_key,
      });
    }

    // Get updated budget info
    const budgetInfo = budget.checkBudget(0, txCurrency, chain);

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_tx',
      details: JSON.stringify({ chain, amount, currency: txCurrency }),
    });

    return {
      signed_tx: signResult.signed_tx,
      signature: signResult.signature,
      chain,
      remaining_daily: budgetInfo.remaining_daily,
    };
  });

  // ============================================================================
  // V1 API: Activity (Audit Events)
  // ============================================================================

  server.get<{
    Querystring: {
      limit?: string;
      agent?: string;
      type?: string;
      since?: string;
    };
  }>('/v1/vault/activity', async (request) => {
    const limit = parseInt(request.query.limit || '100', 10);
    const agentName = request.query.agent;
    const eventType = request.query.type?.toUpperCase() as AuditEventType | undefined;
    const since = request.query.since ? new Date(request.query.since) : undefined;

    // Validate event type
    if (eventType && !['GRANT', 'DENY', 'EXECUTE', 'READ', 'REVOKE', 'CONFIG', 'EXPIRE'].includes(eventType)) {
      throw new VaultError('INTERNAL_ERROR', `Invalid event type: ${request.query.type}`);
    }

    const events = storage.getAuditEvents(limit, {
      eventType,
      agentName,
      since,
    });

    return {
      events: events.map((e) => ({
        id: e.id,
        event_type: e.event_type,
        agent_name: e.agent_name,
        scope: e.scope,
        operation: e.operation,
        outcome: e.outcome,
        created_at: e.created_at,
        details: e.details ? (() => {
          try {
            return JSON.parse(e.details);
          } catch {
            return e.details;
          }
        })() : undefined,
      })),
      count: events.length,
    };
  });

  // ============================================================================
  // V1 API: Revoke Specific Session
  // ============================================================================

  server.post<{ Params: { id: string } }>('/v1/vault/agents/:id/revoke', async (request) => {
    const { id } = request.params;

    const session = storage.getSession(id);
    if (!session) {
      throw new VaultError('INTERNAL_ERROR', `Session not found: ${id}`);
    }

    const success = storage.revokeSession(id);

    if (success) {
      storage.logAudit('REVOKE', 'success', {
        agentName: session.agent_name,
        operation: 'revoke_session',
        details: JSON.stringify({ session_id: id }),
      });
    }

    return {
      revoked: success,
      session_id: id,
      agent_name: session.agent_name,
    };
  });

  return server;
}

// ============================================================================
// Helpers
// ============================================================================

function getChainForCurrency(currency: string): Chain {
  switch (currency.toUpperCase()) {
    case 'SOL':
      return 'solana';
    case 'ETH':
      return 'ethereum';
    case 'BASE_ETH':
      return 'base';
    default:
      return 'solana';
  }
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  const port = parseInt(process.env.VAULT_PORT || String(DEFAULT_PORT), 10);

  const server = await buildServer();

  try {
    await server.listen({ port, host: HOST });
    console.log(`\nDCP Vault REST Server running at http://${HOST}:${port}`);
    console.log('SECURITY: Bound to localhost only\n');
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down...');
  process.exit(0);
});

// Export for testing
export { buildServer };

// Start server if run directly
main();
