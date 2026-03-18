/**
 * MCP Tools for DCP Vault
 *
 * Implements the MCP tools from PRD Section 3.1.3:
 * - vault_list_scopes() - List available scopes (no consent)
 * - vault_get_address(chain) - Get public address (no consent)
 * - vault_budget_check(amount, currency) - Check budget (no consent)
 * - vault_read(scope, fields?) - Read data (consent required)
 * - vault_sign_tx(chain, unsigned_tx, description?) - Sign transaction (consent required)
 * - vault_sign_message(chain, message, encoding?) - Sign message (consent required)
 * - vault_sign_typed_data(chain, typed_data) - Sign typed data (consent required)
 * - vault_sign_x402(network, payload, ...) - Sign x402 payload (consent required)
 */

import {
  VaultStorage,
  BudgetEngine,
  VaultError,
  Chain,
  signTransaction,
  signSolanaMessage,
  signEvmMessage,
  signEvmTypedData,
  envelopeDecrypt,
} from '@dcprotocol/core';

import {
  ListScopesOutput,
  GetAddressInput,
  GetAddressOutput,
  BudgetCheckInput,
  BudgetCheckOutput,
  ReadInput,
  ReadOutput,
  SignTxInput,
  SignTxOutput,
  SignMessageInput,
  SignMessageOutput,
  SignTypedDataInput,
  SignTypedDataOutput,
  SignX402Input,
  SignX402Output,
  WriteInput,
  WriteOutput,
  ScopeInfo,
  UnlockInput,
  UnlockOutput,
 LockOutput,
} from './types.js';

import {
  requestConsent,
  requiresMandatoryApproval,
  hasSessionScope,
  touchSession,
  getActiveAgentSessionId,
  isTTY,
  createPendingConsent,
  APPROVAL_URL,
} from './consent.js';

// ============================================================================
// Tool Context
// ============================================================================

export interface ToolContext {
  storage: VaultStorage;
  budget: BudgetEngine;
  agentName: string;
  sessionId?: string;
}

// ============================================================================
// Helper: Get Master Key Safely
// ============================================================================

/**
 * Get master key, throwing VAULT_LOCKED if not available
 */
function getMasterKeySafe(storage: VaultStorage): Buffer {
  if (!storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
  }
  return storage.getMasterKey();
}

// ============================================================================
// vault_unlock / vault_lock - Local only
// ============================================================================

/**
 * Unlock vault for this MCP process
 *
 * Consent: No (local user action)
 */
export async function vault_unlock(
  ctx: ToolContext,
  input: UnlockInput
): Promise<UnlockOutput> {
  if (!input.passphrase) {
    throw new VaultError('INTERNAL_ERROR', 'passphrase is required');
  }
  await ctx.storage.unlock(input.passphrase);
  return { unlocked: true };
}

/**
 * Lock vault for this MCP process
 *
 * Consent: No (local user action)
 */
export async function vault_lock(ctx: ToolContext): Promise<LockOutput> {
  ctx.storage.lock();
  return { locked: true };
}

// ============================================================================
// vault_list_scopes - No consent required
// ============================================================================

/**
 * List all available scopes in the vault
 *
 * PRD: Returns array of scopes, types, sensitivity levels, operations
 * Consent: No
 */
export async function vault_list_scopes(ctx: ToolContext): Promise<ListScopesOutput> {
  const records = ctx.storage.listRecords();

  const scopes: ScopeInfo[] = records.map((record) => {
    const info: ScopeInfo = {
      scope: record.scope,
      type: record.item_type,
      sensitivity: record.sensitivity,
      operations: getOperationsForType(record.item_type, record.sensitivity),
    };

    // Add chain and address for wallets
    if (record.chain) {
      info.chain = record.chain;
    }
    if (record.public_address) {
      info.public_address = record.public_address;
    }

    return info;
  });

  // Log to audit
  ctx.storage.logAudit('READ', 'success', {
    agentName: ctx.agentName,
    operation: 'list_scopes',
    details: JSON.stringify({ count: scopes.length }),
  });

  return { scopes };
}

/**
 * Get available operations for a record type
 */
function getOperationsForType(itemType: string, sensitivity: string): string[] {
  switch (itemType) {
    case 'WALLET_KEY':
      return ['sign_tx', 'sign_message', 'get_address'];
    case 'ADDRESS':
    case 'IDENTITY':
    case 'PREFERENCES':
    case 'CREDENTIALS':
    case 'HEALTH':
    case 'BUDGET':
      if (sensitivity === 'critical') {
        return ['read_reference', 'submit_to_endpoint'];
      }
      return ['read'];
    default:
      return ['read'];
  }
}

// ============================================================================
// vault_get_address - No consent required
// ============================================================================

/**
 * Get public address for a chain
 *
 * PRD: Returns public address string
 * Consent: No (public addresses are not sensitive)
 */
export async function vault_get_address(
  ctx: ToolContext,
  input: GetAddressInput
): Promise<GetAddressOutput> {
  // Find wallet record for the chain
  const records = ctx.storage.listRecords();
  const walletRecord = records.find(
    (r) => r.item_type === 'WALLET_KEY' && r.chain === input.chain
  );

  if (!walletRecord || !walletRecord.public_address) {
    throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${input.chain}`, {
      chain: input.chain,
    });
  }

  // Log to audit
  ctx.storage.logAudit('READ', 'success', {
    agentName: ctx.agentName,
    scope: walletRecord.scope,
    operation: 'get_address',
    details: JSON.stringify({ chain: input.chain }),
  });

  return {
    chain: input.chain,
    address: walletRecord.public_address,
  };
}

// ============================================================================
// vault_budget_check - No consent required
// ============================================================================

/**
 * Check if a proposed transaction is within budget
 *
 * PRD: Returns allowed, limits, remaining, requires_approval
 * Consent: No (budget info is not sensitive)
 */
export async function vault_budget_check(
  ctx: ToolContext,
  input: BudgetCheckInput
): Promise<BudgetCheckOutput> {
  const limits = ctx.budget.getLimits(input.currency);

  // Determine chain (required for chain-agnostic currencies like USDC/USDT)
  const chain = getChainForCurrency(input.currency, input.chain);
  const result = ctx.budget.checkBudget(input.amount, input.currency, chain);

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

/**
 * Get the chain for a currency code
 */
function getChainForCurrency(currency: string, chain?: Chain): Chain {
  if (chain) return chain;
  switch (currency.toUpperCase()) {
    case 'SOL':
      return 'solana';
    case 'ETH':
      return 'ethereum';
    case 'BASE_ETH':
      return 'base';
    case 'USDC':
    case 'USDT':
      throw new VaultError('INTERNAL_ERROR', `chain is required for ${currency}`);
    default:
      throw new VaultError('INTERNAL_ERROR', `Unknown currency: ${currency}`);
  }
}

// ============================================================================
// vault_read - Consent required
// ============================================================================

/**
 * Read data from a scope
 *
 * PRD: Returns plaintext data (STANDARD/SENSITIVE) or reference (CRITICAL)
 * Consent: Yes (first time per session)
 */
export async function vault_read(
  ctx: ToolContext,
  input: ReadInput
): Promise<ReadOutput> {
  // If we don't have a session yet, try to reuse an existing active session
  if (!ctx.sessionId) {
    const existingSessionId = getActiveAgentSessionId(ctx.storage, ctx.agentName, input.scope);
    if (existingSessionId) {
      ctx.sessionId = existingSessionId;
    }
  }

  // Find the record
  const record = ctx.storage.getRecord(input.scope);

  if (!record) {
    throw new VaultError('RECORD_NOT_FOUND', `Scope not found: ${input.scope}`, {
      scope: input.scope,
    });
  }

  // If vault is locked and we need plaintext, short-circuit before consent
  if (record.sensitivity !== 'critical' && !ctx.storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Unlock at http://127.0.0.1:8420', {
      approval_url: APPROVAL_URL,
    });
  }

  // CRITICAL data is reference-only (private keys never exposed)
  if (record.sensitivity === 'critical') {
    // No consent needed for reference-only
    ctx.storage.logAudit('READ', 'success', {
      agentName: ctx.agentName,
      scope: input.scope,
      operation: 'read_reference',
    });

    return {
      scope: input.scope,
      data: null,
      sensitivity: record.sensitivity,
      is_reference: true,
      reference_id: record.id,
    };
  }

  // Check if we need consent
  const needsConsent = !ctx.sessionId || !hasSessionScope(ctx.storage, ctx.sessionId, input.scope);

  if (needsConsent) {
    const consentResponse = await requestConsent(
      ctx.storage,
      ctx.agentName,
      'read',
      input.scope,
      { sessionId: ctx.sessionId }
    );

    if (!consentResponse.approved) {
      ctx.storage.logAudit('DENY', 'denied', {
        agentName: ctx.agentName,
        scope: input.scope,
        operation: 'read',
        details: 'Consent denied by user',
      });

      throw new VaultError('CONSENT_DENIED', 'User denied consent for read operation', {
        scope: input.scope,
      });
    }

    // If session consent was granted, track the session
    if (consentResponse.mode === 'session') {
      // Non-TTY approval already created a session with session_id
      if (consentResponse.session_id) {
        ctx.sessionId = consentResponse.session_id;
      } else {
        // TTY mode: create session ourselves (4 hour max duration)
        const session = ctx.storage.createSession(
          ctx.agentName,
          [input.scope],
          'session',
          new Date(Date.now() + 4 * 60 * 60 * 1000) // 4 hours
        );
        ctx.sessionId = session.id;
      }
    }
  } else {
    // Touch session if we have one
    if (ctx.sessionId) {
      touchSession(ctx.storage, ctx.sessionId);
    }
  }

  // Get master key and decrypt
  const masterKey = getMasterKeySafe(ctx.storage);
  const payload = ctx.storage.getEncryptedPayload(input.scope);

  if (!payload) {
    throw new VaultError('RECORD_NOT_FOUND', `Scope not found: ${input.scope}`, {
      scope: input.scope,
    });
  }

  const plaintext = envelopeDecrypt(payload, masterKey);
  let data: Record<string, unknown> = JSON.parse(plaintext.toString('utf8'));

  // Filter fields if specified
  if (input.fields && input.fields.length > 0) {
    const filtered: Record<string, unknown> = {};
    for (const field of input.fields) {
      if (field in data) {
        filtered[field] = data[field];
      }
    }
    data = filtered;
  }

  // Log to audit
  ctx.storage.logAudit('READ', 'success', {
    agentName: ctx.agentName,
    scope: input.scope,
    operation: 'read',
    details: input.fields ? JSON.stringify({ fields: input.fields }) : undefined,
  });

  return {
    scope: input.scope,
    data,
    sensitivity: record.sensitivity,
    is_reference: false,
  };
}

// ============================================================================
// vault_sign_tx - Consent required
// ============================================================================

/**
 * Get wallet scope for a chain (matches storage convention)
 */
function getWalletScope(chain: Chain): string {
  return `crypto.wallet.${chain}`;
}

/**
 * Sign a transaction
 *
 * PRD: Returns signed_tx, signature, budget remaining
 * Consent: Yes (first time, or if above approval threshold)
 */
export async function vault_sign_tx(
  ctx: ToolContext,
  input: SignTxInput
): Promise<SignTxOutput> {
  if (!ctx.storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Unlock at http://127.0.0.1:8420', {
      approval_url: APPROVAL_URL,
    });
  }

  // Get wallet scope
  const walletScope = getWalletScope(input.chain);

  // If we don't have a session yet, try to reuse an existing active session
  if (!ctx.sessionId) {
    const existingSessionId = getActiveAgentSessionId(ctx.storage, ctx.agentName, walletScope);
    if (existingSessionId) {
      ctx.sessionId = existingSessionId;
    }
  }

  // Find wallet record for the chain
  const records = ctx.storage.listRecords();
  const walletRecord = records.find(
    (r) => r.item_type === 'WALLET_KEY' && r.chain === input.chain
  );

  if (!walletRecord) {
    throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${input.chain}`, {
      chain: input.chain,
    });
  }

  // Determine currency from chain if not provided
  const currency = input.currency || BudgetEngine.getCurrencyForChain(input.chain);
  const amount = input.amount || 0;

  // Check idempotency key
  if (input.idempotency_key) {
    const existing = ctx.storage.getSpendByIdempotencyKey(input.idempotency_key);
    if (existing) {
      throw new VaultError('IDEMPOTENCY_CONFLICT', 'Transaction already processed', {
        idempotency_key: input.idempotency_key,
        existing_tx_signature: existing.tx_signature,
      });
    }
  }

  // Check rate limit (use agent name if no session)
  const rateLimitId = ctx.sessionId || ctx.agentName;
  ctx.budget.recordExecution(rateLimitId);

  // Check budget
  ctx.budget.enforceBudget(amount, currency, input.chain);

  // Get approval threshold
  const limits = ctx.budget.getLimits(currency);
  const needsMandatoryApproval = requiresMandatoryApproval(amount, limits.approval_threshold);

  // Check if we need consent (first time, or above threshold)
  const needsConsent =
    needsMandatoryApproval ||
    !ctx.sessionId ||
    !hasSessionScope(ctx.storage, ctx.sessionId, walletScope);

  if (needsConsent) {
    const consentResponse = await requestConsent(
      ctx.storage,
      ctx.agentName,
      'sign_tx',
      walletScope,
      {
        description: input.description,
        amount,
        currency,
        chain: input.chain,
        sessionId: ctx.sessionId,
      }
    );

    if (!consentResponse.approved) {
      ctx.storage.logAudit('DENY', 'denied', {
        agentName: ctx.agentName,
        scope: walletScope,
        operation: 'sign_tx',
        details: JSON.stringify({
          chain: input.chain,
          amount,
          currency,
          description: input.description,
        }),
      });

      throw new VaultError('CONSENT_DENIED', 'User denied consent for sign operation', {
        chain: input.chain,
        amount,
        currency,
      });
    }

    // Track session if session mode granted
    if (consentResponse.mode === 'session') {
      // Non-TTY approval already created a session with session_id
      if (consentResponse.session_id) {
        ctx.sessionId = consentResponse.session_id;
      } else {
        // TTY mode: create session ourselves (4 hour max duration)
        const session = ctx.storage.createSession(
          ctx.agentName,
          [walletScope],
          'session',
          new Date(Date.now() + 4 * 60 * 60 * 1000) // 4 hours
        );
        ctx.sessionId = session.id;
      }
    }
  } else {
    // Touch session
    if (ctx.sessionId) {
      touchSession(ctx.storage, ctx.sessionId);
    }
  }

  // Get master key
  const masterKey = getMasterKeySafe(ctx.storage);

  // Get encrypted wallet key
  const encryptedKey = ctx.storage.getEncryptedPayload(walletScope);
  if (!encryptedKey) {
    throw new VaultError('RECORD_NOT_FOUND', `Wallet not found: ${walletScope}`, {
      chain: input.chain,
    });
  }

  // Sign the transaction
  const signResult = await signTransaction(
    encryptedKey,
    masterKey,
    input.chain,
    input.unsigned_tx
  );

  // Record spend event
  const spendEvent = ctx.storage.recordSpend(
    ctx.sessionId || 'anonymous',
    amount,
    currency,
    input.chain,
    'sign_tx',
    'committed',
    {
      destination: input.destination,
      idempotencyKey: input.idempotency_key,
      txSignature: signResult.signature,
    }
  );

  // Log to audit
  ctx.storage.logAudit('EXECUTE', 'success', {
    agentName: ctx.agentName,
    scope: walletScope,
    operation: 'sign_tx',
    details: JSON.stringify({
      chain: input.chain,
      amount,
      currency,
      signature: signResult.signature,
      spend_event_id: spendEvent.id,
    }),
  });

  // Get updated budget remaining
  const updatedBudget = ctx.budget.checkBudget(0, currency, input.chain);

  return {
    signed_tx: signResult.signed_tx,
    signature: signResult.signature,
    chain: input.chain,
    budget_remaining: {
      daily: updatedBudget.remaining_daily,
      per_tx: limits.tx_limit,
    },
  };
}

// ============================================================================
// vault_sign_message - Consent required
// ============================================================================

/**
 * Sign an arbitrary message
 *
 * Consent: Yes (first time per session)
 */
export async function vault_sign_message(
  ctx: ToolContext,
  input: SignMessageInput
): Promise<SignMessageOutput> {
  if (!ctx.storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Unlock at http://127.0.0.1:8420', {
      approval_url: APPROVAL_URL,
    });
  }

  if (!input.chain || !input.message) {
    throw new VaultError('INTERNAL_ERROR', 'chain and message are required');
  }

  const walletScope = getWalletScope(input.chain);

  if (!ctx.sessionId) {
    const existingSessionId = getActiveAgentSessionId(ctx.storage, ctx.agentName, walletScope);
    if (existingSessionId) {
      ctx.sessionId = existingSessionId;
    }
  }

  const records = ctx.storage.listRecords();
  const walletRecord = records.find(
    (r) => r.item_type === 'WALLET_KEY' && r.chain === input.chain
  );

  if (!walletRecord || !walletRecord.public_address) {
    throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${input.chain}`, {
      chain: input.chain,
    });
  }

  const needsConsent =
    !ctx.sessionId || !hasSessionScope(ctx.storage, ctx.sessionId, walletScope);

  if (needsConsent) {
    const consentResponse = await requestConsent(
      ctx.storage,
      ctx.agentName,
      'sign_message',
      walletScope,
      {
        description: input.description,
        chain: input.chain,
        sessionId: ctx.sessionId,
      }
    );

    if (!consentResponse.approved) {
      ctx.storage.logAudit('DENY', 'denied', {
        agentName: ctx.agentName,
        scope: walletScope,
        operation: 'sign_message',
        details: JSON.stringify({
          chain: input.chain,
        }),
      });

      throw new VaultError('CONSENT_DENIED', 'User denied consent for sign_message', {
        chain: input.chain,
      });
    }

    if (consentResponse.mode === 'session') {
      if (consentResponse.session_id) {
        ctx.sessionId = consentResponse.session_id;
      } else {
        const session = ctx.storage.createSession(
          ctx.agentName,
          [walletScope],
          'session',
          new Date(Date.now() + 4 * 60 * 60 * 1000)
        );
        ctx.sessionId = session.id;
      }
    }
  } else if (ctx.sessionId) {
    touchSession(ctx.storage, ctx.sessionId);
  }

  const masterKey = getMasterKeySafe(ctx.storage);
  const encryptedKey = ctx.storage.getEncryptedPayload(walletScope);
  if (!encryptedKey) {
    throw new VaultError('RECORD_NOT_FOUND', `Wallet not found: ${walletScope}`, {
      chain: input.chain,
    });
  }

  const encoding = input.encoding || 'utf8';
  let signature: string;
  if (input.chain === 'solana') {
    signature = signSolanaMessage(encryptedKey, masterKey, input.message, encoding);
  } else {
    const messagePayload =
      encoding === 'base64' ? Buffer.from(input.message, 'base64') : input.message;
    signature = await signEvmMessage(encryptedKey, masterKey, messagePayload);
  }

  ctx.storage.logAudit('EXECUTE', 'success', {
    agentName: ctx.agentName,
    scope: walletScope,
    operation: 'sign_message',
    details: JSON.stringify({ chain: input.chain }),
  });

  return {
    signature,
    public_key: walletRecord.public_address,
    chain: input.chain,
  };
}

// ============================================================================
// vault_sign_typed_data - Consent required
// ============================================================================

/**
 * Sign EIP-712 typed data (EVM)
 *
 * Consent: Yes (first time per session)
 */
export async function vault_sign_typed_data(
  ctx: ToolContext,
  input: SignTypedDataInput
): Promise<SignTypedDataOutput> {
  if (!ctx.storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Unlock at http://127.0.0.1:8420', {
      approval_url: APPROVAL_URL,
    });
  }

  if (!input.chain || !input.typed_data) {
    throw new VaultError('INTERNAL_ERROR', 'chain and typed_data are required');
  }

  if (input.chain !== 'base' && input.chain !== 'ethereum') {
    throw new VaultError('INVALID_CHAIN', `Unsupported chain for typed data: ${input.chain}`);
  }

  const walletScope = getWalletScope(input.chain);

  if (!ctx.sessionId) {
    const existingSessionId = getActiveAgentSessionId(ctx.storage, ctx.agentName, walletScope);
    if (existingSessionId) {
      ctx.sessionId = existingSessionId;
    }
  }

  const records = ctx.storage.listRecords();
  const walletRecord = records.find(
    (r) => r.item_type === 'WALLET_KEY' && r.chain === input.chain
  );

  if (!walletRecord || !walletRecord.public_address) {
    throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${input.chain}`, {
      chain: input.chain,
    });
  }

  const needsConsent =
    !ctx.sessionId || !hasSessionScope(ctx.storage, ctx.sessionId, walletScope);

  if (needsConsent) {
    const consentResponse = await requestConsent(
      ctx.storage,
      ctx.agentName,
      'sign_typed_data',
      walletScope,
      {
        description: input.description,
        chain: input.chain,
        sessionId: ctx.sessionId,
      }
    );

    if (!consentResponse.approved) {
      ctx.storage.logAudit('DENY', 'denied', {
        agentName: ctx.agentName,
        scope: walletScope,
        operation: 'sign_typed_data',
        details: JSON.stringify({
          chain: input.chain,
        }),
      });

      throw new VaultError('CONSENT_DENIED', 'User denied consent for sign_typed_data', {
        chain: input.chain,
      });
    }

    if (consentResponse.mode === 'session') {
      if (consentResponse.session_id) {
        ctx.sessionId = consentResponse.session_id;
      } else {
        const session = ctx.storage.createSession(
          ctx.agentName,
          [walletScope],
          'session',
          new Date(Date.now() + 4 * 60 * 60 * 1000)
        );
        ctx.sessionId = session.id;
      }
    }
  } else if (ctx.sessionId) {
    touchSession(ctx.storage, ctx.sessionId);
  }

  const masterKey = getMasterKeySafe(ctx.storage);
  const encryptedKey = ctx.storage.getEncryptedPayload(walletScope);
  if (!encryptedKey) {
    throw new VaultError('RECORD_NOT_FOUND', `Wallet not found: ${walletScope}`, {
      chain: input.chain,
    });
  }

  const signature = await signEvmTypedData(encryptedKey, masterKey, input.typed_data);

  ctx.storage.logAudit('EXECUTE', 'success', {
    agentName: ctx.agentName,
    scope: walletScope,
    operation: 'sign_typed_data',
    details: JSON.stringify({ chain: input.chain }),
  });

  return {
    signature,
    public_key: walletRecord.public_address,
    chain: input.chain,
  };
}

// ============================================================================
// vault_sign_x402 - Consent required
// ============================================================================

/**
 * Sign an x402 payload with optional typed data for EVM
 *
 * Consent: Yes (first time per session, and above approval threshold)
 */
export async function vault_sign_x402(
  ctx: ToolContext,
  input: SignX402Input
): Promise<SignX402Output> {
  if (!ctx.storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Unlock at http://127.0.0.1:8420', {
      approval_url: APPROVAL_URL,
    });
  }

  if (!input.network || !input.payload) {
    throw new VaultError('INTERNAL_ERROR', 'network and payload are required');
  }

  const chain: Chain = input.network === 'solana' ? 'solana' : 'base';
  const walletScope = getWalletScope(chain);

  if (!ctx.sessionId) {
    const existingSessionId = getActiveAgentSessionId(ctx.storage, ctx.agentName, walletScope);
    if (existingSessionId) {
      ctx.sessionId = existingSessionId;
    }
  }

  const records = ctx.storage.listRecords();
  const walletRecord = records.find(
    (r) => r.item_type === 'WALLET_KEY' && r.chain === chain
  );

  if (!walletRecord || !walletRecord.public_address) {
    throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`, {
      chain,
    });
  }

  const amount = normalizeAmount(input.amount);
  const currency = input.currency;

  if (amount !== undefined && !currency) {
    throw new VaultError('INTERNAL_ERROR', 'currency is required when amount is provided');
  }

  if (amount !== undefined && currency) {
    const budgetResult = ctx.budget.checkBudget(amount, currency, chain);
    if (!budgetResult.allowed) {
      throw new VaultError(
        budgetResult.reason?.includes('BUDGET_EXCEEDED_TX')
          ? 'BUDGET_EXCEEDED_TX'
          : 'BUDGET_EXCEEDED_DAILY',
        budgetResult.reason || 'Budget exceeded',
        {
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
        }
      );
    }
  }

  const limits = currency ? ctx.budget.getLimits(currency) : undefined;
  const needsMandatoryApproval =
    currency && amount !== undefined && limits
      ? requiresMandatoryApproval(amount, limits.approval_threshold)
      : false;

  const needsConsent =
    needsMandatoryApproval ||
    !ctx.sessionId ||
    !hasSessionScope(ctx.storage, ctx.sessionId, walletScope);

  if (needsConsent) {
    const consentResponse = await requestConsent(
      ctx.storage,
      ctx.agentName,
      'sign_x402',
      walletScope,
      {
        description: input.purpose,
        amount,
        currency,
        chain,
        recipient: input.recipient,
        purpose: input.purpose,
        network: input.network,
        sessionId: ctx.sessionId,
      }
    );

    if (!consentResponse.approved) {
      ctx.storage.logAudit('DENY', 'denied', {
        agentName: ctx.agentName,
        scope: walletScope,
        operation: 'sign_x402',
        details: JSON.stringify({
          chain,
          amount,
          currency,
          recipient: input.recipient,
          purpose: input.purpose,
        }),
      });

      throw new VaultError('CONSENT_DENIED', 'User denied consent for sign_x402', {
        chain,
        amount,
        currency,
      });
    }

    if (consentResponse.mode === 'session') {
      if (consentResponse.session_id) {
        ctx.sessionId = consentResponse.session_id;
      } else {
        const session = ctx.storage.createSession(
          ctx.agentName,
          [walletScope],
          'session',
          new Date(Date.now() + 4 * 60 * 60 * 1000)
        );
        ctx.sessionId = session.id;
      }
    }
  } else if (ctx.sessionId) {
    touchSession(ctx.storage, ctx.sessionId);
  }

  const masterKey = getMasterKeySafe(ctx.storage);
  const encryptedKey = ctx.storage.getEncryptedPayload(walletScope);
  if (!encryptedKey) {
    throw new VaultError('RECORD_NOT_FOUND', `Wallet not found: ${walletScope}`, {
      chain,
    });
  }

  let signature: string;
  if (chain === 'solana') {
    signature = signSolanaMessage(encryptedKey, masterKey, input.payload, 'base64');
  } else if (input.typed_data) {
    signature = await signEvmTypedData(encryptedKey, masterKey, input.typed_data);
  } else {
    const payloadBytes = Buffer.from(input.payload, 'base64');
    signature = await signEvmMessage(encryptedKey, masterKey, payloadBytes);
  }

  if (amount !== undefined && currency) {
    ctx.storage.recordSpend(
      ctx.sessionId || ctx.agentName,
      amount,
      currency,
      chain,
      'sign_x402',
      'committed',
      {
        destination: input.recipient,
      }
    );
  }

  ctx.storage.logAudit('EXECUTE', 'success', {
    agentName: ctx.agentName,
    scope: walletScope,
    operation: 'sign_x402',
    details: JSON.stringify({
      chain,
      amount,
      currency,
      recipient: input.recipient,
      purpose: input.purpose,
    }),
  });

  return {
    signature,
    public_key: walletRecord.public_address,
    chain,
  };
}

function normalizeAmount(amount?: string | number): number | undefined {
  if (amount === undefined || amount === null) return undefined;
  if (typeof amount === 'number') return amount;
  if (typeof amount === 'string' && amount.trim().length > 0) {
    const parsed = Number(amount);
    if (!Number.isFinite(parsed)) {
      throw new VaultError('INTERNAL_ERROR', 'Invalid amount');
    }
    return parsed;
  }
  return undefined;
}

// ============================================================================
// vault_write - Consent required
// ============================================================================

/**
 * Write data to a scope
 *
 * Consent: Yes (first time per session)
 */
export async function vault_write(
  ctx: ToolContext,
  input: WriteInput
): Promise<WriteOutput> {
  if (!input.scope || !input.data) {
    throw new VaultError('INTERNAL_ERROR', 'scope and data are required');
  }

  if (!ctx.storage.isUnlocked()) {
    throw new VaultError('VAULT_LOCKED', 'Vault is locked. Unlock at http://127.0.0.1:8420', {
      approval_url: APPROVAL_URL,
    });
  }

  if (!isWriteAllowed(ctx, input.scope)) {
    throw new VaultError(
      'SCOPE_VIOLATION',
      `Agent ${ctx.agentName} not authorized to write scope: ${input.scope}`
    );
  }

  if (!ctx.sessionId) {
    const existingSessionId = getActiveAgentSessionId(ctx.storage, ctx.agentName, input.scope);
    if (existingSessionId) {
      ctx.sessionId = existingSessionId;
    }
  }

  const needsConsent =
    !ctx.sessionId || !hasSessionScope(ctx.storage, ctx.sessionId, input.scope);

  if (needsConsent) {
    const consentResponse = await requestConsent(
      ctx.storage,
      ctx.agentName,
      'write',
      input.scope,
      { sessionId: ctx.sessionId }
    );

    if (!consentResponse.approved) {
      ctx.storage.logAudit('DENY', 'denied', {
        agentName: ctx.agentName,
        scope: input.scope,
        operation: 'write',
        details: 'Consent denied by user',
      });

      throw new VaultError('CONSENT_DENIED', 'User denied consent for write operation', {
        scope: input.scope,
      });
    }

    if (consentResponse.mode === 'session') {
      if (consentResponse.session_id) {
        ctx.sessionId = consentResponse.session_id;
      } else {
        const session = ctx.storage.createSession(
          ctx.agentName,
          [input.scope],
          'session',
          new Date(Date.now() + 4 * 60 * 60 * 1000)
        );
        ctx.sessionId = session.id;
      }
    }
  } else if (ctx.sessionId) {
    touchSession(ctx.storage, ctx.sessionId);
  }

  const masterKey = getMasterKeySafe(ctx.storage);
  const existing = ctx.storage.getRecord(input.scope);
  const data = normalizeWriteData(input.scope, input.data);

  if (existing) {
    ctx.storage.updateRecord(existing.id, data, masterKey);
  } else {
    ctx.storage.createRecord({
      scope: input.scope,
      item_type: inferItemType(input.scope),
      sensitivity: inferSensitivity(input.scope),
      data,
    });
  }

  ctx.storage.logAudit('EXECUTE', 'success', {
    agentName: ctx.agentName,
    scope: input.scope,
    operation: 'write',
  });

  return {
    scope: input.scope,
    created: !existing,
    updated: !!existing,
    sensitivity: existing?.sensitivity || inferSensitivity(input.scope),
  };
}

function isWriteAllowed(ctx: ToolContext, scope: string): boolean {
  const config = ctx.budget.getConfig();
  const permissions = config.write_permissions || {};
  const allowed = permissions[ctx.agentName];
  if (!allowed || allowed.length === 0) {
    return false;
  }
  return allowed.some((pattern) => scopeMatches(pattern, scope));
}

function scopeMatches(pattern: string, scope: string): boolean {
  if (pattern === scope) return true;
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2);
    return scope.startsWith(prefix + '.');
  }
  return false;
}

function inferItemType(scope: string): ScopeInfo['type'] {
  if (scope.startsWith('identity.')) return 'IDENTITY';
  if (scope.startsWith('address.')) return 'ADDRESS';
  if (scope.startsWith('preferences.')) return 'PREFERENCES';
  if (scope.startsWith('crypto.')) return 'WALLET_KEY';
  if (scope.startsWith('credentials.')) return 'CREDENTIALS';
  if (scope.startsWith('health.')) return 'HEALTH';
  if (scope.startsWith('budget.')) return 'BUDGET';
  return 'PREFERENCES';
}

function inferSensitivity(scope: string): ScopeInfo['sensitivity'] {
  if (
    scope.startsWith('identity.passport') ||
    scope.startsWith('identity.drivers_license') ||
    scope.startsWith('crypto.')
  ) {
    return 'critical';
  }
  if (scope.startsWith('credentials.')) {
    // Credentials are sensitive (readable with consent), not critical
    return 'sensitive';
  }
  if (scope.startsWith('identity.') || scope.startsWith('address.') || scope.startsWith('health.')) {
    return 'sensitive';
  }
  return 'standard';
}

function ensureSchemaVersion(data: Record<string, unknown>): Record<string, unknown> {
  if ('schema_version' in data) {
    return data;
  }
  return { ...data, schema_version: '1.0' };
}

function normalizeWriteData(scope: string, data: Record<string, unknown>): Record<string, unknown> {
  const base = ensureSchemaVersion(data);
  if (scope.startsWith('credentials.api.')) {
    return validateAndNormalizeCredentialsApi(base);
  }
  return base;
}

function validateAndNormalizeCredentialsApi(data: Record<string, unknown>): Record<string, unknown> {
  const allowedKeys = [
    'schema_version',
    'label',
    'service',
    'key',
    'base_url',
    'auth_type',
    'headers',
  ];

  for (const key of Object.keys(data)) {
    if (!allowedKeys.includes(key)) {
      throw new VaultError('INVALID_SCHEMA', `Unexpected field in credentials.api: ${key}`);
    }
  }

  const normalized: Record<string, unknown> = {
    schema_version: String(data.schema_version || '1.0'),
    label: data.label ?? null,
    service: data.service ?? null,
    key: data.key ?? null,
    base_url: data.base_url ?? null,
    auth_type: data.auth_type ?? null,
    headers: data.headers ?? null,
  };

  if (typeof normalized.schema_version !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'schema_version must be a string');
  }
  if (normalized.label !== null && typeof normalized.label !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'label must be a string or null');
  }
  if (normalized.service !== null && typeof normalized.service !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'service must be a string or null');
  }
  if (normalized.key !== null && typeof normalized.key !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'key must be a string or null');
  }
  if (normalized.base_url !== null && typeof normalized.base_url !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'base_url must be a string or null');
  }
  if (normalized.auth_type !== null && typeof normalized.auth_type !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'auth_type must be a string or null');
  }
  if (
    normalized.headers !== null &&
    (typeof normalized.headers !== 'object' || Array.isArray(normalized.headers))
  ) {
    throw new VaultError('INVALID_SCHEMA', 'headers must be an object or null');
  }

  return normalized;
}
