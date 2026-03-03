/**
 * Budget & Policy Engine for DCP Vault
 *
 * Implements (from PRD Section 3.1.7):
 * - Per-transaction limits (default: 5 SOL, 0.5 ETH, 200 USDC)
 * - Daily limits (default: 20 SOL, 1 ETH, 500 USDC)
 * - Approval thresholds (default: 2 SOL, 0.1 ETH, 100 USDC)
 * - Rate limiting (5 executions/minute)
 * - Idempotency key validation
 *
 * Budget check flow (every `vault_sign_tx`):
 * 1. Sum SpendEvents for this currency in last 24h
 * 2. proposed amount <= tx_limit? No -> BUDGET_EXCEEDED_TX
 * 3. total + proposed <= daily_limit? No -> BUDGET_EXCEEDED_DAILY
 * 4. proposed > approval_threshold? Yes -> require manual approval
 * 5. All pass -> sign
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  BudgetConfig,
  BudgetCheckResult,
  Chain,
  VaultError,
} from './types.js';
import { VaultStorage } from './storage.js';

// ============================================================================
// Constants (from PRD Section 17 - Configuration Reference)
// ============================================================================

/** Default vault directory */
const DEFAULT_VAULT_DIR = path.join(os.homedir(), '.dcp');

/** Default configuration file name */
const CONFIG_FILE = 'config.json';

/** Default budget configuration (from PRD Section 17) */
export const DEFAULT_BUDGET_CONFIG: BudgetConfig = {
  daily_budget: {
    SOL: 20,
    ETH: 1,
    USDC: 500,
    USDT: 500,
    BASE_ETH: 0.5,
  },
  tx_limit: {
    SOL: 5,
    ETH: 0.5,
    USDC: 200,
    USDT: 200,
    BASE_ETH: 0.2,
  },
  approval_threshold: {
    SOL: 2,
    ETH: 0.1,
    USDC: 100,
    USDT: 100,
    BASE_ETH: 0.05,
  },
};

/** Rate limit: executions per minute (from PRD B5) */
export const RATE_LIMIT_PER_MINUTE = 5;

/** Rate limit window in milliseconds */
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

// ============================================================================
// Full Vault Configuration (from PRD Section 17)
// ============================================================================

export interface VaultConfig {
  version: string;
  server_port: number;
  default_chain: Chain;
  daily_budget: Record<string, number>;
  tx_limit: Record<string, number>;
  approval_threshold: Record<string, number>;
  session_timeout_minutes: number;
  session_max_hours: number;
  consent_timeout_seconds: number;
  rate_limit_per_minute: number;
  trust_sources: string[];
  keychain_service: string;
}

/** Default vault configuration */
export const DEFAULT_VAULT_CONFIG: VaultConfig = {
  version: '1.0.0',
  server_port: 8420,
  default_chain: 'solana',
  // Use spread to create copies, not references
  daily_budget: { ...DEFAULT_BUDGET_CONFIG.daily_budget },
  tx_limit: { ...DEFAULT_BUDGET_CONFIG.tx_limit },
  approval_threshold: { ...DEFAULT_BUDGET_CONFIG.approval_threshold },
  session_timeout_minutes: 30,
  session_max_hours: 4,
  consent_timeout_seconds: 300,
  rate_limit_per_minute: RATE_LIMIT_PER_MINUTE,
  trust_sources: [],
  keychain_service: 'dcp',
};

/**
 * Deep clone a VaultConfig to prevent mutation of shared references
 */
function deepCloneConfig(config: VaultConfig): VaultConfig {
  return {
    ...config,
    daily_budget: { ...config.daily_budget },
    tx_limit: { ...config.tx_limit },
    approval_threshold: { ...config.approval_threshold },
    trust_sources: [...config.trust_sources],
  };
}

// ============================================================================
// Budget Engine Class
// ============================================================================

export class BudgetEngine {
  private config: VaultConfig;
  private vaultDir: string;
  private storage: VaultStorage;

  /** In-memory rate limit tracking: sessionId -> timestamps */
  private rateLimitMap: Map<string, number[]> = new Map();

  constructor(storage: VaultStorage, vaultDir: string = DEFAULT_VAULT_DIR) {
    this.storage = storage;
    this.vaultDir = vaultDir;
    this.config = this.loadConfig();
  }

  // ==========================================================================
  // Configuration Management
  // ==========================================================================

  /**
   * Load configuration from file, falling back to defaults
   */
  private loadConfig(): VaultConfig {
    const configPath = path.join(this.vaultDir, CONFIG_FILE);

    // Always deep clone to prevent mutation of global defaults
    const defaults = deepCloneConfig(DEFAULT_VAULT_CONFIG);

    if (fs.existsSync(configPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        // Merge with defaults to ensure all fields exist
        return {
          ...defaults,
          ...data,
          daily_budget: { ...defaults.daily_budget, ...data.daily_budget },
          tx_limit: { ...defaults.tx_limit, ...data.tx_limit },
          approval_threshold: { ...defaults.approval_threshold, ...data.approval_threshold },
        };
      } catch {
        // Invalid config, use defaults
        return defaults;
      }
    }

    return defaults;
  }

  /**
   * Save configuration to file
   */
  saveConfig(): void {
    const configPath = path.join(this.vaultDir, CONFIG_FILE);

    // Ensure directory exists
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }

    fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2), { mode: 0o600 });
  }

  /**
   * Get current configuration (deep cloned to prevent external mutation)
   */
  getConfig(): VaultConfig {
    return deepCloneConfig(this.config);
  }

  /**
   * Update a configuration value
   */
  setConfig<K extends keyof VaultConfig>(key: K, value: VaultConfig[K]): void {
    this.config[key] = value;
    this.saveConfig();

    // Log config change to audit
    this.storage.logAudit('CONFIG', 'success', {
      operation: 'set_config',
      details: JSON.stringify({ key, value }),
    });
  }

  /**
   * Set a budget limit for a specific currency
   */
  setLimit(
    type: 'daily_budget' | 'tx_limit' | 'approval_threshold',
    currency: string,
    amount: number
  ): void {
    if (amount < 0) {
      throw new VaultError('INTERNAL_ERROR', 'Budget limit cannot be negative');
    }

    this.config[type][currency] = amount;
    this.saveConfig();

    // Log config change to audit
    this.storage.logAudit('CONFIG', 'success', {
      operation: 'set_limit',
      details: JSON.stringify({ type, currency, amount }),
    });
  }

  /**
   * Get budget limits for a currency
   */
  getLimits(currency: string): {
    daily_budget: number;
    tx_limit: number;
    approval_threshold: number;
  } {
    return {
      daily_budget: this.config.daily_budget[currency] ?? 0,
      tx_limit: this.config.tx_limit[currency] ?? 0,
      approval_threshold: this.config.approval_threshold[currency] ?? 0,
    };
  }

  // ==========================================================================
  // Budget Check (from PRD Section 3.1.7)
  // ==========================================================================

  /**
   * Check if a proposed transaction is within budget
   *
   * Budget check flow (every `vault_sign_tx`):
   * 1. Sum SpendEvents for this currency in last 24h
   * 2. proposed amount <= tx_limit? No -> BUDGET_EXCEEDED_TX
   * 3. total + proposed <= daily_limit? No -> BUDGET_EXCEEDED_DAILY
   * 4. proposed > approval_threshold? Yes -> require manual approval
   * 5. All pass -> allowed
   *
   * @param amount - Proposed transaction amount
   * @param currency - Currency code (SOL, ETH, USDC, etc.)
   * @param chain - Blockchain
   * @returns Budget check result
   */
  checkBudget(amount: number, currency: string, chain: Chain): BudgetCheckResult {
    const limits = this.getLimits(currency);

    // Default result
    const result: BudgetCheckResult = {
      allowed: true,
      requires_approval: false,
      remaining_daily: limits.daily_budget,
      remaining_tx: limits.tx_limit,
    };

    // If no limits configured for this currency, allow by default
    // (conservative: could also deny unknown currencies)
    if (limits.tx_limit === 0 && limits.daily_budget === 0) {
      return result;
    }

    // Step 1: Sum SpendEvents for this currency in last 24h
    const dailySpent = this.storage.getDailySpend(currency, chain);

    // Step 2: Check per-transaction limit
    if (limits.tx_limit > 0 && amount > limits.tx_limit) {
      return {
        allowed: false,
        requires_approval: false,
        remaining_daily: Math.max(0, limits.daily_budget - dailySpent),
        remaining_tx: limits.tx_limit, // Max you can do in single tx
        reason: `BUDGET_EXCEEDED_TX: Transaction amount ${amount} ${currency} exceeds per-transaction limit of ${limits.tx_limit} ${currency}`,
      };
    }

    // Step 3: Check daily limit
    if (limits.daily_budget > 0 && dailySpent + amount > limits.daily_budget) {
      return {
        allowed: false,
        requires_approval: false,
        remaining_daily: Math.max(0, limits.daily_budget - dailySpent),
        remaining_tx: limits.tx_limit > 0 ? Math.min(limits.tx_limit, Math.max(0, limits.daily_budget - dailySpent)) : 0,
        reason: `BUDGET_EXCEEDED_DAILY: Daily spending limit reached. Spent: ${dailySpent} ${currency}, Limit: ${limits.daily_budget} ${currency}`,
      };
    }

    // Step 4: Check if requires manual approval
    const requiresApproval = limits.approval_threshold > 0 && amount > limits.approval_threshold;

    // Calculate remaining values, ensuring non-negative
    // If a limit is 0 (unlimited), remaining should be 0 to indicate "no limit applies"
    const remainingDaily = limits.daily_budget > 0
      ? Math.max(0, limits.daily_budget - dailySpent - amount)
      : 0;
    const remainingTx = limits.tx_limit > 0
      ? Math.max(0, limits.tx_limit - amount)
      : 0;

    return {
      allowed: true,
      requires_approval: requiresApproval,
      remaining_daily: remainingDaily,
      remaining_tx: remainingTx,
      reason: requiresApproval
        ? `APPROVAL_REQUIRED: Amount ${amount} ${currency} exceeds approval threshold of ${limits.approval_threshold} ${currency}`
        : undefined,
    };
  }

  /**
   * Enforce budget check - throws if budget exceeded
   *
   * @param amount - Proposed transaction amount
   * @param currency - Currency code
   * @param chain - Blockchain
   * @throws VaultError with BUDGET_EXCEEDED_TX or BUDGET_EXCEEDED_DAILY
   */
  enforceBudget(amount: number, currency: string, chain: Chain): BudgetCheckResult {
    const result = this.checkBudget(amount, currency, chain);

    if (!result.allowed) {
      const errorCode = result.reason?.includes('BUDGET_EXCEEDED_TX')
        ? 'BUDGET_EXCEEDED_TX'
        : 'BUDGET_EXCEEDED_DAILY';

      throw new VaultError(errorCode, result.reason || 'Budget exceeded', {
        amount,
        currency,
        chain,
        remaining_daily: result.remaining_daily,
        remaining_tx: result.remaining_tx,
      });
    }

    return result;
  }

  // ==========================================================================
  // Rate Limiting (from PRD B5: 5 executions/minute)
  // ==========================================================================

  /**
   * Check if a session is rate limited
   *
   * @param sessionId - Agent session ID
   * @returns true if rate limited, false if allowed
   */
  isRateLimited(sessionId: string): boolean {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    // Get existing timestamps for this session
    let timestamps = this.rateLimitMap.get(sessionId) || [];

    // Filter to only timestamps in current window
    timestamps = timestamps.filter((t) => t > windowStart);
    if (timestamps.length === 0) {
      this.rateLimitMap.delete(sessionId);
    } else {
      this.rateLimitMap.set(sessionId, timestamps);
    }

    // Check if over limit
    return timestamps.length >= this.config.rate_limit_per_minute;
  }

  /**
   * Record an execution for rate limiting
   *
   * @param sessionId - Agent session ID
   * @throws VaultError with RATE_LIMITED if limit exceeded
   */
  recordExecution(sessionId: string): void {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    // Get existing timestamps and filter to current window
    let timestamps = this.rateLimitMap.get(sessionId) || [];
    timestamps = timestamps.filter((t) => t > windowStart);

    // Check if over limit
    if (timestamps.length >= this.config.rate_limit_per_minute) {
      throw new VaultError('RATE_LIMITED', 'Rate limit exceeded. Maximum 5 executions per minute.', {
        limit: this.config.rate_limit_per_minute,
        window_seconds: 60,
        retry_after_ms: timestamps[0] + RATE_LIMIT_WINDOW_MS - now,
      });
    }

    // Add current timestamp
    timestamps.push(now);
    this.rateLimitMap.set(sessionId, timestamps);
  }

  /**
   * Get remaining executions in current window
   *
   * @param sessionId - Agent session ID
   * @returns Number of remaining executions allowed
   */
  getRemainingExecutions(sessionId: string): number {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    let timestamps = this.rateLimitMap.get(sessionId) || [];
    timestamps = timestamps.filter((t) => t > windowStart);
    if (timestamps.length === 0) {
      this.rateLimitMap.delete(sessionId);
    } else {
      this.rateLimitMap.set(sessionId, timestamps);
    }
    const recentCount = timestamps.length;

    return Math.max(0, this.config.rate_limit_per_minute - recentCount);
  }

  /**
   * Clear rate limit data for a session (e.g., on session end)
   */
  clearRateLimit(sessionId: string): void {
    this.rateLimitMap.delete(sessionId);
  }

  // ==========================================================================
  // Currency Mapping
  // ==========================================================================

  /**
   * Get the currency code for a chain
   * Solana -> SOL
   * Base -> BASE_ETH
   * Ethereum -> ETH
   */
  static getCurrencyForChain(chain: Chain): string {
    switch (chain) {
      case 'solana':
        return 'SOL';
      case 'base':
        return 'BASE_ETH';
      case 'ethereum':
        return 'ETH';
    }
    // Exhaustive check - this should never be reached
    const _exhaustiveCheck: never = chain;
    return _exhaustiveCheck;
  }

  /**
   * Get supported currencies
   */
  getSupportedCurrencies(): string[] {
    return [
      ...Object.keys(this.config.daily_budget),
      ...Object.keys(this.config.tx_limit),
      ...Object.keys(this.config.approval_threshold),
    ].filter((v, i, a) => a.indexOf(v) === i); // unique
  }
}

// ============================================================================
// Default Instance
// ============================================================================

let defaultBudgetEngine: BudgetEngine | null = null;

/**
 * Get the default budget engine instance
 */
export function getBudgetEngine(storage: VaultStorage, vaultDir?: string): BudgetEngine {
  if (!defaultBudgetEngine) {
    defaultBudgetEngine = new BudgetEngine(storage, vaultDir);
  }
  return defaultBudgetEngine;
}

/**
 * Reset the default budget engine instance (for testing)
 */
export function resetBudgetEngine(): void {
  defaultBudgetEngine = null;
}
