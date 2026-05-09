/**
 * DCP Client Errors
 *
 * Consistent error handling across local and relay transports.
 * See protocol spec section A6 for error specification.
 */

// ============================================================================
// Error Codes (from protocol spec A6)
// ============================================================================

export type DcpErrorCode =
  | 'VAULT_OFFLINE'
  | 'VAULT_LOCKED'
  | 'CONSENT_REQUIRED'
  | 'CONSENT_DENIED'
  | 'CONSENT_TIMEOUT'
  | 'RELAY_TIMEOUT'
  | 'RELAY_UNAVAILABLE'
  | 'RELAY_RATE_LIMITED'
  | 'VAULT_UNTRUSTED_SERVICE'
  | 'BUDGET_EXCEEDED_TX'
  | 'BUDGET_EXCEEDED_DAILY'
  | 'INTERNAL_ERROR'
  | 'INVALID_CHAIN'
  | 'RECORD_NOT_FOUND'
  | 'INVALID_CONFIG'
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED';

// ============================================================================
// Error Actions (from protocol spec A6)
// ============================================================================

export type DcpErrorAction =
  | 'open_dcp_app'
  | 'approve_in_dcp_app'
  | 'approve_consent'
  | 'trust_service'
  | 'retry'
  | undefined;

// ============================================================================
// Error → Action Mapping (from protocol spec A6)
// ============================================================================

const ERROR_ACTION_MAP: Record<DcpErrorCode, DcpErrorAction> = {
  VAULT_OFFLINE: 'open_dcp_app',
  VAULT_LOCKED: 'open_dcp_app',
  CONSENT_REQUIRED: 'approve_in_dcp_app',
  CONSENT_DENIED: undefined,
  CONSENT_TIMEOUT: 'approve_in_dcp_app',
  RELAY_TIMEOUT: 'retry',
  RELAY_UNAVAILABLE: 'retry',
  RELAY_RATE_LIMITED: 'retry',
  VAULT_UNTRUSTED_SERVICE: 'trust_service',
  BUDGET_EXCEEDED_TX: undefined,
  BUDGET_EXCEEDED_DAILY: undefined,
  INTERNAL_ERROR: undefined,
  INVALID_CHAIN: undefined,
  RECORD_NOT_FOUND: undefined,
  INVALID_CONFIG: undefined,
  ENCRYPTION_FAILED: undefined,
  DECRYPTION_FAILED: undefined,
};

// ============================================================================
// DcpError Class
// ============================================================================

export interface DcpErrorDetails {
  /** Consent ID for CONSENT_REQUIRED errors */
  consent_id?: string;
  /** Expiration time for consent */
  expires_at?: string;
  /** Remaining daily budget */
  remaining_daily?: number;
  /** Remaining per-transaction limit */
  remaining_tx?: number;
  /** Approval URL for consent */
  approve_url?: string;
  /** Chain that caused the error */
  chain?: string;
  /** Scope that caused the error */
  scope?: string;
  /** Additional context */
  [key: string]: unknown;
}

/**
 * Standard error class for DCP Client SDK.
 * Provides consistent error handling across all transports.
 */
export class DcpError extends Error {
  public readonly code: DcpErrorCode;
  public readonly action: DcpErrorAction;
  public readonly details: DcpErrorDetails;

  constructor(code: DcpErrorCode, message: string, details: DcpErrorDetails = {}) {
    super(message);
    this.name = 'DcpError';
    this.code = code;
    this.action = ERROR_ACTION_MAP[code];
    this.details = details;

    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, DcpError);
    }
  }

  /**
   * Serialize error to JSON format per protocol spec A6
   */
  toJSON(): {
    ok: false;
    error: {
      code: DcpErrorCode;
      message: string;
      action: DcpErrorAction;
      details?: DcpErrorDetails;
    };
  } {
    return {
      ok: false,
      error: {
        code: this.code,
        message: this.message,
        action: this.action,
        details: Object.keys(this.details).length > 0 ? this.details : undefined,
      },
    };
  }

  /**
   * Check if this is a consent-required error
   */
  isConsentRequired(): boolean {
    return this.code === 'CONSENT_REQUIRED';
  }

  /**
   * Check if this is a vault offline/locked error
   */
  isVaultUnavailable(): boolean {
    return this.code === 'VAULT_OFFLINE' || this.code === 'VAULT_LOCKED';
  }

  /**
   * Check if this is a budget exceeded error
   */
  isBudgetExceeded(): boolean {
    return this.code === 'BUDGET_EXCEEDED_TX' || this.code === 'BUDGET_EXCEEDED_DAILY';
  }

  /**
   * Check if this error is retryable
   */
  isRetryable(): boolean {
    return this.action === 'retry';
  }
}

// ============================================================================
// Error Factory Functions
// ============================================================================

/**
 * Create a VAULT_OFFLINE error
 */
export function vaultOffline(message = 'DCP vault is not running'): DcpError {
  return new DcpError('VAULT_OFFLINE', message);
}

/**
 * Create a VAULT_LOCKED error
 */
export function vaultLocked(message = 'DCP vault is locked'): DcpError {
  return new DcpError('VAULT_LOCKED', message, {
    approve_url: 'http://127.0.0.1:8420',
  });
}

/**
 * Create a CONSENT_REQUIRED error
 */
export function consentRequired(
  consentId: string,
  expiresAt: string,
  message = 'User consent required'
): DcpError {
  return new DcpError('CONSENT_REQUIRED', message, {
    consent_id: consentId,
    expires_at: expiresAt,
    approve_url: 'http://127.0.0.1:8420',
  });
}

/**
 * Create a RELAY_UNAVAILABLE error
 */
export function relayUnavailable(message = 'Relay server is unavailable'): DcpError {
  return new DcpError('RELAY_UNAVAILABLE', message);
}

/**
 * Create a RELAY_TIMEOUT error
 */
export function relayTimeout(message = 'Relay request timed out'): DcpError {
  return new DcpError('RELAY_TIMEOUT', message);
}

/**
 * Create an INVALID_CONFIG error
 */
export function invalidConfig(message: string): DcpError {
  return new DcpError('INVALID_CONFIG', message);
}

/**
 * Parse an error response from the server into a DcpError
 */
export function parseErrorResponse(response: unknown): DcpError {
  if (response && typeof response === 'object') {
    const err = response as Record<string, unknown>;

    // Handle { error: { code, message, ... } } format
    if (err.error && typeof err.error === 'object') {
      const errorObj = err.error as Record<string, unknown>;
      const code = (errorObj.code as DcpErrorCode) || 'INTERNAL_ERROR';
      const message = (errorObj.message as string) || 'Unknown error';
      const details: DcpErrorDetails = {};

      // Extract known details
      if (errorObj.consent_id) details.consent_id = errorObj.consent_id as string;
      if (errorObj.expires_at) details.expires_at = errorObj.expires_at as string;
      if (errorObj.remaining_daily !== undefined)
        details.remaining_daily = errorObj.remaining_daily as number;
      if (errorObj.remaining_tx !== undefined)
        details.remaining_tx = errorObj.remaining_tx as number;
      if (errorObj.details && typeof errorObj.details === 'object') {
        Object.assign(details, errorObj.details);
      }

      return new DcpError(code, message, details);
    }

    // Handle { requires_consent: true, consent_id, ... } format
    if (err.requires_consent === true && err.consent_id) {
      return new DcpError('CONSENT_REQUIRED', (err.message as string) || 'User consent required', {
        consent_id: err.consent_id as string,
        expires_at: err.expires_at as string,
        approve_url: 'http://127.0.0.1:8420',
      });
    }
  }

  return new DcpError('INTERNAL_ERROR', 'Unknown error occurred');
}
