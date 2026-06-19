/**
 * Shared protocol error type.
 *
 * Lives in wallet-core (the foundational leaf package) so that EVERY package —
 * wallet-core, core, vault, agent, and the private runtimes — throws and catches
 * the SAME `VaultError` class. A single class keeps `instanceof VaultError`
 * reliable across package boundaries (a second copy would silently break error
 * handling). `@dcprotocol/core` re-exports these for backward compatibility.
 */

export type VaultErrorCode =
  | 'VAULT_NOT_INITIALIZED'
  | 'VAULT_LOCKED'
  | 'CONSENT_REQUIRED'
  | 'CONSENT_DENIED'
  | 'CONSENT_EXPIRED'
  | 'CONSENT_TIMEOUT'
  | 'CONSENT_NOT_FOUND'
  | 'SCOPE_VIOLATION'
  | 'BUDGET_EXCEEDED_TX'
  | 'BUDGET_EXCEEDED_DAILY'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_REVOKED'
  | 'INVALID_CHAIN'
  | 'INVALID_TX'
  | 'INVALID_SCHEMA'
  | 'IDEMPOTENCY_CONFLICT'
  | 'RATE_LIMITED'
  | 'RECORD_NOT_FOUND'
  | 'INTERNAL_ERROR'
  | 'VALIDATION_ERROR'
  | 'UNAUTHORIZED'
  | 'SERVICE_NOT_TRUSTED'
  | 'SERVICE_NOT_FOUND'
  | 'SERVICE_ALREADY_TRUSTED'
  | 'INVALID_SERVICE_SIGNATURE'
  | 'SERVICE_SCOPE_VIOLATION'
  | 'INVALID_PUBLIC_KEY';

export class VaultError extends Error {
  constructor(
    public code: VaultErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'VaultError';
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
      },
    };
  }
}
