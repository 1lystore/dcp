/**
 * Approval result handling — supports BOTH approval styles:
 *
 *  - "approve-now" (mobile): the ApprovalUI awaits a PIN/biometric and resolves a
 *    boolean (or { approved }). Approved → continue; denied → CONSENT_DENIED.
 *  - "approve-later / retry" (desktop + agents): the ApprovalUI creates a pending
 *    consent and resolves { deferred: true, consentId, ... }. The runner then stops
 *    and throws `ConsentRequiredError`, which the host maps to its `requires_consent`
 *    response so the human can approve out-of-band (desktop popup / Telegram /
 *    synced phone) and the agent retries.
 *
 * Backward-compatible: an adapter that returns a bare boolean keeps working
 * unchanged (that's the mobile path), so this never disturbs existing callers.
 */

export interface ConsentDeferred {
  deferred: true;
  consentId: string;
  expiresAt: string;
  reason?: string;
  message: string;
}

export type ApprovalOutcome = { approved: boolean; deferred?: false } | ConsentDeferred;

/** Thrown when approval is deferred to an out-of-band consent flow (not an error —
 *  flow control). Hosts catch it and return their `requires_consent` response. */
export class ConsentRequiredError extends Error {
  readonly kind = 'consent-required';
  readonly consentId: string;
  readonly expiresAt: string;
  readonly reason?: string;
  constructor(consent: { consentId: string; expiresAt: string; reason?: string; message: string }) {
    super(consent.message);
    this.name = 'ConsentRequiredError';
    this.consentId = consent.consentId;
    this.expiresAt = consent.expiresAt;
    this.reason = consent.reason;
  }
}

/** Normalize whatever an ApprovalUI returned into a single shape. */
export function normalizeApproval(result: boolean | ApprovalOutcome): ApprovalOutcome {
  if (typeof result === 'boolean') return { approved: result };
  if ('deferred' in result && result.deferred) return result;
  return { approved: result.approved };
}
