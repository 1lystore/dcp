/**
 * Swap + spend safety validators — the funds-critical "wallet brain" checks.
 *
 * PURE functions: given a quote, a built transaction, or two spend intents, they
 * return a pass/fail result. No network, no env, no keys, no I/O. The vault server
 * and the mobile runtime both call these so the security checks are IDENTICAL on
 * every platform and can never drift. Network (Jupiter fetch), env (fee/config),
 * and signing live in the platform adapters, not here.
 */

import { getTransactionSigners, getTransactionProgramIds } from './solana-tx.js';

export interface ValidationResult {
  ok: boolean;
  reason?: string;
}

// ============================================================================
// Swap quote validation (bind the third-party quote to the caller's intent)
// ============================================================================

/** Subset of a Jupiter quote we make trust decisions on. */
export interface SwapQuote {
  inputMint?: string;
  outputMint?: string;
  inAmount?: string;
  outAmount?: string;
  otherAmountThreshold?: string;
  slippageBps?: number;
}

export interface SwapQuoteIntent {
  /** Mint the caller intends to spend. */
  inputMint: string;
  /** Mint the caller intends to receive. */
  outputMint: string;
  /** Exact input amount in base units (string), as requested. */
  rawInAmount: string;
  /** Max slippage the caller authorized, in bps. */
  slippageBps: number;
}

/**
 * Verify a swap quote matches EXACTLY what was requested before anything is built
 * or signed off it. Jupiter is the trusted router, but a wrong/stale/swapped quote
 * (different mints, a tampered amount, or wider slippage than authorized) must never
 * be acted on — the swap stays bounded to the caller's stated intent.
 */
export function validateSwapQuote(quote: SwapQuote, intent: SwapQuoteIntent): ValidationResult {
  if (quote.inputMint !== intent.inputMint || quote.outputMint !== intent.outputMint) {
    return { ok: false, reason: 'Swap quote does not match the requested tokens' };
  }
  if (quote.inAmount !== intent.rawInAmount) {
    return { ok: false, reason: 'Swap quote input amount does not match the request' };
  }
  if (quote.slippageBps !== undefined && quote.slippageBps > intent.slippageBps) {
    return { ok: false, reason: 'Swap quote slippage exceeds the requested limit' };
  }
  if (!quote.outAmount || BigInt(quote.outAmount) <= 0n) {
    return { ok: false, reason: 'Swap quote returned no output amount' };
  }
  return { ok: true };
}

// ============================================================================
// Swap transaction validation (bound what a Jupiter-built tx may do)
// ============================================================================

/** Standard Solana programs a Jupiter swap route legitimately invokes. */
export const DEFAULT_SWAP_ALLOWED_PROGRAMS: readonly string[] = [
  '11111111111111111111111111111111', // System
  'ComputeBudget111111111111111111111111111111', // Compute Budget
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', // SPL Token
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', // Token-2022
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', // Associated Token Account
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', // Memo
];

/** Jupiter aggregator program ids (v6). Operators may extend via config. */
export const DEFAULT_JUPITER_PROGRAM_IDS: readonly string[] = [
  'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',
];

/**
 * Validate a third-party-built (Jupiter) swap transaction before signing it:
 *  - the wallet must be the fee-payer AND the only required signer (no hidden
 *    co-signer can drain), and
 *  - the tx must invoke the Jupiter aggregator and ONLY allow-listed programs.
 *
 * Program ids always live in a tx's static keys (Solana forbids loading a program
 * via an address lookup table), so a lookup table cannot smuggle a program past
 * this check. Guards against a compromised/spoofed Jupiter response.
 */
export function validateSwapTransaction(
  swapTxB64: string,
  params: { owner: string; jupiterProgramIds: readonly string[]; allowedPrograms: readonly string[] }
): ValidationResult {
  let feePayer: string;
  let numRequiredSignatures: number;
  try {
    ({ feePayer, numRequiredSignatures } = getTransactionSigners(swapTxB64));
  } catch {
    // Undecodable → fail closed; never sign something we can't inspect.
    return { ok: false, reason: 'Swap transaction could not be decoded for validation' };
  }
  if (feePayer !== params.owner) {
    return { ok: false, reason: 'Swap transaction fee-payer is not the wallet' };
  }
  if (numRequiredSignatures !== 1) {
    return { ok: false, reason: 'Swap transaction requires unexpected additional signers' };
  }

  const { programIds, resolvable } = getTransactionProgramIds(swapTxB64);
  if (!resolvable) {
    return { ok: false, reason: 'Swap transaction could not be decoded for validation' };
  }
  const allowed = new Set(params.allowedPrograms);
  const unexpected = programIds.find((p) => !allowed.has(p));
  if (unexpected) {
    return { ok: false, reason: `Swap transaction invokes an unexpected program: ${unexpected}` };
  }
  if (!programIds.some((p) => params.jupiterProgramIds.includes(p))) {
    return { ok: false, reason: 'Swap transaction is not a recognized Jupiter route' };
  }
  return { ok: true };
}

// ============================================================================
// Idempotency intent rule
// ============================================================================

/** The shape of a spend used to compare idempotency intent. */
export interface SpendIntent {
  operation: string;
  /** transfer: recipient; swap: output mint. */
  destination?: string | null;
  currency: string;
  amount: number;
}

/**
 * True when a prior recorded spend represents the SAME intent as the current
 * request — so reusing an idempotency key replays the prior result. False means
 * the key is being reused for a DIFFERENT operation/recipient/amount/token and the
 * caller MUST reject it rather than blindly replay an unrelated signature.
 */
export function idempotencyIntentMatches(prior: SpendIntent, current: SpendIntent): boolean {
  return (
    prior.operation === current.operation &&
    (prior.destination ?? null) === (current.destination ?? null) &&
    prior.currency === current.currency &&
    Math.abs(prior.amount - current.amount) <= 1e-9 * Math.max(1, Math.abs(current.amount))
  );
}
