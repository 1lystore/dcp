/**
 * Jupiter swap integration — quote + build, over `fetch`. RN/Node/browser safe.
 *
 * The fee (rate + account) and API base are INJECTED via `JupiterConfig` — never
 * read from env here — so the OSS code carries no business config. The fee is
 * all-or-nothing: applied only when both a positive rate AND an account are set.
 */

import { VaultError } from './errors.js';
import type { SwapQuote } from './swap.js';

/** Public default endpoint (free tier). Operators may override via config. */
export const DEFAULT_JUPITER_API = 'https://lite-api.jup.ag/swap/v1';

export interface JupiterConfig {
  /** Base URL, e.g. https://lite-api.jup.ag/swap/v1 */
  apiBase: string;
  /** Platform fee in bps (0/undefined = no fee). */
  feeBps?: number;
  /** Token account that collects the fee. Required for any fee to apply. */
  feeAccount?: string;
}

function feeEnabled(cfg: JupiterConfig): boolean {
  return (cfg.feeBps ?? 0) > 0 && !!cfg.feeAccount;
}

function timeoutSignal(timeoutMs: number): AbortSignal | undefined {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return AbortSignal.timeout(timeoutMs);
  }
  if (typeof AbortController === 'undefined') {
    return undefined;
  }
  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

/** Retry transient fetch failures (rate limits / blips) with a short backoff. */
async function fetchWithRetry(input: string, init: RequestInit, attempts = 3, delayMs = 400): Promise<Response> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fetch(input, init);
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw lastErr;
}

export async function jupiterQuote(
  cfg: JupiterConfig,
  args: { inputMint: string; outputMint: string; amountBaseUnits: string; slippageBps: number }
): Promise<SwapQuote> {
  let url = `${cfg.apiBase}/quote?inputMint=${args.inputMint}&outputMint=${args.outputMint}&amount=${args.amountBaseUnits}&slippageBps=${args.slippageBps}`;
  if (feeEnabled(cfg)) url += `&platformFeeBps=${cfg.feeBps}`;
  const res = await fetchWithRetry(url, { signal: timeoutSignal(15_000) });
  if (!res.ok) throw new VaultError('INTERNAL_ERROR', `Jupiter quote failed (${res.status})`);
  return res.json() as Promise<SwapQuote>;
}

export async function jupiterBuildSwapTx(
  cfg: JupiterConfig,
  quote: unknown,
  userPublicKey: string
): Promise<string> {
  const body: Record<string, unknown> = {
    quoteResponse: quote,
    userPublicKey,
    wrapAndUnwrapSol: true,
    dynamicComputeUnitLimit: true,
    prioritizationFeeLamports: 'auto',
  };
  if (feeEnabled(cfg)) body.feeAccount = cfg.feeAccount;
  const res = await fetch(`${cfg.apiBase}/swap`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: timeoutSignal(20_000),
  });
  if (!res.ok) throw new VaultError('INTERNAL_ERROR', `Jupiter swap build failed (${res.status})`);
  const data = (await res.json()) as { swapTransaction?: string };
  if (!data.swapTransaction) throw new VaultError('INTERNAL_ERROR', 'Jupiter returned no swap transaction');
  return data.swapTransaction;
}
