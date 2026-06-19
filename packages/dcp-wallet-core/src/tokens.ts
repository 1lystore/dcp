/**
 * SPL token registry + resolution. Pure lookups, no env, no I/O.
 *
 * The mainnet mints below are universal public constants (the same for every
 * Solana app), not business config — safe in OSS. Per-cluster overrides (e.g. a
 * devnet USDC mint) are injected by the caller via the `registry` argument, so
 * wallet-core never reads env.
 */

import { VaultError } from './errors.js';

export const WSOL_MINT = 'So11111111111111111111111111111111111111112';

export interface TokenInfo {
  mint: string;
  decimals: number;
}

export type TokenRegistry = Record<string, TokenInfo>;

/** Default mainnet registry. Callers may pass an overridden registry (e.g. devnet). */
export const DEFAULT_KNOWN_TOKENS: TokenRegistry = {
  USDC: { mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals: 6 },
  USDT: { mint: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', decimals: 6 },
  '1LY': { mint: 'Aih3sbAbu39Yn7jB2Qf4btZ5eWtDGQJH2gMfC4qdBAGS', decimals: 6 },
};

/**
 * Resolve an SPL token for a transfer: an explicit mint+decimals wins, otherwise
 * the known-token registry by currency symbol.
 */
export function resolveToken(
  currency: string,
  registry: TokenRegistry,
  explicitMint?: string,
  explicitDecimals?: number
): TokenInfo {
  if (explicitMint && explicitDecimals !== undefined) {
    return { mint: explicitMint, decimals: explicitDecimals };
  }
  const known = registry[currency.toUpperCase()];
  if (known) return known;
  throw new VaultError('INVALID_CHAIN', `Unknown token '${currency}'. Provide mint and decimals.`);
}

/**
 * Resolve a token for a swap: 'SOL' → wrapped SOL; a known symbol → its mint; an
 * explicit mint+decimals → used as-is. Returns the currency label too.
 */
export function resolveSwapToken(
  symbolOrMint: string,
  registry: TokenRegistry,
  decimals?: number
): { mint: string; decimals: number; currency: string } {
  const up = symbolOrMint.toUpperCase();
  if (up === 'SOL') return { mint: WSOL_MINT, decimals: 9, currency: 'SOL' };
  if (registry[up]) return { mint: registry[up].mint, decimals: registry[up].decimals, currency: up };
  if (decimals !== undefined) return { mint: symbolOrMint, decimals, currency: symbolOrMint.slice(0, 6) };
  throw new VaultError('INVALID_CHAIN', `Unknown swap token '${symbolOrMint}'. Provide a mint and decimals.`);
}
