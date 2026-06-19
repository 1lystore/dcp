import { describe, it, expect } from 'vitest';
import {
  resolveToken,
  resolveSwapToken,
  DEFAULT_KNOWN_TOKENS,
  WSOL_MINT,
  VaultError,
} from '../src/index.js';

const REG = DEFAULT_KNOWN_TOKENS;
const RANDOM_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

describe('resolveToken (transfer)', () => {
  it('prefers an explicit mint + decimals', () => {
    expect(resolveToken('WHATEVER', REG, RANDOM_MINT, 9)).toEqual({ mint: RANDOM_MINT, decimals: 9 });
  });
  it('resolves a known symbol from the registry', () => {
    expect(resolveToken('usdc', REG)).toEqual(REG.USDC);
  });
  it('throws on an unknown token with no explicit mint', () => {
    expect(() => resolveToken('NOPE', REG)).toThrowError(VaultError);
  });
  it('honors an overridden registry (e.g. devnet mint)', () => {
    const custom = { USDC: { mint: 'DevnetUsdcMint11111111111111111111111111111', decimals: 6 } };
    expect(resolveToken('USDC', custom).mint).toBe('DevnetUsdcMint11111111111111111111111111111');
  });
});

describe('resolveSwapToken (swap)', () => {
  it('maps SOL to wrapped SOL', () => {
    expect(resolveSwapToken('SOL', REG)).toEqual({ mint: WSOL_MINT, decimals: 9, currency: 'SOL' });
  });
  it('resolves a known symbol', () => {
    expect(resolveSwapToken('USDC', REG)).toEqual({ mint: REG.USDC.mint, decimals: 6, currency: 'USDC' });
  });
  it('accepts an explicit mint + decimals', () => {
    const r = resolveSwapToken(RANDOM_MINT, REG, 6);
    expect(r.mint).toBe(RANDOM_MINT);
    expect(r.decimals).toBe(6);
  });
  it('throws on an unknown token with no decimals', () => {
    expect(() => resolveSwapToken('NOPE', REG)).toThrowError(VaultError);
  });
});
