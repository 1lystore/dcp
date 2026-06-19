/**
 * Funds-critical swap + idempotency validators. These run on every swap and guard
 * real money, so they're tested exhaustively for both pass and reject paths.
 */

import { describe, it, expect } from 'vitest';
import { Keypair, PublicKey, Transaction } from '@solana/web3.js';
import {
  validateSwapQuote,
  validateSwapTransaction,
  idempotencyIntentMatches,
  DEFAULT_SWAP_ALLOWED_PROGRAMS,
  DEFAULT_JUPITER_PROGRAM_IDS,
  type SwapQuote,
  type SwapQuoteIntent,
} from '../src/index.js';

const WSOL = 'So11111111111111111111111111111111111111112';
const OUT_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';
const JUP = DEFAULT_JUPITER_PROGRAM_IDS[0];
const SYSTEM = '11111111111111111111111111111111';

const intent: SwapQuoteIntent = { inputMint: WSOL, outputMint: OUT_MINT, rawInAmount: '1000000', slippageBps: 50 };
const goodQuote: SwapQuote = { inputMint: WSOL, outputMint: OUT_MINT, inAmount: '1000000', outAmount: '500', slippageBps: 50 };

describe('validateSwapQuote', () => {
  it('accepts a quote that matches the requested intent', () => {
    expect(validateSwapQuote(goodQuote, intent)).toEqual({ ok: true });
  });

  it('rejects a mismatched output mint', () => {
    const r = validateSwapQuote({ ...goodQuote, outputMint: Keypair.generate().publicKey.toBase58() }, intent);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/requested tokens/i);
  });

  it('rejects a mismatched input mint', () => {
    expect(validateSwapQuote({ ...goodQuote, inputMint: OUT_MINT }, intent).ok).toBe(false);
  });

  it('rejects a tampered input amount', () => {
    const r = validateSwapQuote({ ...goodQuote, inAmount: '999999' }, intent);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/input amount/i);
  });

  it('rejects slippage wider than authorized', () => {
    const r = validateSwapQuote({ ...goodQuote, slippageBps: 100 }, intent);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/slippage/i);
  });

  it('accepts slippage tighter than authorized', () => {
    expect(validateSwapQuote({ ...goodQuote, slippageBps: 10 }, intent).ok).toBe(true);
  });

  it('rejects a zero / missing output amount', () => {
    expect(validateSwapQuote({ ...goodQuote, outAmount: '0' }, intent).ok).toBe(false);
    expect(validateSwapQuote({ ...goodQuote, outAmount: undefined }, intent).ok).toBe(false);
  });
});

describe('validateSwapTransaction', () => {
  const allowed = [...DEFAULT_SWAP_ALLOWED_PROGRAMS, ...DEFAULT_JUPITER_PROGRAM_IDS];
  const cfg = { owner: OWNER, jupiterProgramIds: DEFAULT_JUPITER_PROGRAM_IDS, allowedPrograms: allowed };

  function tx(feePayer: string, programIds: string[]): string {
    const t = new Transaction({ feePayer: new PublicKey(feePayer), recentBlockhash: BLOCKHASH });
    for (const pid of programIds) t.add({ keys: [], programId: new PublicKey(pid), data: Buffer.from([]) });
    return t.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
  }

  it('accepts a single-signer Jupiter route with only allow-listed programs', () => {
    expect(validateSwapTransaction(tx(OWNER, [JUP, SYSTEM]), cfg)).toEqual({ ok: true });
  });

  it('rejects when the fee-payer is not the wallet', () => {
    const other = Keypair.generate().publicKey.toBase58();
    const r = validateSwapTransaction(tx(other, [JUP]), cfg);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/fee-payer/i);
  });

  it('rejects an unexpected program', () => {
    const rogue = Keypair.generate().publicKey.toBase58();
    const r = validateSwapTransaction(tx(OWNER, [JUP, rogue]), cfg);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unexpected program/i);
  });

  it('rejects a tx that is not a Jupiter route', () => {
    const r = validateSwapTransaction(tx(OWNER, [SYSTEM]), cfg);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/not a recognized Jupiter route/i);
  });

  it('rejects an undecodable blob', () => {
    const r = validateSwapTransaction(Buffer.from('garbage').toString('base64'), cfg);
    expect(r.ok).toBe(false);
  });
});

describe('idempotencyIntentMatches', () => {
  const base = { operation: 'transfer', destination: 'DEST', currency: 'SOL', amount: 0.5 };

  it('matches an identical transfer intent', () => {
    expect(idempotencyIntentMatches(base, { ...base })).toBe(true);
  });

  it('does not match a different destination', () => {
    expect(idempotencyIntentMatches(base, { ...base, destination: 'OTHER' })).toBe(false);
  });

  it('does not match a different amount', () => {
    expect(idempotencyIntentMatches(base, { ...base, amount: 0.6 })).toBe(false);
  });

  it('does not match a different currency', () => {
    expect(idempotencyIntentMatches(base, { ...base, currency: 'USDC' })).toBe(false);
  });

  it('does not match a different operation', () => {
    expect(idempotencyIntentMatches(base, { ...base, operation: 'swap' })).toBe(false);
  });

  it('tolerates float representation noise on equal amounts', () => {
    expect(idempotencyIntentMatches({ ...base, amount: 0.1 + 0.2 }, { ...base, amount: 0.3 })).toBe(true);
  });

  it('treats null and undefined destination as equal', () => {
    expect(idempotencyIntentMatches({ ...base, destination: null }, { ...base, destination: undefined })).toBe(true);
  });
});
