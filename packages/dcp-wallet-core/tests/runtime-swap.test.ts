/**
 * Swap workflow tests with fake adapters. Proves quote-intent binding, tx program
 * validation, idempotency, and approval gating all fire before signing/submitting.
 */

import { describe, it, expect } from 'vitest';
import { PublicKey, Transaction } from '@solana/web3.js';
import {
  DEFAULT_SWAP_ALLOWED_PROGRAMS,
  DEFAULT_JUPITER_PROGRAM_IDS,
  executeSwap,
  type SwapQuote,
} from '../src/index.js';
import type { SwapPorts, PriorSpend } from '../src/index.js';

const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
const WSOL = 'So11111111111111111111111111111111111111112';
const OUT_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';
const JUP = DEFAULT_JUPITER_PROGRAM_IDS[0];
const SYSTEM = '11111111111111111111111111111111';

function swapTxWith(feePayer: string, programIds: string[]): string {
  const t = new Transaction({ feePayer: new PublicKey(feePayer), recentBlockhash: BLOCKHASH });
  for (const pid of programIds) t.add({ keys: [], programId: new PublicKey(pid), data: Buffer.from([]) });
  return t.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
}

const rawIn = String(Math.round(0.001 * 1e9));
const goodQuote: SwapQuote = { inputMint: WSOL, outputMint: OUT_MINT, inAmount: rawIn, outAmount: '500', slippageBps: 50 };

interface Calls { signed: number; submitted: number; recorded: number; committed: number; approvalsAsked: number; }

function makePorts(opts: {
  quote?: SwapQuote;
  swapTx?: string;
  prior?: PriorSpend | null;
  withinDailyLimit?: boolean;
  needsApproval?: boolean;
  approve?: boolean;
  submitStatus?: string;
}): { ports: SwapPorts; calls: Calls } {
  const calls: Calls = { signed: 0, submitted: 0, recorded: 0, committed: 0, approvalsAsked: 0 };
  const ports: SwapPorts = {
    signer: { address: OWNER, async sign(tx) { calls.signed++; return tx; } },
    rpc: {
      async getLatestBlockhash() { return BLOCKHASH; },
      async accountExists() { return true; },
      async submit() { calls.submitted++; return { signature: 'SIG_NEW', status: opts.submitStatus ?? 'confirmed' }; },
    },
    swapProvider: {
      async quote() { return opts.quote ?? goodQuote; },
      async buildSwapTx() { return opts.swapTx ?? swapTxWith(OWNER, [JUP, SYSTEM]); },
    },
    approval: { async requestApproval() { calls.approvalsAsked++; return opts.approve ?? true; } },
    budget: {
      async check() { return { withinDailyLimit: opts.withinDailyLimit ?? true, needsApproval: opts.needsApproval ?? false }; },
      async record() { calls.recorded++; },
    },
    idempotency: { async get() { return opts.prior ?? null; }, async commit() { calls.committed++; } },
    activity: { async record() {} },
    config: {
      jupiterProgramIds: () => [...DEFAULT_JUPITER_PROGRAM_IDS],
      swapAllowedPrograms: () => [...DEFAULT_SWAP_ALLOWED_PROGRAMS, ...DEFAULT_JUPITER_PROGRAM_IDS],
    },
  };
  return { ports, calls };
}

const req = {
  chain: 'solana' as const,
  fromToken: { mint: WSOL, decimals: 9, currency: 'SOL' },
  toToken: { mint: OUT_MINT, decimals: 6, currency: 'USDC' },
  amount: 0.001,
  slippageBps: 50,
  idempotencyKey: 's1',
};

describe('executeSwap', () => {
  it('happy path: quote, validate, build, validate-tx, sign, submit, debit + commit', async () => {
    const { ports, calls } = makePorts({});
    const res = await executeSwap(req, ports);
    expect(res.signature).toBe('SIG_NEW');
    expect(res.outAmount).toBe('500');
    expect(calls).toMatchObject({ signed: 1, submitted: 1, recorded: 1, committed: 1 });
  });

  it('does NOT debit budget or commit idempotency on a failed submit', async () => {
    const { ports, calls } = makePorts({ submitStatus: 'failed' });
    const res = await executeSwap(req, ports);
    expect(res.status).toBe('failed');
    expect(calls.recorded).toBe(0);
    expect(calls.committed).toBe(0);
  });

  it('rejects a quote whose output mint does not match (never signs)', async () => {
    const { ports, calls } = makePorts({ quote: { ...goodQuote, outputMint: SYSTEM } });
    await expect(executeSwap(req, ports)).rejects.toMatchObject({ code: 'INVALID_CHAIN' });
    expect(calls.signed).toBe(0);
  });

  it('rejects a quote with a tampered input amount (never signs)', async () => {
    const { ports, calls } = makePorts({ quote: { ...goodQuote, inAmount: '999' } });
    await expect(executeSwap(req, ports)).rejects.toMatchObject({ code: 'INVALID_CHAIN' });
    expect(calls.signed).toBe(0);
  });

  it('rejects a swap tx that invokes an unexpected program (never signs)', async () => {
    const rogue = '11111111111111111111111111111112';
    const { ports, calls } = makePorts({ swapTx: swapTxWith(OWNER, [JUP, rogue]) });
    await expect(executeSwap(req, ports)).rejects.toMatchObject({ code: 'INVALID_CHAIN' });
    expect(calls.signed).toBe(0);
  });

  it('rejects a tx that is not a Jupiter route (never signs)', async () => {
    const { ports, calls } = makePorts({ swapTx: swapTxWith(OWNER, [SYSTEM]) });
    await expect(executeSwap(req, ports)).rejects.toMatchObject({ code: 'INVALID_CHAIN' });
    expect(calls.signed).toBe(0);
  });

  it('replays a prior identical swap without signing', async () => {
    const prior: PriorSpend = { operation: 'swap', destination: OUT_MINT, currency: 'SOL', amount: 0.001, signature: 'SIG_OLD' };
    const { ports, calls } = makePorts({ prior });
    const res = await executeSwap(req, ports);
    expect(res).toMatchObject({ signature: 'SIG_OLD', idempotentReplay: true });
    expect(calls.signed).toBe(0);
  });

  it('rejects key reuse for a different swap', async () => {
    const prior: PriorSpend = { operation: 'swap', destination: WSOL, currency: 'SOL', amount: 0.001, signature: 'SIG_OLD' };
    const { ports } = makePorts({ prior });
    await expect(executeSwap(req, ports)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
  });

  it('aborts a swap the user denies (never signs)', async () => {
    const { ports, calls } = makePorts({ needsApproval: true, approve: false });
    await expect(executeSwap(req, ports)).rejects.toMatchObject({ code: 'CONSENT_DENIED' });
    expect(calls.signed).toBe(0);
  });
});
