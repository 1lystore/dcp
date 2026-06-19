/**
 * Transfer workflow tests with fake adapters. These prove the security gates
 * (idempotency, budget, approval, verify-after-sign) fire BEFORE any signing or
 * submission — i.e. the runtime never moves funds it shouldn't.
 */

import { describe, it, expect } from 'vitest';
import { buildSolanaTransferTx, executeTransfer } from '../src/index.js';
import type { TransferPorts, PriorSpend } from '../src/index.js';

const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
const TO = '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S';
const OTHER = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';
const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

interface Calls {
  signed: number;
  submitted: number;
  recorded: number;
  committed: number;
  approvalsAsked: number;
}

function makePorts(opts: {
  prior?: PriorSpend | null;
  withinDailyLimit?: boolean;
  needsApproval?: boolean;
  approve?: boolean;
  /** Status returned by submit (default 'confirmed'; use 'failed' to test the failure path). */
  submitStatus?: string;
  /** A signer that returns a DIFFERENT tx than asked (simulates a bad/compromised signer). */
  tamperTo?: string;
}): { ports: TransferPorts; calls: Calls } {
  const calls: Calls = { signed: 0, submitted: 0, recorded: 0, committed: 0, approvalsAsked: 0 };
  const ports: TransferPorts = {
    signer: {
      address: OWNER,
      async sign(unsignedTxB64) {
        calls.signed++;
        if (opts.tamperTo) {
          // Return a validly-built tx to a DIFFERENT destination than was requested.
          return buildSolanaTransferTx(OWNER, opts.tamperTo, 0.1, BLOCKHASH);
        }
        return unsignedTxB64; // signing doesn't change the message
      },
    },
    rpc: {
      async getLatestBlockhash() { return BLOCKHASH; },
      async accountExists() { return true; },
      async submit() { calls.submitted++; return { signature: 'SIG_NEW', status: opts.submitStatus ?? 'confirmed' }; },
    },
    approval: {
      async requestApproval() { calls.approvalsAsked++; return opts.approve ?? true; },
    },
    budget: {
      async check() { return { withinDailyLimit: opts.withinDailyLimit ?? true, needsApproval: opts.needsApproval ?? false }; },
      async record() { calls.recorded++; },
    },
    idempotency: {
      async get() { return opts.prior ?? null; },
      async commit() { calls.committed++; },
    },
    activity: {
      async record() {},
    },
  };
  return { ports, calls };
}

const req = { chain: 'solana' as const, to: TO, amount: 0.1, currency: 'SOL', idempotencyKey: 'k1' };

describe('executeTransfer', () => {
  it('happy path: builds, signs, verifies, submits, debits budget + commits idempotency', async () => {
    const { ports, calls } = makePorts({});
    const res = await executeTransfer(req, ports);
    expect(res.signature).toBe('SIG_NEW');
    expect(res.status).toBe('confirmed');
    expect(calls).toMatchObject({ signed: 1, submitted: 1, recorded: 1, committed: 1 });
  });

  it('does NOT debit budget or commit idempotency on a failed submit', async () => {
    const { ports, calls } = makePorts({ submitStatus: 'failed' });
    const res = await executeTransfer(req, ports);
    expect(res.status).toBe('failed');
    expect(calls.submitted).toBe(1);
    expect(calls.recorded).toBe(0);  // budget not debited
    expect(calls.committed).toBe(0); // idempotency key stays free to retry
  });

  it('replays a prior identical transfer WITHOUT signing again', async () => {
    const prior: PriorSpend = { operation: 'transfer', destination: TO, currency: 'SOL', amount: 0.1, signature: 'SIG_OLD' };
    const { ports, calls } = makePorts({ prior });
    const res = await executeTransfer(req, ports);
    expect(res).toMatchObject({ signature: 'SIG_OLD', idempotentReplay: true });
    expect(calls.signed).toBe(0);
    expect(calls.submitted).toBe(0);
  });

  it('rejects the same key reused for a DIFFERENT transfer (no signing)', async () => {
    const prior: PriorSpend = { operation: 'transfer', destination: OTHER, currency: 'SOL', amount: 0.1, signature: 'SIG_OLD' };
    const { ports, calls } = makePorts({ prior });
    await expect(executeTransfer(req, ports)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
    expect(calls.signed).toBe(0);
  });

  it('blocks when over the daily budget (never signs)', async () => {
    const { ports, calls } = makePorts({ withinDailyLimit: false });
    await expect(executeTransfer(req, ports)).rejects.toMatchObject({ code: 'BUDGET_EXCEEDED_DAILY' });
    expect(calls.signed).toBe(0);
    expect(calls.submitted).toBe(0);
  });

  it('requires approval and aborts if denied (never signs)', async () => {
    const { ports, calls } = makePorts({ needsApproval: true, approve: false });
    await expect(executeTransfer(req, ports)).rejects.toMatchObject({ code: 'CONSENT_DENIED' });
    expect(calls.approvalsAsked).toBe(1);
    expect(calls.signed).toBe(0);
  });

  it('signs after approval is granted', async () => {
    const { ports, calls } = makePorts({ needsApproval: true, approve: true });
    await executeTransfer(req, ports);
    expect(calls.approvalsAsked).toBe(1);
    expect(calls.submitted).toBe(1);
  });

  it('catches a compromised signer that swaps the destination (never submits)', async () => {
    const { ports, calls } = makePorts({ tamperTo: OTHER });
    await expect(executeTransfer(req, ports)).rejects.toMatchObject({ code: 'INVALID_TX' });
    expect(calls.signed).toBe(1);     // it did sign…
    expect(calls.submitted).toBe(0);  // …but verify-after-sign blocked the broadcast
  });
});
