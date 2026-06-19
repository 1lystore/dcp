/**
 * The runner's two approval styles:
 *  - "approve-now" (boolean) — mobile PIN/biometric, unchanged.
 *  - "approve-later" (deferred) — desktop/agents: the runner stops and throws
 *    ConsentRequiredError instead of signing, so the host returns requires_consent.
 */

import { describe, it, expect } from 'vitest';
import { buildSolanaTransferTx, executeTransfer, ConsentRequiredError } from '../src/index.js';
import type { TransferPorts } from '../src/index.js';

const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
const TO = '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S';
const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

function ports(approvalResult: any): { ports: TransferPorts; calls: { signed: number; submitted: number } } {
  const calls = { signed: 0, submitted: 0 };
  return {
    calls,
    ports: {
      signer: { address: OWNER, async sign(tx) { calls.signed++; return tx; } },
      rpc: {
        async getLatestBlockhash() { return BLOCKHASH; },
        async accountExists() { return true; },
        async submit() { calls.submitted++; return { signature: 'SIG', status: 'confirmed' }; },
      },
      approval: { async requestApproval() { return approvalResult; } },
      budget: { async check() { return { withinDailyLimit: true, needsApproval: true }; }, async record() {} },
      idempotency: { async get() { return null; }, async commit() {} },
      activity: { async record() {} },
    },
  };
}

const req = { chain: 'solana' as const, to: TO, amount: 0.1, currency: 'SOL', idempotencyKey: 'k' };

describe('runner approval styles', () => {
  it('approve-now: boolean true → signs + submits', async () => {
    const { ports: p, calls } = ports(true);
    await executeTransfer(req, p);
    expect(calls.submitted).toBe(1);
  });

  it('approve-now: boolean false → CONSENT_DENIED, never signs', async () => {
    const { ports: p, calls } = ports(false);
    await expect(executeTransfer(req, p)).rejects.toMatchObject({ code: 'CONSENT_DENIED' });
    expect(calls.signed).toBe(0);
  });

  it('object { approved: true } → signs', async () => {
    const { ports: p, calls } = ports({ approved: true });
    await executeTransfer(req, p);
    expect(calls.submitted).toBe(1);
  });

  it('deferred → throws ConsentRequiredError with the consent details, never signs', async () => {
    const deferred = { deferred: true, consentId: 'consent_123', expiresAt: '2026-01-01T00:00:00Z', message: 'Approve on your device' };
    const { ports: p, calls } = ports(deferred);
    await expect(executeTransfer(req, p)).rejects.toBeInstanceOf(ConsentRequiredError);
    try {
      await executeTransfer(req, p);
    } catch (e) {
      const err = e as ConsentRequiredError;
      expect(err.consentId).toBe('consent_123');
      expect(err.expiresAt).toBe('2026-01-01T00:00:00Z');
    }
    expect(calls.signed).toBe(0);
    expect(calls.submitted).toBe(0);
  });
});
