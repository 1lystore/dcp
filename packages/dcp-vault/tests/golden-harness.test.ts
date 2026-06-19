/**
 * GOLDEN HARNESS — Phase 0 of the wallet-consolidation plan.
 *
 * Captures the CURRENT vault's decision behavior on the transfer/swap money path
 * as a reference oracle, BEFORE Phase 4 rewires those routes onto the shared
 * wallet-core runner. Phase 4 runs this same harness against the rewired path
 * (behind a feature flag) and asserts byte-for-byte identical records — so any
 * behavior drift in the money path is caught.
 *
 * Scope = the DECISION logic that short-circuits before on-chain submit, which is
 * where the rewrite risk concentrates and which is fully deterministic offline:
 *   - idempotency replay + conflict (transfer + swap)
 *   - swap quote/program validation rejections
 *   - budget enforcement (per-tx limit) + consent gating (approval threshold)
 *   - spend-ledger integrity: a rejected op must NEVER add a ledger row
 *
 * The on-chain behaviors (real SOL/SPL submit, ATA creation, rent edge, 20-way
 * concurrency / no-overspend, failed-submit-no-debit) are covered by the devnet
 * oracle in `devnet-transfer.test.ts` (RUN_DEVNET=1) and re-run in Phase 4.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { buildServer } from '../src/index.js';
import {
  VaultStorage,
  resetStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  createWallet,
  getStorage,
} from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Keypair, PublicKey, Transaction } from '@solana/web3.js';

const WSOL = 'So11111111111111111111111111111111111111112';
const OUT_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const JUP_V6 = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';
const SYSTEM = '11111111111111111111111111111111';

// Budget tuned so the gating decisions are deterministic. The daily cap is roomy
// (the seeded prior spends count against it — a tight daily cap would make the
// consent scenario trip BUDGET_EXCEEDED_DAILY instead). The per-tx limit + approval
// threshold are what drive the gating scenarios:
//   per-tx limit 0.0002 SOL · approval threshold 0.00005 SOL · daily 0.01 SOL
const BUDGET = {
  daily_budget: { SOL: 0.01 },
  tx_limit: { SOL: 0.0002 },
  approval_threshold: { SOL: 0.00005 },
};

/** Normalized behavior record — the thing Phase 4 diffs old-vs-new against. */
interface Record {
  statusCode: number;
  errorCode?: string;
  idempotentReplay?: boolean;
  requiresConsent?: boolean;
}

function classify(res: { statusCode: number; json: () => any }): Record {
  const body = res.json();
  if (res.statusCode === 200) {
    return {
      statusCode: 200,
      idempotentReplay: body.idempotent_replay === true || undefined,
      requiresConsent: body.requires_consent === true || undefined,
    };
  }
  return { statusCode: res.statusCode, errorCode: body?.error?.code };
}

describe('Golden harness — money-path decision oracle', () => {
  let server: FastifyInstance;
  let vaultDir: string;
  let storage: VaultStorage;
  let walletAddress: string;
  let seedSessionId: string;
  const passphrase = 'golden-passphrase-123';

  beforeAll(async () => {
    resetStorage();
    vaultDir = path.join(os.tmpdir(), `dcp-golden-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    process.env.VAULT_DIR = vaultDir;

    storage = new VaultStorage(vaultDir);
    storage.initializeSchema();
    const masterKey = deriveKeyFromMnemonic(generateRecoveryMnemonic());
    try {
      await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
      const { encrypted, info } = createWallet('solana', masterKey);
      storage.createRecord({
        scope: 'crypto.wallet.solana',
        item_type: 'WALLET_KEY',
        sensitivity: 'critical',
        data: encrypted,
        chain: 'solana',
        public_address: info.public_address,
      });
      walletAddress = info.public_address;
      // A session is needed only to satisfy the spend_events FK when SEEDING prior
      // spends. It is under a DIFFERENT agent name than the requests below, so it
      // never auto-approves them — consent/budget gating still applies to 'gh-agent'.
      const seedSession = storage.createSession('gh-seed-agent', ['crypto.wallet.solana'], 'session', new Date(Date.now() + 60 * 60 * 1000));
      seedSessionId = seedSession.id;
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    fs.writeFileSync(path.join(vaultDir, 'config.json'), JSON.stringify(BUDGET, null, 2));

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });
  });

  afterAll(async () => {
    await server.close();
    resetStorage();
    if (vaultDir && fs.existsSync(vaultDir)) fs.rmSync(vaultDir, { recursive: true, force: true });
    delete process.env.VAULT_DIR;
  });

  afterEach(() => vi.unstubAllGlobals());

  function seedSpend(op: 'transfer' | 'swap', key: string, destination: string, amount: number, currency: string, signature: string) {
    getStorage().recordSpend(seedSessionId, amount, currency, 'solana', op, 'committed', {
      destination,
      idempotencyKey: key,
      txSignature: signature,
    });
  }

  function ledgerCount(): number {
    return (getStorage() as any).db.prepare('SELECT COUNT(*) AS n FROM spend_events').get().n as number;
  }

  /** Stub Jupiter: by default a VALID quote (echoes the request) + a valid swap tx. */
  function stubJupiter(opts: { quoteOverride?: Record<string, unknown>; swapPrograms?: string[] } = {}) {
    const swapTx = (() => {
      const programs = opts.swapPrograms ?? [JUP_V6, SYSTEM];
      const tx = new Transaction({ feePayer: new PublicKey(walletAddress), recentBlockhash: 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi' });
      for (const pid of programs) tx.add({ keys: [], programId: new PublicKey(pid), data: Buffer.from([]) });
      return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
    })();
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const u = String(url);
      if (u.includes('/quote')) {
        const params = new URL(u.replace(/^[^?]*/, 'https://x' )).searchParams;
        const quote = opts.quoteOverride ?? {
          inputMint: params.get('inputMint'),
          outputMint: params.get('outputMint'),
          inAmount: params.get('amount'),
          outAmount: '1',
          slippageBps: Number(params.get('slippageBps')),
        };
        return { ok: true, status: 200, json: async () => quote };
      }
      if (u.includes('/swap')) return { ok: true, status: 200, json: async () => ({ swapTransaction: swapTx }) };
      return { ok: true, status: 200, json: async () => ({}) };
    }));
  }

  const swap = (amount: number, key: string) => ({
    chain: 'solana', from_token: 'SOL', to_token: OUT_MINT, to_decimals: 6,
    amount, slippage_bps: 50, agent_name: 'gh-agent', idempotency_key: key,
  });

  // ── Transfer idempotency (pre-network) ──────────────────────────────────────
  it('GOLDEN transfer/idempotent-replay → replays prior signature', async () => {
    const dest = Keypair.generate().publicKey.toBase58();
    seedSpend('transfer', 'g-t-replay', dest, 0.00001, 'SOL', 'SIG_T_REPLAY');
    const res = await server.inject({ method: 'POST', url: '/v1/vault/transfer',
      payload: { chain: 'solana', to: dest, amount: 0.00001, currency: 'SOL', agent_name: 'gh-agent', idempotency_key: 'g-t-replay' } });
    expect(classify(res)).toEqual({ statusCode: 200, idempotentReplay: true });
    expect(res.json().signature).toBe('SIG_T_REPLAY');
  });

  it('GOLDEN transfer/idempotency-conflict → rejects key reused for a different transfer', async () => {
    seedSpend('transfer', 'g-t-conflict', Keypair.generate().publicKey.toBase58(), 0.00001, 'SOL', 'SIG_T_C');
    const before = ledgerCount();
    const res = await server.inject({ method: 'POST', url: '/v1/vault/transfer',
      payload: { chain: 'solana', to: Keypair.generate().publicKey.toBase58(), amount: 0.00001, currency: 'SOL', agent_name: 'gh-agent', idempotency_key: 'g-t-conflict' } });
    expect(classify(res)).toEqual({ statusCode: 400, errorCode: 'IDEMPOTENCY_CONFLICT' });
    expect(ledgerCount()).toBe(before); // rejected → no ledger row added
  });

  // ── Swap idempotency ────────────────────────────────────────────────────────
  it('GOLDEN swap/idempotent-replay → replays prior signature', async () => {
    seedSpend('swap', 'g-s-replay', OUT_MINT, 0.0001, 'SOL', 'SIG_S_REPLAY');
    stubJupiter();
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0001, 'g-s-replay') });
    expect(classify(res)).toEqual({ statusCode: 200, idempotentReplay: true });
    expect(res.json().signature).toBe('SIG_S_REPLAY');
  });

  it('GOLDEN swap/idempotency-conflict → rejects key reused for a different swap', async () => {
    seedSpend('swap', 'g-s-conflict', WSOL, 0.0001, 'SOL', 'SIG_S_C'); // different output mint
    stubJupiter();
    const before = ledgerCount();
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0001, 'g-s-conflict') });
    expect(classify(res)).toEqual({ statusCode: 400, errorCode: 'IDEMPOTENCY_CONFLICT' });
    expect(ledgerCount()).toBe(before);
  });

  // ── Swap validation rejections ──────────────────────────────────────────────
  it('GOLDEN swap/quote-mismatch → INVALID_CHAIN', async () => {
    stubJupiter({ quoteOverride: { inputMint: WSOL, outputMint: SYSTEM, inAmount: '100000', outAmount: '1', slippageBps: 50 } });
    const before = ledgerCount();
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0001, 'g-s-qm') });
    expect(classify(res)).toEqual({ statusCode: 400, errorCode: 'INVALID_CHAIN' });
    expect(ledgerCount()).toBe(before);
  });

  it('GOLDEN swap/unexpected-program → INVALID_CHAIN', async () => {
    stubJupiter({ swapPrograms: [JUP_V6, Keypair.generate().publicKey.toBase58()] });
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0001, 'g-s-up') });
    expect(classify(res)).toEqual({ statusCode: 400, errorCode: 'INVALID_CHAIN' });
  });

  it('GOLDEN swap/not-jupiter-route → INVALID_CHAIN', async () => {
    stubJupiter({ swapPrograms: [SYSTEM] });
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0001, 'g-s-nj') });
    expect(classify(res)).toEqual({ statusCode: 400, errorCode: 'INVALID_CHAIN' });
  });

  // ── Budget + consent gating (valid quote/tx, so we reach signWithGuards) ─────
  it('GOLDEN swap/over-per-tx-limit → BUDGET_EXCEEDED_TX, no ledger row', async () => {
    stubJupiter();
    const before = ledgerCount();
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0003, 'g-s-budget') }); // 0.0003 > 0.0002 tx_limit
    expect(classify(res)).toEqual({ statusCode: 400, errorCode: 'BUDGET_EXCEEDED_TX' });
    expect(ledgerCount()).toBe(before);
  });

  it('GOLDEN swap/over-approval-threshold (no session) → requires consent, no ledger row', async () => {
    stubJupiter();
    const before = ledgerCount();
    const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swap(0.0001, 'g-s-consent') }); // > 0.00005 threshold, <= limits
    expect(classify(res)).toEqual({ statusCode: 200, requiresConsent: true });
    expect(ledgerCount()).toBe(before);
  });
});
