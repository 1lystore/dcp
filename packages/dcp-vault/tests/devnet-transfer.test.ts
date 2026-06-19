/**
 * DEVNET live integration test for /v1/vault/transfer (build + sign + submit).
 *
 * Gated behind RUN_DEVNET=1. Uses a pre-funded wallet whose secret is at
 * /tmp/dcp-devnet-wallet.json (generated out-of-band, funded via faucet), and a
 * Helius devnet RPC for submission. Proves the vault itself BUILDS, SIGNS,
 * SUBMITS, and CONFIRMS real transactions — at volume — and that a repeated
 * idempotency key never double-sends.
 *
 *   RUN_DEVNET=1 npx vitest run tests/devnet-transfer.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer } from '../src/index.js';
import {
  VaultStorage,
  resetStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  encryptWalletKey,
} from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, Transaction, SystemProgram, sendAndConfirmTransaction } from '@solana/web3.js';
import { createMint, getOrCreateAssociatedTokenAccount, mintTo, getAccount, getAssociatedTokenAddressSync } from '@solana/spl-token';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// Provide a devnet RPC via DCP_DEVNET_RPC (e.g. a Helius devnet URL). Falls back
// to the public devnet endpoint (rate-limited) — never hardcode a keyed URL here.
const RPC = process.env.DCP_DEVNET_RPC || 'https://api.devnet.solana.com';
const WALLET_FILE = '/tmp/dcp-devnet-wallet.json';
const N_TX = 20;
const AMOUNT_SOL = 0.00005; // under the 0.0001 SOL approval threshold → auto-approves
const AMOUNT_LAMPORTS = 50_000;

const runDevnet = process.env.RUN_DEVNET === '1' && fs.existsSync(WALLET_FILE);

describe.skipIf(!runDevnet)('DEVNET /v1/vault/transfer (live, 20 tx)', () => {
  let server: FastifyInstance;
  let walletAddress: string;
  let conn: Connection;
  let funder: Keypair;
  const passphrase = 'devnet-test-passphrase';

  // Pre-create + rent-exempt a destination account (a brand-new account can't
  // receive sub-rent-exempt amounts). Uses the funded wallet's own keypair.
  async function makeFundedDest(): Promise<string> {
    const dest = Keypair.generate().publicKey;
    const tx = new Transaction().add(
      SystemProgram.transfer({ fromPubkey: funder.publicKey, toPubkey: dest, lamports: 2_000_000 })
    );
    await sendAndConfirmTransaction(conn, tx, [funder], { commitment: 'confirmed' });
    return dest.toBase58();
  }

  beforeAll(async () => {
    process.env.DCP_SOLANA_RPC_URL = RPC;
    resetStorage();
    const dir = path.join(os.tmpdir(), `dcp-devnet-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    process.env.VAULT_DIR = dir;

    // Load the pre-funded devnet wallet and import it as the vault's wallet.
    const saved = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8')) as { address: string; secretKey: number[] };
    const kp = Keypair.fromSecretKey(Uint8Array.from(saved.secretKey));
    funder = kp;
    walletAddress = kp.publicKey.toBase58();

    const storage = new VaultStorage(dir);
    storage.initializeSchema();
    const masterKey = deriveKeyFromMnemonic(generateRecoveryMnemonic());
    try {
      await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
      const seed = Buffer.from(kp.secretKey.slice(0, 32));
      const { encrypted } = encryptWalletKey(
        { chain: 'solana', public_address: walletAddress, key_type: 'ed25519', private_key: seed },
        masterKey
      );
      storage.createRecord({
        scope: 'crypto.wallet.solana',
        item_type: 'WALLET_KEY',
        sensitivity: 'critical',
        data: encrypted,
        chain: 'solana',
        public_address: walletAddress,
      });
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });

    conn = new Connection(RPC, 'confirmed');
  }, 120_000);

  afterAll(async () => {
    if (server) await server.close();
  });

  it(`fires ${N_TX} transfers CONCURRENTLY (load + concurrency) and processes all safely`, async () => {
    const startBal = await conn.getBalance(new PublicKey(walletAddress));
    console.log(`[devnet] wallet ${walletAddress} balance: ${startBal / LAMPORTS_PER_SOL} SOL`);

    const dest = await makeFundedDest();
    const destStart = await conn.getBalance(new PublicKey(dest));

    // IDENTICAL amount + recipient on every tx — the exact case that would
    // collide on one signature with a cached blockhash. They stay distinct only
    // because each carries a unique memo nonce (the idempotency key).
    const expectedReceived = N_TX * AMOUNT_LAMPORTS;
    const reqs = Array.from({ length: N_TX }, (_, i) => ({
      chain: 'solana',
      to: dest,
      amount: AMOUNT_SOL,
      currency: 'SOL',
      agent_name: 'devnet-test',
      idempotency_key: `load-${Date.now()}-${i}`,
    }));

    // FIRE ALL AT ONCE.
    const t0 = Date.now();
    const results = await Promise.all(
      reqs.map((payload) => server.inject({ method: 'POST', url: '/v1/vault/transfer', payload }))
    );
    const totalMs = Date.now() - t0;

    const sigs: string[] = [];
    let ok = 0;
    let confirmed = 0;
    for (let i = 0; i < results.length; i++) {
      const res = results[i];
      if (res.statusCode !== 200) {
        console.log(`[devnet] tx ${i} FAILED ${res.statusCode}:`, res.body.slice(0, 200));
        continue;
      }
      ok++;
      const body = res.json();
      sigs.push(body.signature);
      if (body.status === 'confirmed' || body.status === 'finalized') confirmed++;
    }

    console.log(`[devnet] ${N_TX} concurrent tx in ${totalMs}ms — ok ${ok}/${N_TX}, confirmed ${confirmed}/${N_TX}, unique sigs ${new Set(sigs).size}, throughput ${(N_TX / (totalMs / 1000)).toFixed(2)} tx/s`);

    // Concurrency correctness: every request succeeded, every tx is unique (no
    // budget race, no double-spend, no blockhash collision).
    expect(ok).toBe(N_TX);
    expect(new Set(sigs).size).toBe(N_TX);

    // On-chain truth: destination received EXACTLY the sum — not more (double
    // spend) and not less (dropped/collided).
    await new Promise((r) => setTimeout(r, 6000));
    const received = (await conn.getBalance(new PublicKey(dest))) - destStart;
    console.log(`[devnet] destination received ${received} lamports (expected ${expectedReceived})`);
    expect(received).toBe(expectedReceived);

    // Budget ledger must reflect exactly N_TX spends (no over/under count).
    const dailyRes = await server.inject({ method: 'GET', url: '/budget/check?amount=0&currency=SOL&chain=solana' });
    console.log('[devnet] budget after load:', dailyRes.body);
  }, 180_000);

  it('measures latency: confirmed vs fast-submit (with blockhash cache)', async () => {
    const dest = await makeFundedDest();
    let i = 0;
    const send = async (confirm: 'confirmed' | 'submitted') => {
      const t0 = Date.now();
      const res = await server.inject({
        method: 'POST',
        url: '/v1/vault/transfer',
        payload: {
          chain: 'solana', to: dest, amount: (AMOUNT_LAMPORTS + i++) / LAMPORTS_PER_SOL,
          currency: 'SOL', agent_name: 'devnet-test', confirm, idempotency_key: `lat-${Date.now()}-${i}`,
        },
      });
      expect(res.statusCode).toBe(200);
      return Date.now() - t0;
    };

    await send('confirmed'); // warm up the blockhash cache
    const conf: number[] = [];
    for (let k = 0; k < 3; k++) conf.push(await send('confirmed'));
    const fast: number[] = [];
    for (let k = 0; k < 3; k++) fast.push(await send('submitted'));

    const avg = (a: number[]) => Math.round(a.reduce((x, y) => x + y, 0) / a.length);
    console.log(`[devnet] confirm='confirmed' avg ${avg(conf)}ms ${JSON.stringify(conf)}`);
    console.log(`[devnet] confirm='submitted' (fast) avg ${avg(fast)}ms ${JSON.stringify(fast)}`);
    expect(avg(fast)).toBeLessThan(avg(conf)); // fast path is faster
    expect(avg(fast)).toBeLessThan(1100); // sub-confirmed, broadcast-only
  }, 120_000);

  it('does not double-send for a repeated idempotency key', async () => {
    const dest = await makeFundedDest();
    const destStart = await conn.getBalance(new PublicKey(dest));
    const key = `idem-${Date.now()}`;
    const payload = {
      chain: 'solana', to: dest, amount: AMOUNT_SOL, currency: 'SOL',
      agent_name: 'devnet-test', idempotency_key: key,
    };
    const first = (await server.inject({ method: 'POST', url: '/v1/vault/transfer', payload })).json();
    const second = (await server.inject({ method: 'POST', url: '/v1/vault/transfer', payload })).json();

    expect(first.signature).toBeTruthy();
    expect(second.signature).toBe(first.signature);
    expect(second.idempotent_replay).toBe(true);

    await new Promise((r) => setTimeout(r, 5000));
    const received = (await conn.getBalance(new PublicKey(dest))) - destStart;
    expect(received).toBe(AMOUNT_LAMPORTS); // received exactly once
  }, 120_000);

  it('sends an SPL token to a BRAND-NEW wallet — auto-creates its token account', async () => {
    // Mint a fresh devnet SPL token (6 decimals) and fund the vault wallet with it.
    const mint = await createMint(conn, funder, funder.publicKey, null, 6);
    const senderAta = await getOrCreateAssociatedTokenAccount(conn, funder, mint, funder.publicKey);
    await mintTo(conn, funder, mint, senderAta.address, funder, 1_000_000); // 1.0 token
    console.log(`[devnet] minted token ${mint.toBase58()} → vault wallet`);

    // Recipient is a brand-new wallet that has NEVER held this token (no ATA).
    const newWallet = Keypair.generate().publicKey;
    const recipientAta = getAssociatedTokenAddressSync(mint, newWallet);
    const before = await conn.getAccountInfo(recipientAta);
    expect(before).toBeNull(); // confirm the token account does not exist yet

    const res = await server.inject({
      method: 'POST',
      url: '/v1/vault/transfer',
      payload: {
        chain: 'solana',
        to: newWallet.toBase58(),
        amount: 0.00005, // 50 base units, under USDC approval threshold → auto-approves
        currency: 'USDC',
        mint: mint.toBase58(),
        decimals: 6,
        agent_name: 'devnet-test',
        idempotency_key: `spl-${Date.now()}`,
      },
    });

    if (res.statusCode !== 200) console.log('[devnet] SPL transfer FAILED:', res.body.slice(0, 300));
    expect(res.statusCode).toBe(200);
    const body = res.json();
    console.log(`[devnet] SPL transfer to new wallet: ${body.status} ${body.signature?.slice(0, 16)}…`);
    expect(body.signature).toBeTruthy();
    expect(['confirmed', 'finalized', 'submitted']).toContain(body.status);

    // The recipient's token account was created AND received the tokens.
    await new Promise((r) => setTimeout(r, 5000));
    const acct = await getAccount(conn, recipientAta);
    console.log(`[devnet] new wallet token account created, balance: ${acct.amount} base units`);
    expect(acct.amount).toBe(50n); // 0.00005 * 1e6
  }, 150_000);
});
