/**
 * Wallet transfer/swap route guards (no network):
 *  - idempotency_key reused for a DIFFERENT intent is rejected (not blindly replayed)
 *  - idempotency_key reused for the SAME intent replays the prior signature
 *  - swap quote must match the requested mints/amount/slippage
 *  - swap tx must be a real Jupiter route invoking only allow-listed programs
 *
 * The rejection/replay paths all short-circuit BEFORE any signing or submit, so these
 * run fully offline (Jupiter HTTP is stubbed for the swap-validation cases).
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
const OUT_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // USDC mainnet (used as an explicit output mint)
const JUP_V6 = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';
const SYSTEM = '11111111111111111111111111111111';

describe('Wallet transfer/swap guards', () => {
  let server: FastifyInstance;
  let testVaultDir: string;
  let storage: VaultStorage;
  let walletAddress: string;
  let sessionId: string;
  const passphrase = 'test-passphrase-123';

  beforeAll(async () => {
    resetStorage();
    testVaultDir = path.join(os.tmpdir(), `dcp-wtx-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    process.env.VAULT_DIR = testVaultDir;

    storage = new VaultStorage(testVaultDir);
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
      const session = storage.createSession(
        'wtx-test-agent',
        ['crypto.wallet.solana'],
        'session',
        new Date(Date.now() + 60 * 60 * 1000)
      );
      sessionId = session.id;
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });
  });

  afterAll(async () => {
    await server.close();
    resetStorage();
    if (testVaultDir && fs.existsSync(testVaultDir)) fs.rmSync(testVaultDir, { recursive: true, force: true });
    delete process.env.VAULT_DIR;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // Seed a committed transfer spend that a later request can collide with.
  function seedTransferSpend(key: string, destination: string, amount: number, signature: string) {
    getStorage().recordSpend(sessionId, amount, 'SOL', 'solana', 'transfer', 'committed', {
      destination,
      idempotencyKey: key,
      txSignature: signature,
    });
  }

  describe('transfer idempotency', () => {
    it('rejects the same key reused for a DIFFERENT transfer (no blind replay)', async () => {
      const key = `idem-conflict-${Date.now()}`;
      const destA = Keypair.generate().publicKey.toBase58();
      const destB = Keypair.generate().publicKey.toBase58();
      seedTransferSpend(key, destA, 0.5, 'SIGAAA');

      const res = await server.inject({
        method: 'POST',
        url: '/v1/vault/transfer',
        payload: { chain: 'solana', to: destB, amount: 0.5, currency: 'SOL', agent_name: 'wtx-test-agent', session_id: sessionId, idempotency_key: key },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe('IDEMPOTENCY_CONFLICT');
    });

    it('replays the prior signature for the SAME transfer intent', async () => {
      const key = `idem-replay-${Date.now()}`;
      const dest = Keypair.generate().publicKey.toBase58();
      seedTransferSpend(key, dest, 0.5, 'SIGBBB');

      const res = await server.inject({
        method: 'POST',
        url: '/v1/vault/transfer',
        payload: { chain: 'solana', to: dest, amount: 0.5, currency: 'SOL', agent_name: 'wtx-test-agent', session_id: sessionId, idempotency_key: key },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.idempotent_replay).toBe(true);
      expect(body.signature).toBe('SIGBBB');
    });
  });

  describe('swap validation', () => {
    // Stub Jupiter's quote + swap-build HTTP. `quote` is returned for /quote, and a
    // base64 tx built from `swapPrograms` is returned for /swap.
    function stubJupiter(quote: Record<string, unknown>, swapPrograms?: string[]) {
      const swapTransaction = swapPrograms
        ? (() => {
            const tx = new Transaction({ feePayer: new PublicKey(walletAddress), recentBlockhash: 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi' });
            for (const pid of swapPrograms) tx.add({ keys: [], programId: new PublicKey(pid), data: Buffer.from([]) });
            return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
          })()
        : undefined;
      vi.stubGlobal(
        'fetch',
        vi.fn(async (url: string) => {
          const u = String(url);
          if (u.includes('/quote')) return { ok: true, status: 200, json: async () => quote };
          if (u.includes('/swap')) return { ok: true, status: 200, json: async () => ({ swapTransaction }) };
          return { ok: true, status: 200, json: async () => ({}) };
        })
      );
    }

    const rawIn = String(Math.round(0.001 * 1e9)); // 0.001 SOL → lamports
    const swapPayload = {
      chain: 'solana', from_token: 'SOL', to_token: OUT_MINT, to_decimals: 6,
      amount: 0.001, slippage_bps: 50, agent_name: 'wtx-test-agent', session_id: sessionId,
    };

    it('rejects a quote whose output mint does not match the request', async () => {
      const wrongMint = Keypair.generate().publicKey.toBase58();
      stubJupiter({ inputMint: WSOL, outputMint: wrongMint, inAmount: rawIn, outAmount: '500', slippageBps: 50 });

      const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swapPayload });
      expect(res.statusCode).toBe(400);
      expect(res.json().error.message).toMatch(/does not match the requested tokens/i);
    });

    it('rejects a swap tx that invokes an unexpected program', async () => {
      const rogue = Keypair.generate().publicKey.toBase58();
      stubJupiter({ inputMint: WSOL, outputMint: OUT_MINT, inAmount: rawIn, outAmount: '500', slippageBps: 50 }, [JUP_V6, rogue]);

      const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swapPayload });
      expect(res.statusCode).toBe(400);
      expect(res.json().error.message).toMatch(/unexpected program/i);
    });

    it('rejects a tx that is not a recognized Jupiter route', async () => {
      stubJupiter({ inputMint: WSOL, outputMint: OUT_MINT, inAmount: rawIn, outAmount: '500', slippageBps: 50 }, [SYSTEM]);

      const res = await server.inject({ method: 'POST', url: '/v1/vault/swap', payload: swapPayload });
      expect(res.statusCode).toBe(400);
      expect(res.json().error.message).toMatch(/not a recognized Jupiter route/i);
    });
  });
});
