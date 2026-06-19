/**
 * MAINNET on-chain proof for the Phase 4 shared-runner path. This is the gate that
 * justifies flipping DCP_USE_SHARED_RUNNER to default: it runs a REAL transfer and a
 * REAL Jupiter swap through the new path (executeTransfer/executeSwap via the vault
 * adapters) against mainnet, with real funds, and confirms them on-chain.
 *
 * Gated — only runs when BOTH are present:
 *   RUN_MAINNET=1   and   a funded wallet at /tmp/dcp-devnet-wallet.json
 *                         (format: { address, secretKey: number[] })
 *
 * Usage once the wallet has ~0.1 SOL on mainnet:
 *   RUN_MAINNET=1 DCP_USE_SHARED_RUNNER=1 \
 *     npx vitest run tests/mainnet-verify.test.ts
 *
 * Amounts are intentionally tiny (transfer 0.001 SOL to a recoverable burner we save
 * to /tmp/dcp-mainnet-recipient.json; swap 0.003 SOL → USDC, which only loses fees +
 * slippage). Total cost ≈ a few cents of SOL.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildServer } from '../src/index.js';
import {
  VaultStorage, resetStorage, generateRecoveryMnemonic, deriveKeyFromMnemonic,
  zeroize, encryptWalletKey,
} from '@dcprotocol/core';
import type { FastifyInstance } from 'fastify';
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const RPC = process.env.DCP_MAINNET_RPC || 'https://api.mainnet-beta.solana.com';
const WALLET_FILE = '/tmp/dcp-devnet-wallet.json';
const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

const runMainnet = process.env.RUN_MAINNET === '1' && fs.existsSync(WALLET_FILE);

describe.skipIf(!runMainnet)('MAINNET shared-runner proof (real funds)', () => {
  let server: FastifyInstance;
  let conn: Connection;
  let walletAddress: string;
  const passphrase = 'mainnet-verify-passphrase';

  beforeAll(async () => {
    // Force the shared-runner path + mainnet RPC for this run.
    process.env.DCP_USE_SHARED_RUNNER = '1';
    process.env.DCP_SOLANA_RPC_URL = RPC;
    resetStorage();
    const dir = path.join(os.tmpdir(), `dcp-mainnet-${Date.now()}`);
    process.env.VAULT_DIR = dir;

    const saved = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8')) as { address: string; secretKey: number[] };
    const kp = Keypair.fromSecretKey(Uint8Array.from(saved.secretKey));
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
      storage.createRecord({ scope: 'crypto.wallet.solana', item_type: 'WALLET_KEY', sensitivity: 'critical', data: encrypted, chain: 'solana', public_address: walletAddress });
    } finally {
      zeroize(masterKey);
    }
    storage.close();

    server = await buildServer();
    await server.ready();
    await server.inject({ method: 'POST', url: '/v1/vault/unlock', payload: { passphrase } });
    conn = new Connection(RPC, 'confirmed');
  }, 60_000);

  afterAll(async () => { if (server) await server.close(); });

  it('reads a non-zero balance (wallet is funded)', async () => {
    const bal = await conn.getBalance(new PublicKey(walletAddress));
    console.log(`[mainnet] ${walletAddress} balance: ${bal / LAMPORTS_PER_SOL} SOL`);
    expect(bal).toBeGreaterThan(0.05 * LAMPORTS_PER_SOL); // need a little headroom
  });

  it('real SOL transfer through the shared runner — confirmed on-chain', async () => {
    // Recoverable burner — saved so funds aren't lost.
    const recipient = Keypair.generate();
    fs.writeFileSync('/tmp/dcp-mainnet-recipient.json', JSON.stringify({ address: recipient.publicKey.toBase58(), secretKey: Array.from(recipient.secretKey) }));
    const before = await conn.getBalance(recipient.publicKey);

    const res = await server.inject({
      method: 'POST', url: '/v1/vault/transfer',
      payload: { chain: 'solana', to: recipient.publicKey.toBase58(), amount: 0.001, currency: 'SOL', agent_name: 'mainnet-verify', idempotency_key: `mn-xfer-${Date.now()}` },
    });
    if (res.statusCode !== 200) console.log('[mainnet] transfer failed:', res.body.slice(0, 300));
    expect(res.statusCode).toBe(200);
    const body = res.json();
    console.log(`[mainnet] transfer ${body.status} ${body.signature}`);
    expect(body.signature).toBeTruthy();

    await new Promise((r) => setTimeout(r, 8000));
    const after = await conn.getBalance(recipient.publicKey);
    expect(after - before).toBe(Math.round(0.001 * LAMPORTS_PER_SOL));
  }, 90_000);

  it('real Jupiter swap (SOL → USDC) through the shared runner — confirmed on-chain', async () => {
    const res = await server.inject({
      method: 'POST', url: '/v1/vault/swap',
      payload: { chain: 'solana', from_token: 'SOL', to_token: 'USDC', amount: 0.003, slippage_bps: 100, agent_name: 'mainnet-verify', idempotency_key: `mn-swap-${Date.now()}` },
    });
    if (res.statusCode !== 200) console.log('[mainnet] swap failed:', res.body.slice(0, 400));
    expect(res.statusCode).toBe(200);
    const body = res.json();
    console.log(`[mainnet] swap ${body.status} out=${body.out_amount} ${body.signature}`);
    expect(body.signature).toBeTruthy();
    expect(['confirmed', 'finalized', 'submitted']).toContain(body.status);

    // Confirm the USDC ATA now holds a balance.
    await new Promise((r) => setTimeout(r, 8000));
    const ata = await conn.getParsedTokenAccountsByOwner(new PublicKey(walletAddress), { mint: new PublicKey(USDC) });
    const usdc = ata.value[0]?.account.data.parsed.info.tokenAmount.uiAmount ?? 0;
    console.log(`[mainnet] USDC balance after swap: ${usdc}`);
    expect(usdc).toBeGreaterThan(0);
  }, 120_000);
});
