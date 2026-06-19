/**
 * Standalone tests for @dcprotocol/wallet-core — proves the pure wallet brain
 * works imported directly from the package, with zero native deps. (The full
 * behavioral suite also runs in @dcprotocol/core via the re-export, guaranteeing
 * backward compatibility.)
 */

import { describe, it, expect } from 'vitest';
import { Keypair, Transaction, SystemProgram, PublicKey } from '@solana/web3.js';
import {
  buildSolanaTransferTx,
  buildSplTransferTx,
  getSolanaAtaAddress,
  verifyTransferTx,
  getTransactionSigners,
  getTransactionProgramIds,
  VaultError,
} from '../src/index.js';

const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
const TO = '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S';
const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

describe('wallet-core: build + signers', () => {
  it('builds a SOL transfer with the sender as fee-payer + sole signer', () => {
    const tx = buildSolanaTransferTx(OWNER, TO, 0.1, BLOCKHASH);
    const s = getTransactionSigners(tx);
    expect(s.feePayer).toBe(OWNER);
    expect(s.numRequiredSignatures).toBe(1);
  });

  it('throws a VaultError (INVALID_CHAIN) on a self-transfer', () => {
    expect(() => buildSolanaTransferTx(OWNER, OWNER, 0.1, BLOCKHASH)).toThrowError(VaultError);
  });

  it('derives a deterministic ATA address', () => {
    expect(getSolanaAtaAddress(MINT, OWNER)).toBe(getSolanaAtaAddress(MINT, OWNER));
  });

  it('builds an SPL transfer with normal decimals', () => {
    const tx = buildSplTransferTx({ fromAddress: OWNER, toAddress: TO, mint: MINT, amount: 1.5, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false });
    expect(typeof tx).toBe('string');
  });

  it('rejects an out-of-range decimals (resource-exhaustion guard)', () => {
    // A huge user-supplied `decimals` must NOT be allowed to allocate giant strings.
    for (const decimals of [1_000_000_000, 100, 19, -1, 6.5]) {
      expect(() => buildSplTransferTx({ fromAddress: OWNER, toAddress: TO, mint: MINT, amount: 1, decimals, blockhash: BLOCKHASH, createRecipientAta: false }))
        .toThrowError(VaultError);
    }
  });
});

describe('wallet-core: anti-blind-sign', () => {
  it('passes a matching declared SOL transfer', () => {
    const tx = buildSolanaTransferTx(OWNER, TO, 0.1, BLOCKHASH);
    expect(verifyTransferTx({ unsignedTx: tx, owner: OWNER, declaredAmount: 0.1, declaredDestination: TO, currency: 'SOL' }))
      .toEqual({ ok: true, verified: true });
  });

  it('rejects a tx that sends more than declared', () => {
    const tx = buildSolanaTransferTx(OWNER, TO, 0.1, BLOCKHASH);
    expect(verifyTransferTx({ unsignedTx: tx, owner: OWNER, declaredAmount: 0.05, currency: 'SOL' }).ok).toBe(false);
  });

  it('does not enforce (verified:false) on an unrecognized blob', () => {
    expect(verifyTransferTx({ unsignedTx: Buffer.from('nope').toString('base64'), owner: OWNER }))
      .toEqual({ ok: true, verified: false });
  });
});

describe('wallet-core: program ids (LUT-safe)', () => {
  it('extracts the top-level programs a tx invokes', () => {
    const SYSTEM = '11111111111111111111111111111111';
    const tx = new Transaction({ feePayer: new PublicKey(OWNER), recentBlockhash: BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: new PublicKey(OWNER), toPubkey: new PublicKey(TO), lamports: 1 })
    );
    const b64 = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
    const r = getTransactionProgramIds(b64);
    expect(r.resolvable).toBe(true);
    expect(r.programIds).toContain(SYSTEM);
  });

  it('reports resolvable:false on garbage', () => {
    expect(getTransactionProgramIds(Buffer.from('garbage').toString('base64')).resolvable).toBe(false);
  });
});
