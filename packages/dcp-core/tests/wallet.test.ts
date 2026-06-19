/**
 * Tests for Wallet Manager
 *
 * These tests verify:
 * - Solana (Ed25519) keypair generation
 * - Wallet encryption/decryption roundtrip
 * - Transaction signing
 * - Message signing
 * - Wallet import
 * - Private key is NEVER exposed
 */

import { describe, it, expect } from 'vitest';
import { Keypair, Transaction, SystemProgram, PublicKey } from '@solana/web3.js';
import { TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID } from '@solana/spl-token';
import {
  generateWalletKeypair,
  encryptWalletKey,
  createWallet,
  buildSolanaTransferTx,
  buildSplTransferTx,
  getSolanaAtaAddress,
  verifyTransferTx,
  getTransactionSigners,
  getTransactionProgramIds,
  signSolanaMessage,
  importWallet,
  getPublicAddress,
  getSupportedOperations,
  isChainSupported,
} from '../src/wallet.js';
import { generateKey, zeroize, envelopeDecrypt } from '../src/crypto.js';
import { VaultError, Chain } from '../src/types.js';

describe('Wallet Manager', () => {
  describe('Keypair Generation', () => {
    it('should generate Solana Ed25519 keypair', () => {
      const wallet = generateWalletKeypair('solana');

      expect(wallet.chain).toBe('solana');
      expect(wallet.key_type).toBe('ed25519');
      expect(wallet.private_key.length).toBe(32); // Ed25519 seed
      expect(wallet.public_address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/); // Base58

      // Cleanup
      zeroize(wallet.private_key);
    });

    it('should generate unique keypairs each time', () => {
      const wallet1 = generateWalletKeypair('solana');
      const wallet2 = generateWalletKeypair('solana');

      expect(wallet1.public_address).not.toBe(wallet2.public_address);
      expect(wallet1.private_key.equals(wallet2.private_key)).toBe(false);

      // Cleanup
      zeroize(wallet1.private_key);
      zeroize(wallet2.private_key);
    });

    it('should reject unsupported chain', () => {
      expect(() => generateWalletKeypair('bitcoin' as Chain)).toThrow(VaultError);
    });
  });

  describe('Wallet Encryption', () => {
    it('should encrypt Solana wallet immediately after generation', () => {
      const masterKey = generateKey();
      const wallet = generateWalletKeypair('solana');
      const publicAddress = wallet.public_address;

      const { encrypted, info } = encryptWalletKey(wallet, masterKey);

      // Verify info is correct
      expect(info.chain).toBe('solana');
      expect(info.public_address).toBe(publicAddress);
      expect(info.key_type).toBe('ed25519');
      expect(info.operations).toContain('sign_tx');

      // Verify wallet private key was zeroized
      expect(wallet.private_key.every((b) => b === 0)).toBe(true);

      // Verify encrypted payload structure
      expect(encrypted.ciphertext.length).toBeGreaterThan(0);
      expect(encrypted.nonce.length).toBe(24);
      expect(encrypted.dek_wrapped.length).toBeGreaterThan(0);
      expect(encrypted.dek_nonce.length).toBe(24);

      zeroize(masterKey);
    });

    it('should encrypt and decrypt wallet key successfully', () => {
      const masterKey = generateKey();
      const originalWallet = generateWalletKeypair('solana');
      const originalPrivateKey = Buffer.from(originalWallet.private_key);

      const { encrypted } = encryptWalletKey(originalWallet, masterKey);

      // Decrypt and verify
      const decryptedKey = envelopeDecrypt(encrypted, masterKey);
      expect(decryptedKey.equals(originalPrivateKey)).toBe(true);

      // Cleanup
      zeroize(masterKey);
      zeroize(decryptedKey);
    });

    it('should fail decryption with wrong master key', () => {
      const masterKey1 = generateKey();
      const masterKey2 = generateKey();

      const { encrypted } = createWallet('solana', masterKey1);

      expect(() => envelopeDecrypt(encrypted, masterKey2)).toThrow(VaultError);

      zeroize(masterKey1);
      zeroize(masterKey2);
    });
  });

  describe('createWallet (atomic operation)', () => {
    it('should create Solana wallet in one operation', () => {
      const masterKey = generateKey();

      const { encrypted, info } = createWallet('solana', masterKey);

      expect(info.chain).toBe('solana');
      expect(info.key_type).toBe('ed25519');
      expect(info.public_address).toBeTruthy();
      expect(encrypted.ciphertext.length).toBeGreaterThan(0);

      zeroize(masterKey);
    });

  });

  describe('Message Signing', () => {
    it('should sign Solana message and produce valid signature', () => {
      const masterKey = generateKey();
      const { encrypted, info } = createWallet('solana', masterKey);

      const message = 'Hello, DCP Vault!';
      const signature = signSolanaMessage(encrypted, masterKey, message);

      // Signature should be base58 encoded (Solana standard), 64 bytes when decoded
      const bs58 = require('bs58');
      const decode = bs58.default?.decode || bs58.decode;
      const sigBuffer = Buffer.from(decode(signature));
      expect(sigBuffer.length).toBe(64); // Ed25519 signature is 64 bytes

      // Verify signature using tweetnacl
      const nacl = require('tweetnacl');
      const publicKey = new PublicKey(info.public_address).toBytes();
      const isValid = nacl.sign.detached.verify(
        Buffer.from(message),
        sigBuffer,
        publicKey
      );
      expect(isValid).toBe(true);

      zeroize(masterKey);
    });

    it('should produce different signatures for different messages', () => {
      const masterKey = generateKey();
      const { encrypted } = createWallet('solana', masterKey);

      const sig1 = signSolanaMessage(encrypted, masterKey, 'message 1');
      const sig2 = signSolanaMessage(encrypted, masterKey, 'message 2');

      expect(sig1).not.toBe(sig2);

      zeroize(masterKey);
    });

    it('should sign base64 encoded message correctly', () => {
      const masterKey = generateKey();
      const { encrypted, info } = createWallet('solana', masterKey);

      // Create a binary message and encode as base64
      const binaryMessage = Buffer.from([0x01, 0x02, 0x03, 0xff, 0xfe]);
      const base64Message = binaryMessage.toString('base64');

      const signature = signSolanaMessage(encrypted, masterKey, base64Message, 'base64');

      // Verify signature
      const bs58 = require('bs58');
      const decode = bs58.default?.decode || bs58.decode;
      const sigBuffer = Buffer.from(decode(signature));
      expect(sigBuffer.length).toBe(64);

      const nacl = require('tweetnacl');
      const publicKey = new PublicKey(info.public_address).toBytes();
      const isValid = nacl.sign.detached.verify(
        binaryMessage,
        sigBuffer,
        publicKey
      );
      expect(isValid).toBe(true);

      zeroize(masterKey);
    });
  });

  describe('Wallet Import', () => {
    it('should import Solana wallet from base58 private key', () => {
      const masterKey = generateKey();

      // Create a wallet and get its private key for import testing
      const originalKeypair = Keypair.generate();
      const bs58 = require('bs58');
      // bs58 v6 uses default export
      const encode = bs58.default?.encode || bs58.encode;
      const privateKeyBase58 = encode(originalKeypair.secretKey);

      const { encrypted, info } = importWallet('solana', privateKeyBase58, masterKey);

      expect(info.chain).toBe('solana');
      expect(info.public_address).toBe(originalKeypair.publicKey.toBase58());

      // Verify we can decrypt and use the key
      const message = 'test import';
      const signature = signSolanaMessage(encrypted, masterKey, message);
      expect(signature).toBeTruthy();

      zeroize(masterKey);
    });

    it('should reject invalid Solana private key', () => {
      const masterKey = generateKey();

      expect(() => importWallet('solana', 'invalid-key', masterKey)).toThrow(VaultError);

      zeroize(masterKey);
    });

  });

  describe('Utility Functions', () => {
    it('should get public address from wallet info', () => {
      const masterKey = generateKey();
      const { info } = createWallet('solana', masterKey);

      const address = getPublicAddress(info);
      expect(address).toBe(info.public_address);

      zeroize(masterKey);
    });

    it('should get supported operations for chain', () => {
      const ops = getSupportedOperations('solana');

      expect(ops).toContain('sign_tx');
      expect(ops).toContain('sign_message');
      expect(ops).toContain('get_address');
    });

    it('should validate supported chains', () => {
      expect(isChainSupported('solana')).toBe(true);
      expect(isChainSupported('bitcoin')).toBe(false);
      expect(isChainSupported('random')).toBe(false);
    });
  });

  describe('Security: Private Key Never Exposed', () => {
    it('should zeroize private key after encryption', () => {
      const masterKey = generateKey();
      const wallet = generateWalletKeypair('solana');

      // Keep reference to check zeroization
      const privateKeyRef = wallet.private_key;

      encryptWalletKey(wallet, masterKey);

      // Private key should be all zeros
      expect(privateKeyRef.every((b) => b === 0)).toBe(true);

      zeroize(masterKey);
    });

    it('should not expose private key in wallet info', () => {
      const masterKey = generateKey();
      const { info } = createWallet('solana', masterKey);

      // TypeScript should prevent this, but let's verify at runtime
      expect((info as Record<string, unknown>).private_key).toBeUndefined();
      expect((info as Record<string, unknown>).secretKey).toBeUndefined();

      zeroize(masterKey);
    });

    it('should not include private key in encrypted payload', () => {
      const masterKey = generateKey();
      const { encrypted } = createWallet('solana', masterKey);

      // Encrypted payload should only contain encrypted data, not plaintext
      const payloadString = JSON.stringify(encrypted);
      expect(payloadString).not.toContain('private');
      expect(payloadString).not.toContain('secret');

      zeroize(masterKey);
    });
  });
});

describe('buildSolanaTransferTx (build-from-intent)', () => {
  const FROM = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
  const TO = '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S';
  const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

  it('builds an unsigned SOL transfer with fee-payer = sender and correct lamports', () => {
    const b64 = buildSolanaTransferTx(FROM, TO, 0.25, BLOCKHASH);
    const tx = Transaction.from(Buffer.from(b64, 'base64'));

    expect(tx.feePayer?.toBase58()).toBe(FROM);
    expect(tx.recentBlockhash).toBe(BLOCKHASH);

    const ix = tx.instructions.find((i) => i.programId.equals(SystemProgram.programId))!;
    expect(ix).toBeDefined();
    expect(ix.keys[0].pubkey.toBase58()).toBe(FROM);
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[1].pubkey.toBase58()).toBe(TO);
    expect(ix.data.readBigUInt64LE(4)).toBe(250_000_000n);
  });

  it('adds a priority fee instruction by default, omits it when 0', () => {
    const withFee = Transaction.from(Buffer.from(buildSolanaTransferTx(FROM, TO, 1, BLOCKHASH), 'base64'));
    expect(withFee.instructions).toHaveLength(2); // [setComputeUnitPrice, transfer]
    const noFee = Transaction.from(
      Buffer.from(buildSolanaTransferTx(FROM, TO, 1, BLOCKHASH, { priorityFeeMicroLamports: 0 }), 'base64')
    );
    expect(noFee.instructions).toHaveLength(1); // [transfer]
  });

  it('is unsigned (no signatures attached)', () => {
    const tx = Transaction.from(Buffer.from(buildSolanaTransferTx(FROM, TO, 1, BLOCKHASH), 'base64'));
    expect(tx.signatures.every((s) => s.signature === null)).toBe(true);
  });

  it('rejects self-transfer, bad addresses, and non-positive amounts', () => {
    expect(() => buildSolanaTransferTx(FROM, FROM, 1, BLOCKHASH)).toThrow(VaultError);
    expect(() => buildSolanaTransferTx('bad', TO, 1, BLOCKHASH)).toThrow(/Invalid from/);
    expect(() => buildSolanaTransferTx(FROM, 'bad', 1, BLOCKHASH)).toThrow(/Invalid to/);
    expect(() => buildSolanaTransferTx(FROM, TO, 0, BLOCKHASH)).toThrow(/positive/);
    expect(() => buildSolanaTransferTx(FROM, TO, -1, BLOCKHASH)).toThrow(/positive/);
    expect(() => buildSolanaTransferTx(FROM, TO, 1, '')).toThrow(/blockhash/);
  });
});

describe('buildSplTransferTx (SPL token, auto-ATA)', () => {
  const FROM = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
  const TO = '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S';
  const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // USDC
  const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

  it('CREATES the recipient ATA when they have never held the token', () => {
    const b64 = buildSplTransferTx({ fromAddress: FROM, toAddress: TO, mint: MINT, amount: 1.5, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: true });
    const tx = Transaction.from(Buffer.from(b64, 'base64'));
    expect(tx.feePayer?.toBase58()).toBe(FROM); // sender pays
    const programs = tx.instructions.map((i) => i.programId.toBase58());
    expect(programs).toContain(ASSOCIATED_TOKEN_PROGRAM_ID.toBase58()); // ATA creation present
    expect(programs).toContain(TOKEN_PROGRAM_ID.toBase58()); // token transfer present
  });

  it('omits ATA creation when the recipient already has the account', () => {
    const tx = Transaction.from(
      Buffer.from(buildSplTransferTx({ fromAddress: FROM, toAddress: TO, mint: MINT, amount: 1, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false }), 'base64')
    );
    const programs = tx.instructions.map((i) => i.programId.toBase58());
    expect(programs).not.toContain(ASSOCIATED_TOKEN_PROGRAM_ID.toBase58());
    expect(programs).toContain(TOKEN_PROGRAM_ID.toBase58());
  });

  it('derives a deterministic ATA address and rejects bad input', () => {
    const ata = getSolanaAtaAddress(MINT, FROM);
    expect(ata).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
    expect(() => buildSplTransferTx({ fromAddress: FROM, toAddress: FROM, mint: MINT, amount: 1, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false })).toThrow(/self-transfer/);
    expect(() => buildSplTransferTx({ fromAddress: FROM, toAddress: TO, mint: 'bad', amount: 1, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false })).toThrow(/Invalid token mint/);
    expect(() => buildSplTransferTx({ fromAddress: FROM, toAddress: TO, mint: MINT, amount: 0, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false })).toThrow(/positive/);
  });
});

describe('verifyTransferTx (anti blind-sign for vault_sign_tx)', () => {
  const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
  const TO = '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S';
  const OTHER = 'So11111111111111111111111111111111111111112';
  const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

  it('accepts a SOL transfer matching declared amount + destination', () => {
    const tx = buildSolanaTransferTx(OWNER, TO, 0.1, BLOCKHASH);
    const r = verifyTransferTx({ unsignedTx: tx, owner: OWNER, declaredAmount: 0.1, declaredDestination: TO, currency: 'SOL' });
    expect(r).toEqual({ ok: true, verified: true });
  });

  it('REJECTS a blob that sends MORE SOL than declared (the attack)', () => {
    const tx = buildSolanaTransferTx(OWNER, TO, 10, BLOCKHASH); // blob really sends 10
    const r = verifyTransferTx({ unsignedTx: tx, owner: OWNER, declaredAmount: 0.1, declaredDestination: TO, currency: 'SOL' });
    expect(r.ok).toBe(false);
    expect(r.verified).toBe(true);
  });

  it('REJECTS a blob to a DIFFERENT destination than declared', () => {
    const tx = buildSolanaTransferTx(OWNER, OTHER, 0.1, BLOCKHASH); // blob sends to OTHER
    const r = verifyTransferTx({ unsignedTx: tx, owner: OWNER, declaredAmount: 0.1, declaredDestination: TO, currency: 'SOL' });
    expect(r.ok).toBe(false);
  });

  it('accepts a matching SPL transfer and rejects an over-amount one', () => {
    const okTx = buildSplTransferTx({ fromAddress: OWNER, toAddress: TO, mint: MINT, amount: 1.5, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false });
    expect(verifyTransferTx({ unsignedTx: okTx, owner: OWNER, declaredAmount: 1.5, declaredDestination: TO, currency: 'USDC' })).toEqual({ ok: true, verified: true });

    const badTx = buildSplTransferTx({ fromAddress: OWNER, toAddress: TO, mint: MINT, amount: 100, decimals: 6, blockhash: BLOCKHASH, createRecipientAta: false });
    expect(verifyTransferTx({ unsignedTx: badTx, owner: OWNER, declaredAmount: 1, declaredDestination: TO, currency: 'USDC' }).ok).toBe(false);
  });

  it('does not enforce (verified:false) for an unrecognized/garbage blob', () => {
    const r = verifyTransferTx({ unsignedTx: Buffer.from('not a tx').toString('base64'), owner: OWNER, declaredAmount: 1 });
    expect(r).toEqual({ ok: true, verified: false }); // escape hatch, not enforced
  });
});

describe('getTransactionSigners (swap-tx validation)', () => {
  it('reports the fee-payer and a single required signer for a built tx', () => {
    const tx = buildSolanaTransferTx(
      'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm',
      '2ojv9BAiHUrvsm9gxDe7fJSzbNZSJcxZvf8dqmWGHG8S',
      0.1,
      'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi'
    );
    const s = getTransactionSigners(tx);
    expect(s.feePayer).toBe('Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm');
    expect(s.numRequiredSignatures).toBe(1); // only the owner signs
  });
});

describe('getTransactionProgramIds (swap-tx program allow-listing)', () => {
  const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';
  const BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

  function txWithPrograms(programIds: string[]): string {
    const tx = new Transaction({ feePayer: new PublicKey(OWNER), recentBlockhash: BLOCKHASH });
    for (const pid of programIds) {
      tx.add({ keys: [], programId: new PublicKey(pid), data: Buffer.from([]) });
    }
    return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
  }

  it('extracts the top-level program ids a tx invokes', () => {
    const SYSTEM = '11111111111111111111111111111111';
    const JUP = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';
    const r = getTransactionProgramIds(txWithPrograms([SYSTEM, JUP]));
    expect(r.resolvable).toBe(true);
    expect(r.programIds.sort()).toEqual([SYSTEM, JUP].sort());
  });

  it('surfaces an unexpected program so the caller can reject it', () => {
    const RANDOM = Keypair.generate().publicKey.toBase58();
    const r = getTransactionProgramIds(txWithPrograms([RANDOM]));
    expect(r.resolvable).toBe(true);
    expect(r.programIds).toContain(RANDOM);
  });

  it('reports resolvable:false for a garbage blob (treat as opaque)', () => {
    const r = getTransactionProgramIds(Buffer.from('not a tx').toString('base64'));
    expect(r.resolvable).toBe(false);
    expect(r.programIds).toEqual([]);
  });
});
