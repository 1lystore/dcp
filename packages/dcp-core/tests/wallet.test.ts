/**
 * Tests for Wallet Manager
 *
 * These tests verify:
 * - Solana (Ed25519) keypair generation
 * - EVM (secp256k1) keypair generation
 * - Wallet encryption/decryption roundtrip
 * - Transaction signing
 * - Message signing
 * - Wallet import
 * - Private key is NEVER exposed
 */

import { describe, it, expect } from 'vitest';
import { Keypair, Transaction, SystemProgram, PublicKey } from '@solana/web3.js';
import {
  generateWalletKeypair,
  encryptWalletKey,
  createWallet,
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

    it('should generate Base secp256k1 keypair', () => {
      const wallet = generateWalletKeypair('base');

      expect(wallet.chain).toBe('base');
      expect(wallet.key_type).toBe('secp256k1');
      expect(wallet.private_key.length).toBe(32); // secp256k1 private key
      expect(wallet.public_address).toMatch(/^0x[a-fA-F0-9]{40}$/); // Ethereum address format

      // Cleanup
      zeroize(wallet.private_key);
    });

    it('should generate Ethereum secp256k1 keypair', () => {
      const wallet = generateWalletKeypair('ethereum');

      expect(wallet.chain).toBe('ethereum');
      expect(wallet.key_type).toBe('secp256k1');
      expect(wallet.private_key.length).toBe(32);
      expect(wallet.public_address).toMatch(/^0x[a-fA-F0-9]{40}$/);

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

    it('should create Base wallet in one operation', () => {
      const masterKey = generateKey();

      const { encrypted, info } = createWallet('base', masterKey);

      expect(info.chain).toBe('base');
      expect(info.key_type).toBe('secp256k1');
      expect(info.public_address).toMatch(/^0x/);

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

    it('should import EVM wallet from hex private key', () => {
      const masterKey = generateKey();

      // Known test private key (DO NOT use in production)
      const testPrivateKey = '0x' + 'ab'.repeat(32);
      const { Wallet } = require('ethers');
      const expectedAddress = new Wallet(testPrivateKey).address;

      const { info } = importWallet('base', testPrivateKey, masterKey);

      expect(info.chain).toBe('base');
      expect(info.public_address.toLowerCase()).toBe(expectedAddress.toLowerCase());

      zeroize(masterKey);
    });

    it('should import EVM wallet without 0x prefix', () => {
      const masterKey = generateKey();

      const testPrivateKey = 'cd'.repeat(32); // Without 0x
      const { Wallet } = require('ethers');
      const expectedAddress = new Wallet('0x' + testPrivateKey).address;

      const { info } = importWallet('ethereum', testPrivateKey, masterKey);

      expect(info.public_address.toLowerCase()).toBe(expectedAddress.toLowerCase());

      zeroize(masterKey);
    });

    it('should reject invalid Solana private key', () => {
      const masterKey = generateKey();

      expect(() => importWallet('solana', 'invalid-key', masterKey)).toThrow(VaultError);

      zeroize(masterKey);
    });

    it('should reject invalid EVM private key', () => {
      const masterKey = generateKey();

      expect(() => importWallet('base', '0x123', masterKey)).toThrow(VaultError);

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
      expect(isChainSupported('base')).toBe(true);
      expect(isChainSupported('ethereum')).toBe(true);
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
