/**
 * Wallet Manager for DCP Vault
 *
 * Implements:
 * - Solana (Ed25519) keypair generation
 * - Base/EVM (secp256k1) keypair generation
 * - Transaction signing (returns signed tx, NEVER the key)
 * - Message signing (returns signature, NEVER the key)
 * - Immediate encryption after key generation (~5ms plaintext window)
 * - Memory zeroization after every operation
 *
 * CRITICAL SECURITY RULES:
 * 1. Private key exists in plaintext for ~5ms during generation
 * 2. Private key is NEVER returned to any caller
 * 3. No export_key operation exists. Ever. Non-negotiable.
 * 4. All plaintext key material is zeroized after use
 */

import { Keypair, Transaction, VersionedTransaction } from '@solana/web3.js';
import { Wallet, Transaction as EthTransaction } from 'ethers';
import {
  Chain,
  KeyType,
  WalletKeyData,
  WalletInfo,
  SignResult,
  EncryptedPayload,
  VaultError,
} from './types.js';
import { envelopeEncrypt, envelopeDecrypt, zeroize } from './crypto.js';

// ============================================================================
// Constants
// ============================================================================

/** Supported chains and their key types */
const CHAIN_KEY_TYPES: Record<Chain, KeyType> = {
  solana: 'ed25519',
  base: 'secp256k1',
  ethereum: 'secp256k1',
};

// ============================================================================
// Keypair Generation
// ============================================================================

/**
 * Generate a new wallet keypair for the specified chain
 *
 * SECURITY: Private key exists in plaintext for ~5ms during this operation.
 * Caller MUST call zeroize() on the returned private_key after encrypting it.
 *
 * @param chain - Blockchain to generate wallet for
 * @returns Wallet key data including private key (must be zeroized after use)
 */
export function generateWalletKeypair(chain: Chain): WalletKeyData {
  const keyType = CHAIN_KEY_TYPES[chain];

  if (!keyType) {
    throw new VaultError('INVALID_CHAIN', `Unsupported chain: ${chain}`);
  }

  if (keyType === 'ed25519') {
    return generateSolanaKeypair(chain);
  } else {
    return generateEvmKeypair(chain);
  }
}

/**
 * Generate Solana Ed25519 keypair
 */
function generateSolanaKeypair(chain: Chain): WalletKeyData {
  const keypair = Keypair.generate();
  const publicAddress = keypair.publicKey.toBase58();

  // Extract private key (64 bytes for Ed25519: 32 byte seed + 32 byte public key)
  // We only need the first 32 bytes (the seed/private key)
  const privateKey = Buffer.from(keypair.secretKey.slice(0, 32));

  return {
    chain,
    public_address: publicAddress,
    key_type: 'ed25519',
    private_key: privateKey,
  };
}

/**
 * Generate EVM secp256k1 keypair
 */
function generateEvmKeypair(chain: Chain): WalletKeyData {
  const wallet = Wallet.createRandom();
  const publicAddress = wallet.address;

  // Extract private key (32 bytes, without 0x prefix)
  const privateKeyHex = wallet.privateKey.slice(2); // Remove '0x'
  const privateKey = Buffer.from(privateKeyHex, 'hex');

  return {
    chain,
    public_address: publicAddress,
    key_type: 'secp256k1',
    private_key: privateKey,
  };
}

// ============================================================================
// Wallet Encryption (Immediate after generation)
// ============================================================================

/**
 * Encrypt wallet private key immediately after generation
 *
 * This is the ONLY way to persist a wallet. The private key is encrypted
 * with envelope encryption and the plaintext is zeroized immediately.
 *
 * Flow (from PRD):
 * 1. Encrypt private key: XChaCha20-Poly1305(key, DEK, random_24B_nonce)
 * 2. Wrap DEK with master key: XChaCha20-Poly1305(DEK, master_key, random_24B_nonce)
 * 3. Zeroize plaintext private key
 *
 * @param walletData - Wallet key data from generateWalletKeypair()
 * @param masterKey - Master key from OS Keychain
 * @returns Encrypted payload ready for storage + wallet info (without private key)
 */
export function encryptWalletKey(
  walletData: WalletKeyData,
  masterKey: Buffer
): { encrypted: EncryptedPayload; info: WalletInfo } {
  try {
    // Encrypt private key with envelope encryption
    const encrypted = envelopeEncrypt(walletData.private_key, masterKey);

    // Return wallet info (public data only)
    const info: WalletInfo = {
      chain: walletData.chain,
      public_address: walletData.public_address,
      key_type: walletData.key_type,
      operations: ['sign_tx', 'sign_message', 'get_address'],
    };

    return { encrypted, info };
  } finally {
    // CRITICAL: Zeroize private key from memory
    zeroize(walletData.private_key);
  }
}

/**
 * Create a new wallet: generate + encrypt in one atomic operation
 *
 * This is the recommended way to create wallets. The private key
 * exists in plaintext for <100ms total.
 *
 * @param chain - Blockchain to create wallet for
 * @param masterKey - Master key from OS Keychain
 * @returns Encrypted payload + wallet info
 */
export function createWallet(
  chain: Chain,
  masterKey: Buffer
): { encrypted: EncryptedPayload; info: WalletInfo } {
  const walletData = generateWalletKeypair(chain);
  return encryptWalletKey(walletData, masterKey);
}

// ============================================================================
// Transaction Signing
// ============================================================================

/**
 * Sign a Solana transaction
 *
 * SECURITY: Private key is decrypted, used for signing, then immediately zeroized.
 * The signed transaction is returned, NEVER the private key.
 *
 * @param encryptedKey - Encrypted wallet from storage
 * @param masterKey - Master key from OS Keychain
 * @param unsignedTx - Base64 encoded unsigned transaction
 * @returns Signed transaction (base64) and signature (base58, Solana standard)
 */
export function signSolanaTransaction(
  encryptedKey: EncryptedPayload,
  masterKey: Buffer,
  unsignedTx: string
): SignResult {
  // Decrypt private key
  const privateKey = envelopeDecrypt(encryptedKey, masterKey);

  // bs58 for base58 encoding (Solana standard)
  const bs58 = require('bs58');
  const encode = bs58.default?.encode || bs58.encode;

  try {
    // Derive keypair from seed (32 bytes)
    const keypair = Keypair.fromSeed(privateKey);

    // Decode the unsigned transaction
    const txBuffer = Buffer.from(unsignedTx, 'base64');

    let signedTx: string;
    let signature: string;

    // Try to parse as VersionedTransaction first, then legacy Transaction
    try {
      const versionedTx = VersionedTransaction.deserialize(txBuffer);
      versionedTx.sign([keypair]);
      signedTx = Buffer.from(versionedTx.serialize()).toString('base64');
      // Signature in base58 (Solana standard format like "5KtR7...")
      signature = encode(versionedTx.signatures[0]);
    } catch {
      // Fall back to legacy transaction
      const legacyTx = Transaction.from(txBuffer);
      legacyTx.sign(keypair);
      signedTx = legacyTx.serialize().toString('base64');
      // Signature in base58 (Solana standard format)
      signature = legacyTx.signature ? encode(legacyTx.signature) : '';
    }

    return {
      signed_tx: signedTx,
      signature,
      chain: 'solana',
    };
  } finally {
    // CRITICAL: Zeroize private key from memory
    zeroize(privateKey);
  }
}

/**
 * Sign an EVM transaction (Base, Ethereum)
 *
 * SECURITY: Private key is decrypted, used for signing, then immediately zeroized.
 * The signed transaction is returned, NEVER the private key.
 *
 * @param encryptedKey - Encrypted wallet from storage
 * @param masterKey - Master key from OS Keychain
 * @param unsignedTx - JSON string of unsigned transaction request
 * @param chain - The chain (base or ethereum)
 * @returns Signed transaction (serialized) and signature
 */
export async function signEvmTransaction(
  encryptedKey: EncryptedPayload,
  masterKey: Buffer,
  unsignedTx: string,
  chain: Chain
): Promise<SignResult> {
  // Decrypt private key
  const privateKey = envelopeDecrypt(encryptedKey, masterKey);

  try {
    // Create wallet from private key (ethers v6)
    const privateKeyHex = '0x' + privateKey.toString('hex');
    const wallet = new Wallet(privateKeyHex);

    // Parse transaction request
    const txRequest = JSON.parse(unsignedTx);

    // Sign the transaction - this returns the fully serialized signed transaction
    const signedTxSerialized = await wallet.signTransaction(txRequest);

    // Parse the signed transaction to extract signature
    const signedTx = EthTransaction.from(signedTxSerialized);
    const signature = signedTx.signature;

    return {
      signed_tx: signedTxSerialized,
      signature: signature ? signature.serialized : '',
      chain,
    };
  } finally {
    // CRITICAL: Zeroize private key from memory
    zeroize(privateKey);
  }
}

/**
 * Sign a transaction for any supported chain
 *
 * @param encryptedKey - Encrypted wallet from storage
 * @param masterKey - Master key from OS Keychain
 * @param chain - The blockchain
 * @param unsignedTx - Unsigned transaction (base64 for Solana, JSON for EVM)
 * @returns Signed transaction and signature
 */
export async function signTransaction(
  encryptedKey: EncryptedPayload,
  masterKey: Buffer,
  chain: Chain,
  unsignedTx: string
): Promise<SignResult> {
  const keyType = CHAIN_KEY_TYPES[chain];

  if (!keyType) {
    throw new VaultError('INVALID_CHAIN', `Unsupported chain: ${chain}`);
  }

  if (chain === 'solana') {
    return signSolanaTransaction(encryptedKey, masterKey, unsignedTx);
  } else {
    return signEvmTransaction(encryptedKey, masterKey, unsignedTx, chain);
  }
}

// ============================================================================
// Message Signing
// ============================================================================

/**
 * Sign an arbitrary message (Solana)
 *
 * @param encryptedKey - Encrypted wallet from storage
 * @param masterKey - Master key from OS Keychain
 * @param message - Message to sign (UTF-8 string or base64 encoded bytes)
 * @param encoding - Input encoding: 'utf8' (default) or 'base64'
 * @returns Base58 encoded signature (Solana standard format)
 */
export function signSolanaMessage(
  encryptedKey: EncryptedPayload,
  masterKey: Buffer,
  message: string,
  encoding: 'utf8' | 'base64' = 'utf8'
): string {
  const privateKey = envelopeDecrypt(encryptedKey, masterKey);

  // bs58 for base58 encoding (Solana standard)
  const bs58 = require('bs58');
  const encode = bs58.default?.encode || bs58.encode;

  try {
    const keypair = Keypair.fromSeed(privateKey);
    const messageBuffer = Buffer.from(message, encoding);

    // Use nacl sign for Ed25519
    // @solana/web3.js uses tweetnacl internally
    const nacl = require('tweetnacl');
    const signature = nacl.sign.detached(messageBuffer, keypair.secretKey);

    // Return base58 encoded signature (Solana ecosystem standard)
    return encode(signature);
  } finally {
    zeroize(privateKey);
  }
}

/**
 * Sign an arbitrary message (EVM)
 *
 * @param encryptedKey - Encrypted wallet from storage
 * @param masterKey - Master key from OS Keychain
 * @param message - Message to sign
 * @returns Hex encoded signature
 */
export async function signEvmMessage(
  encryptedKey: EncryptedPayload,
  masterKey: Buffer,
  message: string
): Promise<string> {
  const privateKey = envelopeDecrypt(encryptedKey, masterKey);

  try {
    const privateKeyHex = '0x' + privateKey.toString('hex');
    const wallet = new Wallet(privateKeyHex);

    const signature = await wallet.signMessage(message);
    return signature;
  } finally {
    zeroize(privateKey);
  }
}

// ============================================================================
// Import Wallet (from existing private key)
// ============================================================================

/**
 * Import an existing wallet from a private key
 *
 * SECURITY: The provided private key is encrypted immediately and zeroized.
 * Caller should warn user to delete the original key source.
 *
 * @param chain - Blockchain the wallet is for
 * @param privateKeyInput - Private key (base58 for Solana, hex for EVM)
 * @param masterKey - Master key from OS Keychain
 * @returns Encrypted payload + wallet info
 */
export function importWallet(
  chain: Chain,
  privateKeyInput: string,
  masterKey: Buffer
): { encrypted: EncryptedPayload; info: WalletInfo } {
  const keyType = CHAIN_KEY_TYPES[chain];

  if (!keyType) {
    throw new VaultError('INVALID_CHAIN', `Unsupported chain: ${chain}`);
  }

  let walletData: WalletKeyData;

  if (chain === 'solana') {
    walletData = importSolanaWallet(chain, privateKeyInput);
  } else {
    walletData = importEvmWallet(chain, privateKeyInput);
  }

  return encryptWalletKey(walletData, masterKey);
}

/**
 * Import Solana wallet from base58 encoded private key
 */
function importSolanaWallet(chain: Chain, privateKeyBase58: string): WalletKeyData {
  try {
    // Decode base58 private key (handle bs58 v5 and v6 API)
    const bs58 = require('bs58');
    const decode = bs58.default?.decode || bs58.decode;
    const secretKey = decode(privateKeyBase58);

    // Solana secret keys can be 64 bytes (full) or 32 bytes (seed only)
    let seed: Buffer;
    if (secretKey.length === 64) {
      seed = Buffer.from(secretKey.slice(0, 32));
    } else if (secretKey.length === 32) {
      seed = Buffer.from(secretKey);
    } else {
      throw new VaultError('INTERNAL_ERROR', 'Invalid Solana private key length');
    }

    const keypair = Keypair.fromSeed(seed);

    return {
      chain,
      public_address: keypair.publicKey.toBase58(),
      key_type: 'ed25519',
      private_key: seed,
    };
  } catch (error) {
    if (error instanceof VaultError) throw error;
    throw new VaultError('INTERNAL_ERROR', 'Failed to import Solana wallet: invalid key format');
  }
}

/**
 * Import EVM wallet from hex encoded private key
 */
function importEvmWallet(chain: Chain, privateKeyHex: string): WalletKeyData {
  try {
    // Remove 0x prefix if present
    const cleanHex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const privateKey = Buffer.from(cleanHex, 'hex');

    if (privateKey.length !== 32) {
      throw new VaultError('INTERNAL_ERROR', 'Invalid EVM private key length');
    }

    const wallet = new Wallet('0x' + cleanHex);

    return {
      chain,
      public_address: wallet.address,
      key_type: 'secp256k1',
      private_key: privateKey,
    };
  } catch (error) {
    if (error instanceof VaultError) throw error;
    throw new VaultError('INTERNAL_ERROR', 'Failed to import EVM wallet: invalid key format');
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get public address from encrypted wallet (no decryption needed)
 *
 * This is stored alongside the ciphertext, not inside it.
 * Safe to return without consent.
 */
export function getPublicAddress(walletInfo: WalletInfo): string {
  return walletInfo.public_address;
}

/**
 * Get supported operations for a chain
 */
export function getSupportedOperations(chain: Chain): string[] {
  const keyType = CHAIN_KEY_TYPES[chain];
  if (!keyType) {
    throw new VaultError('INVALID_CHAIN', `Unsupported chain: ${chain}`);
  }
  return ['sign_tx', 'sign_message', 'get_address'];
}

/**
 * Validate chain is supported
 */
export function isChainSupported(chain: string): chain is Chain {
  return chain in CHAIN_KEY_TYPES;
}
