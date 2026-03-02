/**
 * dcp create-wallet
 *
 * Generate a new wallet inside the vault:
 * 1. Generate keypair (Ed25519 for Solana, secp256k1 for EVM)
 * 2. Encrypt immediately with per-record DEK
 * 3. Store in vault
 * 4. Display only the public address
 *
 * The private key is NEVER displayed, exported, or accessible.
 */

import { Command } from 'commander';
import {
  success,
  error,
  info,
  warn,
  spinner,
  getPassphrase,
  handleError,
  highlight,
  formatChain,
  box,
} from '../utils.js';
import {
  VaultStorage,
  createWallet,
  Chain,
  isChainSupported,
} from '@dcprotocol/core';

export const createWalletCommand = new Command('create-wallet')
  .description('Generate a new wallet inside the vault')
  .requiredOption('-c, --chain <chain>', 'Blockchain: solana, base, or ethereum')
  .action(async (options) => {
    try {
      await runCreateWallet(options);
    } catch (err) {
      handleError(err);
    }
  });

async function runCreateWallet(options: { chain: string }): Promise<void> {
  const chain = options.chain.toLowerCase();

  // Validate chain
  if (!isChainSupported(chain)) {
    error(`Unsupported chain: ${chain}`);
    info('Supported chains: solana, base, ethereum');
    process.exit(1);
  }

  const storage = new VaultStorage();

  // Check vault is initialized
  if (!storage.isInitialized()) {
    error('Vault not initialized. Run: dcp init');
    process.exit(1);
  }

  // Check if wallet already exists for this chain
  const scope = `crypto.wallet.${chain}`;
  const existing = storage.getRecord(scope);

  if (existing) {
    error(`Wallet already exists for ${formatChain(chain)}`);
    info(`Public address: ${highlight(existing.public_address || 'N/A')}`);
    process.exit(1);
  }

  // Unlock vault
  info(`Creating ${formatChain(chain)} wallet...`);
  console.log();

  const passphrase = await getPassphrase('Enter vault passphrase');

  const spin = spinner('Unlocking vault...');
  spin.start();

  try {
    await storage.unlock(passphrase);
    spin.succeed('Vault unlocked');
  } catch (err) {
    spin.fail('Failed to unlock vault');
    if (err instanceof Error && err.message.includes('Wrong passphrase')) {
      error('Wrong passphrase');
    } else {
      throw err;
    }
    process.exit(1);
  }

  // Generate wallet
  const genSpin = spinner('Generating keypair...');
  genSpin.start();

  try {
    const masterKey = storage.getMasterKey();
    const { encrypted, info: walletInfo } = createWallet(chain as Chain, masterKey);

    genSpin.text = 'Encrypting and storing...';

    // Store in vault
    storage.createRecord({
      scope,
      item_type: 'WALLET_KEY',
      sensitivity: 'critical',
      data: encrypted,
      chain: chain as Chain,
      public_address: walletInfo.public_address,
    });

    genSpin.succeed('Wallet created');

    // Display result
    console.log();
    box(
      [
        `Chain:   ${formatChain(chain)}`,
        `Address: ${highlight(walletInfo.public_address)}`,
        '',
        'Your private key is encrypted inside the vault.',
        'It will NEVER be displayed or exported.',
      ],
      'NEW WALLET'
    );

    success('Wallet created successfully!');
    console.log();
    info('To sign transactions, agents call vault_sign_tx()');
    info(`To see this address: ${highlight(`dcp list --chain ${chain}`)}`);
  } catch (err) {
    genSpin.fail('Failed to create wallet');
    throw err;
  } finally {
    // Always lock vault after operation
    storage.lock();
  }
}
