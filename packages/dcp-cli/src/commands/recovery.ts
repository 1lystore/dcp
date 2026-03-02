/**
 * dcp recovery
 *
 * Recovery commands for the vault (PRD C10).
 *
 * Usage:
 *   dcp recovery show-phrase        # Explain recovery phrase is only shown at init
 *   dcp recovery restore            # Restore vault from recovery phrase
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  success,
  error,
  info,
  warn,
  spinner,
  confirmPassphrase,
  confirm,
  handleError,
  dim,
} from '../utils.js';
import {
  VaultStorage,
  deriveKeyFromMnemonic,
  validateMnemonic,
  zeroize,
} from '@dcprotocol/core';
import prompts from 'prompts';

export const recoveryCommand = new Command('recovery')
  .description('Recovery and backup commands');

// =============================================================================
// show-phrase subcommand
// =============================================================================

recoveryCommand
  .command('show-phrase')
  .description('Explain recovery phrase is only shown once at init')
  .action(async () => {
    try {
      await runShowPhrase();
    } catch (err) {
      handleError(err);
    }
  });

async function runShowPhrase(): Promise<void> {
  console.log();
  warn('Recovery phrases are never stored by design.');
  warn('You can only view the phrase once during `dcp init`.');
  console.log();
  info('If you lost it, create a new vault and re-import data.');
}

// =============================================================================
// restore subcommand
// =============================================================================

recoveryCommand
  .command('restore')
  .description('Restore vault from recovery phrase')
  .action(async () => {
    try {
      await runRestore();
    } catch (err) {
      handleError(err);
    }
  });

async function runRestore(): Promise<void> {
  const storage = new VaultStorage();

  console.log();
  console.log(chalk.bold('Restore Vault from Recovery Phrase'));
  console.log(dim('─'.repeat(50)));
  console.log();

  if (storage.isInitialized()) {
    warn('A vault already exists in this location.');
    info('Restoring will re-encrypt the master key with your new passphrase.');
    info('If you enter the SAME recovery phrase used to create this vault,');
    info('your existing data will be accessible with the new passphrase.');
    console.log();

    const proceed = await confirm('Continue?', false);
    if (!proceed) {
      info('Cancelled');
      return;
    }
    console.log();
  }

  // Get recovery phrase from user
  info('Enter your 12-word recovery phrase:');
  console.log();

  const response = await prompts({
    type: 'text',
    name: 'mnemonic',
    message: 'Recovery phrase',
    validate: (value: string) => {
      const words = value.trim().split(/\s+/);
      if (words.length !== 12) {
        return 'Recovery phrase must be exactly 12 words';
      }
      if (!validateMnemonic(value.trim())) {
        return 'Invalid recovery phrase. Please check your words.';
      }
      return true;
    },
  });

  if (!response.mnemonic) {
    error('Recovery phrase is required');
    process.exit(1);
  }

  const mnemonic = response.mnemonic.trim().toLowerCase();

  // Get new passphrase
  console.log();
  info('Choose a new passphrase to protect your restored vault.');
  console.log();

  const passphrase = await confirmPassphrase();

  if (passphrase.length < 8) {
    error('Passphrase must be at least 8 characters');
    process.exit(1);
  }

  // Restore vault
  console.log();
  const spin = spinner('Deriving master key from recovery phrase...');
  spin.start();

  // Derive master key from recovery phrase (BIP-39)
  const masterKey = deriveKeyFromMnemonic(mnemonic);

  try {
    // Initialize schema (creates tables if not exist)
    storage.initializeSchema();
    spin.text = 'Encrypting with new passphrase (Argon2id)...';

    // Store master key encrypted with new passphrase
    await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);

    spin.succeed('Vault restored successfully');
  } catch (err) {
    spin.fail('Failed to restore vault');
    throw err;
  } finally {
    // CRITICAL: Zeroize master key from memory
    zeroize(masterKey);
  }

  console.log();
  success('Vault has been restored!');
  console.log();
  info('Your vault is now accessible with your new passphrase.');
  info('If you used the same recovery phrase as the original vault,');
  info('all existing wallets and data should now be readable.');
  console.log();
  info('Next steps:');
  console.log(`  ${chalk.cyan('dcp list')}    Check your restored data`);
  console.log(`  ${chalk.cyan('dcp status')}  Check vault status`);
  console.log();
}
