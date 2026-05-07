/**
 * dcp init
 *
 * Initialize a new vault:
 * 1. Generate master key
 * 2. Encrypt with passphrase via Argon2id
 * 3. Store in OS Keychain (or file fallback)
 * 4. Create SQLite database
 * 5. Generate and display recovery phrase
 */

import { Command } from 'commander';
import {
  success,
  error,
  info,
  warn,
  box,
  spinner,
  confirmPassphrase,
  handleError,
  highlight,
  bold,
  dim,
} from '../utils.js';
import {
  VaultStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
} from '@dcprotocol/core';

export const initCommand = new Command('init')
  .description('Initialize a new vault')
  .option('-f, --force', 'Reinitialize even if vault already exists')
  .action(async (options) => {
    try {
      await runInit(options);
    } catch (err) {
      handleError(err);
    }
  });

async function runInit(options: { force?: boolean }): Promise<void> {
  info('Initializing DCP Vault...');
  console.log();

  // Check if vault already exists
  const storage = new VaultStorage();

  if (storage.isInitialized() && !options.force) {
    error('Vault already initialized.');
    info('Use --force to reinitialize (WARNING: this will destroy existing data)');
    process.exit(1);
  }

  if (options.force && storage.isInitialized()) {
    warn('Reinitializing vault. All existing data will be lost!');
    console.log();
  }

  // Get passphrase from user
  info('Choose a strong passphrase to protect your vault.');
  info('You will need this passphrase to unlock your vault.');
  console.log();

  const passphrase = await confirmPassphrase();

  if (passphrase.length < 8) {
    error('Passphrase must be at least 8 characters');
    process.exit(1);
  }

  // Generate recovery phrase - this IS the source of the master key
  const recoveryPhrase = generateRecoveryMnemonic();

  // Initialize database schema and master key with spinner
  const spin = spinner('Creating database schema...');
  spin.start();

  // Derive master key from recovery phrase (BIP-39)
  const masterKey = deriveKeyFromMnemonic(recoveryPhrase);

  try {
    // Create database tables first
    storage.initializeSchema();
    spin.text = 'Deriving master key from recovery phrase...';

    // Store master key encrypted with passphrase
    spin.text = 'Encrypting master key (Argon2id)...';
    await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);

    spin.succeed('Vault created and master key stored');
  } catch (err) {
    spin.fail('Failed to initialize vault');
    throw err;
  } finally {
    // CRITICAL: Zeroize master key from memory
    zeroize(masterKey);
  }

  // Display recovery phrase
  console.log();
  box(
    [
      bold('RECOVERY PHRASE'),
      '',
      ...formatRecoveryPhrase(recoveryPhrase),
      '',
      dim('Write these 12 words down and store them safely.'),
      dim('This is the ONLY way to recover your vault if you forget your passphrase.'),
      dim('This phrase will NOT be shown again.'),
    ],
    'IMPORTANT'
  );

  // Final success message
  success('Vault initialized successfully!');
  console.log();
  info('Next steps:');
  console.log(`  ${highlight('dcp create-wallet --chain solana')}  Create your first wallet`);
  console.log(`  ${highlight('dcp add address.home')}              Add your home address`);
  console.log(`  ${highlight('dcp status')}                        Check vault status`);
  console.log();
}

/**
 * Format recovery phrase for display (4 words per line, numbered)
 */
function formatRecoveryPhrase(phrase: string): string[] {
  const words = phrase.split(' ');
  const lines: string[] = [];

  for (let i = 0; i < words.length; i += 4) {
    const chunk = words.slice(i, i + 4);
    const numbered = chunk.map((w, j) => `${String(i + j + 1).padStart(2)}. ${w}`);
    lines.push(numbered.join('    '));
  }

  return lines;
}
