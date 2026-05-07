/**
 * dcp read <scope>
 *
 * Read a single record from the vault with explicit confirmation.
 * - STANDARD/SENSITIVE: requires passphrase + confirmation
 * - CRITICAL: never shows plaintext (only metadata)
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  success,
  error,
  info,
  warn,
  spinner,
  unlockVault,
  confirm,
  handleError,
  formatScope,
  formatSensitivity,
  dim,
  highlight,
} from '../utils.js';
import { VaultStorage, envelopeDecrypt, zeroize } from '@dcprotocol/core';

export const readCommand = new Command('read')
  .description('Read a single record (explicit confirmation required)')
  .argument('<scope>', 'Scope to read (e.g., address.home, identity.email)')
  .action(async (scope) => {
    try {
      await runRead(scope);
    } catch (err) {
      handleError(err);
    }
  });

async function runRead(scope: string): Promise<void> {
  const storage = new VaultStorage();

  if (!storage.isInitialized()) {
    error('Vault not initialized. Run: dcp init');
    process.exit(1);
  }

  const normalizedScope = normalizeScope(scope);
  let record = storage.getRecord(normalizedScope);
  let resolvedScope = normalizedScope;

  if (!record) {
    const all = storage.listRecords().map((r) => r.scope);
    const matches = all.filter((s) => s.toLowerCase() === normalizedScope.toLowerCase());

    if (matches.length === 1) {
      resolvedScope = matches[0];
      record = storage.getRecord(resolvedScope);
    } else {
      const fuzzy = all.filter((s) =>
        s.toLowerCase().endsWith(normalizedScope.toLowerCase())
      );
      if (fuzzy.length === 1) {
        resolvedScope = fuzzy[0];
        record = storage.getRecord(resolvedScope);
      }
    }
  }

  if (!record) {
    error(`No record found for ${formatScope(scope)}`);
    const all = storage.listRecords().map((r) => r.scope);
    const prefix = scope.split('.')[0];
    const prefixMatches = all.filter((s) => s.startsWith(`${prefix}.`));
    if (prefixMatches.length === 0) {
      info(`No records found under ${formatScope(prefix + '.*')}.`);
      info(`Add one with: ${highlight(`dcp add ${prefix}.home`)}`);
    } else {
      info('Tip: use the full scope shown in `dcp list` (e.g., crypto.wallet.solana).');
    }
    process.exit(1);
  }

  console.log();
  console.log(chalk.bold(`Read ${formatScope(resolvedScope)}`));
  console.log(dim('─'.repeat(60)));
  console.log();
  info(`Sensitivity: ${formatSensitivity(record.sensitivity)}`);

  if (record.item_type === 'WALLET_KEY' && record.public_address) {
    info(`Address: ${highlight(record.public_address)}`);
  }
  console.log();

  if (record.sensitivity === 'critical') {
    warn('CRITICAL data is never displayed in plaintext.');
    info('Use the agent flow (vault_read / vault_sign_tx) for operations.');
    console.log();
    return;
  }

  info('Press Esc or Ctrl+C to cancel.');
  const confirmMsg = record.sensitivity === 'sensitive'
    ? `Display sensitive data for ${formatScope(resolvedScope)}?`
    : `Display data for ${formatScope(resolvedScope)}?`;

  const approved = await confirm(confirmMsg, record.sensitivity !== 'sensitive');
  if (!approved) {
    info('Cancelled.');
    process.exit(0);
  }

  // Unlock vault
  const spin = spinner('Unlocking vault...');
  spin.start();

  try {
    await unlockVault(storage, 'Enter vault passphrase', () => spin.stop());
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

  // Decrypt record
  const dataSpin = spinner('Decrypting...');
  dataSpin.start();

  try {
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(resolvedScope);
    if (!payload) {
      dataSpin.fail('Record not found');
      process.exit(1);
    }

    const plaintext = envelopeDecrypt(payload, masterKey);
    try {
      const json = JSON.parse(plaintext.toString('utf8'));
      dataSpin.succeed('Decrypted');
      console.log();
      console.log(chalk.bold('Data'));
      console.log(dim('─'.repeat(60)));
      console.log(chalk.gray(JSON.stringify(json, null, 2)));
      console.log();
      success('Done');
    } catch {
      dataSpin.succeed('Decrypted');
      console.log();
      console.log(chalk.bold('Data'));
      console.log(dim('─'.repeat(60)));
      console.log(plaintext.toString('utf8'));
      console.log();
      success('Done');
    } finally {
      zeroize(plaintext);
    }
  } catch (err) {
    dataSpin.fail('Failed to decrypt');
    throw err;
  } finally {
    storage.lock();
  }
}

function normalizeScope(scope: string): string {
  const trimmed = scope.trim();
  if (trimmed.startsWith('wallet.')) {
    return `crypto.${trimmed}`;
  }
  return trimmed;
}
