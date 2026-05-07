/**
 * dcp remove <scope>
 *
 * Remove data from the vault:
 * - Requires confirmation
 * - Wallets require extra confirmation
 * - Logs deletion to audit
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
} from '../utils.js';
import { VaultStorage } from '@dcprotocol/core';

export const removeCommand = new Command('remove')
  .description('Remove data from the vault')
  .argument('<scope>', 'Data scope to remove (e.g., address.home)')
  .option('-f, --force', 'Skip confirmation (use with caution)')
  .action(async (scope, options) => {
    try {
      await runRemove(scope, options);
    } catch (err) {
      handleError(err);
    }
  });

async function runRemove(scope: string, options: { force?: boolean }): Promise<void> {
  const storage = new VaultStorage();

  // Check vault is initialized
  if (!storage.isInitialized()) {
    error('Vault not initialized. Run: dcp init');
    process.exit(1);
  }

  // Prevent removing internal records
  if (scope.startsWith('__')) {
    error('Cannot remove internal vault records');
    process.exit(1);
  }

  // Check if scope exists
  const existing = storage.getRecord(scope);
  if (!existing) {
    error(`Scope ${formatScope(scope)} does not exist.`);
    process.exit(1);
  }

  console.log();
  console.log(chalk.bold('Remove ' + formatScope(scope)));
  console.log(dim('─'.repeat(50)));
  console.log();

  // Show record info
  console.log(`  ${dim('Type:')}        ${existing.item_type}`);
  console.log(`  ${dim('Sensitivity:')} ${formatSensitivity(existing.sensitivity)}`);
  if (existing.public_address) {
    console.log(`  ${dim('Address:')}     ${existing.public_address}`);
  }
  console.log(`  ${dim('Created:')}     ${existing.created_at}`);
  console.log();

  // Extra warning for wallets
  if (existing.item_type === 'WALLET_KEY') {
    warn('You are about to delete a WALLET.');
    warn('This action is IRREVERSIBLE. The private key will be permanently deleted.');
    warn('Make sure you have backed up any funds in this wallet.');
    console.log();
  }

  // Confirmation
  if (!options.force) {
    const confirmMsg = existing.item_type === 'WALLET_KEY'
      ? `Type "DELETE" to confirm removal of wallet ${formatScope(scope)}`
      : `Are you sure you want to remove ${formatScope(scope)}?`;

    if (existing.item_type === 'WALLET_KEY') {
      // Require typing "DELETE" for wallets
      const { default: prompts } = await import('prompts');
      const response = await prompts(
        {
          type: 'text',
          name: 'confirm',
          message: confirmMsg,
        },
        {
          onCancel: () => {
            throw new Error('Cancelled');
          },
        }
      );

      if (response.confirm !== 'DELETE') {
        info('Cancelled');
        return;
      }
    } else {
      const confirmed = await confirm(confirmMsg, false);
      if (!confirmed) {
        info('Cancelled');
        return;
      }
    }
    console.log();
  }

  // Unlock vault
  const spin = spinner('Unlocking vault...');
  spin.start();

  try {
    await unlockVault(storage, 'Enter vault passphrase to confirm', () => spin.stop());
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

  // Delete record
  const deleteSpin = spinner('Removing...');
  deleteSpin.start();

  try {
    const deleted = storage.deleteRecord(scope);

    if (deleted) {
      deleteSpin.succeed('Record removed');

      // Log to audit
      storage.logAudit('EXECUTE', 'success', {
        operation: 'remove_record',
        scope,
        details: JSON.stringify({
          item_type: existing.item_type,
          sensitivity: existing.sensitivity,
        }),
      });

      console.log();
      success(`${formatScope(scope)} has been removed from the vault`);
    } else {
      deleteSpin.fail('Failed to remove record');
      error('Record not found or already deleted');
    }
  } catch (err) {
    deleteSpin.fail('Failed to remove');
    throw err;
  } finally {
    storage.lock();
  }
}
