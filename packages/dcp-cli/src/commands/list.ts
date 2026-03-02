/**
 * dcp list
 *
 * List all stored scopes (without showing values):
 * - Scopes grouped by category
 * - Sensitivity levels shown
 * - For wallets: show public address
 * - Filter by type or chain
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  success,
  error,
  info,
  handleError,
  formatScope,
  formatChain,
  formatSensitivity,
  formatDate,
  dim,
  highlight,
} from '../utils.js';
import { VaultStorage } from '@dcprotocol/core';

export const listCommand = new Command('list')
  .description('List all stored scopes (values not shown)')
  .option('-t, --type <type>', 'Filter by type: wallet, identity, address, preferences')
  .option('-c, --chain <chain>', 'Filter by chain: solana, base, ethereum')
  .option('-v, --verbose', 'Show additional details')
  .action(async (options) => {
    try {
      await runList(options);
    } catch (err) {
      handleError(err);
    }
  });

async function runList(options: {
  type?: string;
  chain?: string;
  verbose?: boolean;
}): Promise<void> {
  const storage = new VaultStorage();

  // Check vault is initialized
  if (!storage.isInitialized()) {
    error('Vault not initialized. Run: dcp init');
    process.exit(1);
  }

  // Get all records (this doesn't need unlock - we only read metadata)
  const records = storage.listRecords();

  if (records.length === 0) {
    info('No data stored in vault.');
    console.log();
    info('Get started:');
    console.log(`  ${highlight('dcp create-wallet --chain solana')}  Create a wallet`);
    console.log(`  ${highlight('dcp add address.home')}              Add your address`);
    return;
  }

  // Filter records
  let filtered = records;

  if (options.type) {
    const typeMap: Record<string, string> = {
      wallet: 'WALLET_KEY',
      identity: 'IDENTITY',
      address: 'ADDRESS',
      preferences: 'PREFERENCES',
    };
    const itemType = typeMap[options.type.toLowerCase()];
    if (!itemType) {
      error(`Unknown type: ${options.type}`);
      info('Valid types: wallet, identity, address, preferences');
      process.exit(1);
    }
    filtered = filtered.filter((r) => r.item_type === itemType);
  }

  if (options.chain) {
    filtered = filtered.filter((r) => r.chain === options.chain.toLowerCase());
  }

  if (filtered.length === 0) {
    info('No matching records found.');
    return;
  }

  // Group by category
  const groups: Record<string, typeof filtered> = {};

  for (const record of filtered) {
    const category = record.scope.split('.')[0];
    if (!groups[category]) {
      groups[category] = [];
    }
    groups[category].push(record);
  }

  // Display
  console.log();
  console.log(chalk.bold('Vault Contents'));
  console.log(dim('─'.repeat(60)));
  console.log();

  for (const [category, items] of Object.entries(groups)) {
    console.log(chalk.bold.underline(capitalize(category)));
    console.log();

    for (const item of items) {
      const scopePart = item.scope.replace(`${category}.`, '');

      // First line: scope and sensitivity
      process.stdout.write(`  ${formatScope(scopePart)}`);
      process.stdout.write(`  ${formatSensitivity(item.sensitivity)}`);

      // For wallets: show chain and address
      if (item.item_type === 'WALLET_KEY' && item.chain) {
        process.stdout.write(`  ${formatChain(item.chain)}`);
      }
      console.log();

      // Second line: details
      if (item.item_type === 'WALLET_KEY' && item.public_address) {
        console.log(`    ${dim('Address:')} ${highlight(item.public_address)}`);
      }

      if (options.verbose) {
        console.log(`    ${dim('Created:')} ${formatDate(item.created_at)}`);
        console.log(`    ${dim('Updated:')} ${formatDate(item.updated_at)}`);
      }

      console.log();
    }
  }

  // Summary
  console.log(dim('─'.repeat(60)));
  console.log(
    dim(`${filtered.length} record${filtered.length !== 1 ? 's' : ''} total`)
  );

  const wallets = filtered.filter((r) => r.item_type === 'WALLET_KEY').length;
  if (wallets > 0) {
    console.log(dim(`${wallets} wallet${wallets !== 1 ? 's' : ''}`));
  }

  console.log();
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
