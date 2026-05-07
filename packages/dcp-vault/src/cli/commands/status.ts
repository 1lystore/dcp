/**
 * dcp status
 *
 * Show vault status:
 * - Initialized/not initialized
 * - Locked/unlocked
 * - Number of wallets
 * - Number of records
 * - Active sessions
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  error,
  info,
  handleError,
  formatChain,
  highlight,
  dim,
  bold,
} from '../utils.js';
import { VaultStorage } from '@dcprotocol/core';
import os from 'os';
import path from 'path';

export const statusCommand = new Command('status')
  .description('Show vault status')
  .action(async () => {
    try {
      await runStatus();
    } catch (err) {
      handleError(err);
    }
  });

async function runStatus(): Promise<void> {
  const storage = new VaultStorage();
  const vaultDir = path.join(os.homedir(), '.dcp');

  console.log();
  console.log(chalk.bold('DCP Vault Status'));
  console.log(dim('─'.repeat(40)));
  console.log();

  // Initialized?
  const initialized = storage.isInitialized();
  console.log(
    `${dim('Initialized:')}  ${initialized ? chalk.green('Yes') : chalk.red('No')}`
  );

  if (!initialized) {
    console.log();
    info('Run: dcp init');
    return;
  }

  // Vault directory
  console.log(`${dim('Location:')}     ${vaultDir}`);

  // Locked status
  const unlocked = storage.isUnlocked();
  console.log(
    `${dim('Status:')}       ${unlocked ? chalk.yellow('Unlocked') : chalk.green('Locked')}`
  );

  console.log();

  // Record counts
  const records = storage.listRecords();
  const wallets = records.filter((r) => r.item_type === 'WALLET_KEY');
  const identity = records.filter((r) => r.item_type === 'IDENTITY');
  const addresses = records.filter((r) => r.item_type === 'ADDRESS');
  const preferences = records.filter((r) => r.item_type === 'PREFERENCES');

  console.log(chalk.bold('Records'));
  console.log(`  ${dim('Wallets:')}      ${wallets.length}`);

  // Show wallet details
  for (const wallet of wallets) {
    const chain = wallet.chain || 'unknown';
    const address = wallet.public_address || 'N/A';
    console.log(`    ${formatChain(chain)}: ${highlight(truncateAddress(address))}`);
  }

  console.log(`  ${dim('Identity:')}     ${identity.length}`);
  console.log(`  ${dim('Addresses:')}    ${addresses.length}`);
  console.log(`  ${dim('Preferences:')}  ${preferences.length}`);
  console.log(`  ${dim('Total:')}        ${records.length}`);

  console.log();

  // Active sessions
  const sessions = storage.listActiveSessions();
  console.log(chalk.bold('Active Sessions'));

  if (sessions.length === 0) {
    console.log(`  ${dim('None')}`);
  } else {
    for (const session of sessions) {
      // granted_scopes is already parsed as an array by listActiveSessions()
      const scopes = session.granted_scopes.length;
      console.log(`  ${session.agent_name} (${scopes} scopes, expires ${formatExpiry(session.expires_at)})`);
    }
  }

  console.log();
  console.log(dim('─'.repeat(40)));
  console.log();
}

function truncateAddress(address: string): string {
  if (address.length <= 16) return address;
  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function formatExpiry(expiresAt: string): string {
  const expires = new Date(expiresAt);
  const now = new Date();
  const diffMs = expires.getTime() - now.getTime();

  if (diffMs < 0) return 'expired';

  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return `${diffMins}m`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h`;

  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d`;
}
