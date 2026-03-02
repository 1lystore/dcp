/**
 * dcp config
 *
 * View and manage vault configuration (PRD C9).
 *
 * Usage:
 *   dcp config show                      # Show current config
 *   dcp config set tx_limit.SOL 5        # Set SOL tx limit to 5
 *   dcp config set daily_budget.ETH 2    # Set ETH daily budget to 2
 *   dcp config set approval_threshold.USDC 100
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  error,
  success,
  info,
  handleError,
  dim,
  highlight,
} from '../utils.js';
import { VaultStorage, BudgetEngine, getBudgetEngine, getStorage } from '@dcprotocol/core';

export const configCommand = new Command('config')
  .description('View and manage vault configuration')
  .argument('[action]', 'Action: show, set')
  .argument('[key]', 'Config key (e.g., tx_limit.SOL, daily_budget.ETH)')
  .argument('[value]', 'Value to set')
  .action(async (action?: string, key?: string, value?: string) => {
    try {
      await runConfig(action, key, value);
    } catch (err) {
      handleError(err);
    }
  });

async function runConfig(action?: string, key?: string, value?: string): Promise<void> {
  const storage = getStorage();
  const budget = getBudgetEngine(storage);

  // Default to 'show' if no action provided
  if (!action || action === 'show') {
    await showConfig(budget);
    return;
  }

  if (action === 'set') {
    if (!key || value === undefined) {
      error('Usage: dcp config set <key> <value>');
      console.log();
      info('Examples:');
      console.log(dim('  dcp config set tx_limit.SOL 5'));
      console.log(dim('  dcp config set daily_budget.ETH 2'));
      console.log(dim('  dcp config set approval_threshold.USDC 100'));
      console.log(dim('  dcp config set rate_limit_per_minute 10'));
      console.log();
      return;
    }

    await setConfig(budget, key, value);
    return;
  }

  error(`Unknown action: ${action}`);
  console.log();
  info('Available actions: show, set');
  console.log();
}

/**
 * Show current configuration
 */
async function showConfig(budget: BudgetEngine): Promise<void> {
  const config = budget.getConfig();

  console.log();
  console.log(chalk.bold('Vault Configuration'));
  console.log(dim('─'.repeat(60)));
  console.log();

  // Budget section
  console.log(chalk.bold('Budget Limits'));
  console.log();

  // Create a table of all currencies
  const currencies = new Set([
    ...Object.keys(config.daily_budget),
    ...Object.keys(config.tx_limit),
    ...Object.keys(config.approval_threshold),
  ]);

  // Table header
  console.log(
    `  ${dim('Currency'.padEnd(12))} ${dim('Daily'.padEnd(12))} ${dim('Per-Tx'.padEnd(12))} ${dim('Approval')}`
  );
  console.log(dim('  ' + '─'.repeat(50)));

  for (const currency of currencies) {
    const daily = config.daily_budget[currency] ?? '-';
    const tx = config.tx_limit[currency] ?? '-';
    const approval = config.approval_threshold[currency] ?? '-';

    console.log(
      `  ${highlight(currency.padEnd(12))} ${String(daily).padEnd(12)} ${String(tx).padEnd(12)} ${approval}`
    );
  }

  console.log();

  // Rate limit
  console.log(chalk.bold('Rate Limiting'));
  console.log();
  console.log(`  ${dim('Executions per minute:')} ${highlight(String(config.rate_limit_per_minute))}`);
  console.log();

  // Session defaults
  console.log(chalk.bold('Session Defaults'));
  console.log();
  console.log(`  ${dim('Session idle timeout:')} ${highlight(String(config.session_timeout_minutes))} min`);
  console.log(`  ${dim('Session max duration:')} ${highlight(String(config.session_max_hours))} hours`);
  console.log();

  console.log(dim('─'.repeat(60)));
  console.log();
  console.log(dim('To change: dcp config set <key> <value>'));
  console.log(dim('Examples:  dcp config set tx_limit.SOL 10'));
  console.log(dim('           dcp config set rate_limit_per_minute 5'));
  console.log();
}

/**
 * Set a configuration value
 */
async function setConfig(budget: BudgetEngine, key: string, value: string): Promise<void> {
  // Parse the key to determine what we're setting
  const parts = key.split('.');

  if (parts.length === 2) {
    // Budget limit format: tx_limit.SOL, daily_budget.ETH, etc.
    const [type, currency] = parts;

    if (!['tx_limit', 'daily_budget', 'approval_threshold'].includes(type)) {
      error(`Unknown budget type: ${type}`);
      console.log();
      info('Valid types: tx_limit, daily_budget, approval_threshold');
      console.log();
      return;
    }

    const amount = parseFloat(value);
    if (isNaN(amount)) {
      error(`Invalid amount: ${value}`);
      return;
    }

    budget.setLimit(type as 'tx_limit' | 'daily_budget' | 'approval_threshold', currency.toUpperCase(), amount);

    console.log();
    success(`Set ${type}.${currency.toUpperCase()} = ${amount}`);
    console.log();
    return;
  }

  // Single key format: rate_limit_per_minute, session_timeout_minutes, etc.
  const numericKeys = ['rate_limit_per_minute', 'session_timeout_minutes', 'session_max_hours'];

  if (numericKeys.includes(key)) {
    const numValue = parseFloat(value);
    if (isNaN(numValue)) {
      error(`Invalid numeric value: ${value}`);
      return;
    }

    budget.setConfig(key as 'rate_limit_per_minute' | 'session_timeout_minutes' | 'session_max_hours', numValue);

    console.log();
    success(`Set ${key} = ${numValue}`);
    console.log();
    return;
  }

  error(`Unknown config key: ${key}`);
  console.log();
  info('Valid keys:');
  console.log(dim('  tx_limit.<CURRENCY>'));
  console.log(dim('  daily_budget.<CURRENCY>'));
  console.log(dim('  approval_threshold.<CURRENCY>'));
  console.log(dim('  rate_limit_per_minute'));
  console.log(dim('  session_timeout_minutes'));
  console.log(dim('  session_max_hours'));
  console.log();
}
