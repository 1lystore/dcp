/**
 * dcp pairing start
 *
 * Create a short-lived pairing token for proxy setup.
 *
 * Usage:
 *   dcp pairing start openclaw-vps --scopes sign:solana,read:credentials.* --budget 10usdc/day --auto-approve-under 1usdc
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { VaultStorage } from '@dcprotocol/core';
import {
  error,
  success,
  handleError,
  dim,
  highlight,
} from '../utils.js';

const startCommand = new Command('start')
  .description('Create a pairing token for proxy setup')
  .argument('<service>', 'Service identifier (e.g., openclaw-vps)')
  .option('-s, --scopes <scopes>', 'Comma-separated list of allowed scopes')
  .option('-b, --budget <budget>', 'Daily budget (e.g., 10usdc/day, 50usdc)')
  .option('-a, --auto-approve-under <amount>', 'Auto-approve threshold (e.g., 1usdc)')
  .option('-t, --ttl <seconds>', 'Token TTL in seconds (default: 600)')
  .action(async (serviceId: string, options) => {
    try {
      await startPairing(serviceId, options);
    } catch (err) {
      handleError(err);
    }
  });

export const pairingCommand = new Command('pairing')
  .description('Manage pairing tokens for proxy setup')
  .addCommand(startCommand);

async function startPairing(
  serviceId: string,
  options: { scopes?: string; budget?: string; autoApproveUnder?: string; ttl?: string }
): Promise<void> {
  if (!options.scopes) {
    error('Scopes are required');
    console.log();
    console.log(dim('Usage: dcp pairing start <service> --scopes sign:solana,read:credentials.*'));
    console.log();
    process.exit(1);
  }

  const storage = new VaultStorage();
  storage.initializeSchema();

  const scopes = parseScopes(options.scopes);
  const budget = parseBudget(options.budget || '10usdc/day');
  const autoApprove = options.autoApproveUnder ? parseAmount(options.autoApproveUnder) : 0;
  const ttlSeconds = options.ttl ? parseInt(options.ttl, 10) : undefined;

  const result = storage.createPairingToken({
    service_id: serviceId,
    scopes,
    budget: {
      daily: budget.daily,
      currency: budget.currency,
      auto_approve_under: autoApprove,
    },
    ttl_seconds: ttlSeconds,
  });

  console.log();
  console.log(chalk.bold('Pairing Token'));
  console.log(dim('─'.repeat(60)));
  console.log();
  console.log(`  ${dim('Service:')} ${highlight(serviceId)}`);
  console.log(`  ${dim('Scopes:')}  ${scopes.join(', ')}`);
  console.log(`  ${dim('Budget:')}  ${budget.daily} ${budget.currency}/day`);
  if (autoApprove > 0) {
    console.log(`  ${dim('Auto:')}    < ${autoApprove} ${budget.currency}`);
  }
  console.log(`  ${dim('Expires:')} ${result.expires_at}`);
  console.log();
  console.log(chalk.bold('Token:'));
  console.log(result.token);
  console.log();
  success('Use this token with: dcp proxy --pair <token>');
  console.log();
}

function parseScopes(scopesStr: string): string[] {
  return scopesStr
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseBudget(budgetStr: string): { daily: number; currency: string } {
  const match = budgetStr.match(/^([\d.]+)\s*(\w+)(?:\/day)?$/i);
  if (!match) {
    return { daily: 10, currency: 'USDC' };
  }

  return {
    daily: parseFloat(match[1]),
    currency: match[2].toUpperCase(),
  };
}

function parseAmount(amountStr: string): number {
  const match = amountStr.match(/^([\d.]+)/);
  if (!match) return 0;
  return parseFloat(match[1]);
}
