/**
 * dcp trust <service>
 *
 * Add a trusted service to the vault (protocol spec section B2).
 *
 * Services authenticate with their own Ed25519 keypair.
 * User trusts them once; agents run autonomously within policies.
 *
 * Usage:
 *   dcp trust 1ly                                    # Trust known service with defaults
 *   dcp trust 1ly --scopes sign:solana             # Trust with specific scopes
 *   dcp trust my-bot --key=ed25519:... --scopes ... # Trust custom service
 *   dcp trust 1ly --budget 10usdc/day              # Set daily budget
 *   dcp trust 1ly --auto-approve-under 1usdc       # Auto-approve threshold
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  error,
  success,
  info,
  warn,
  handleError,
  dim,
  bold,
  highlight,
  spinner,
  unlockVault,
  confirm,
  input,
  select,
} from '../utils.js';
import {
  VaultStorage,
  getKnownService,
  isKnownService,
  isValidPublicKey,
  type TrustedService,
} from '@dcprotocol/core';

// ============================================================================
// Command Definition
// ============================================================================

export const trustCommand = new Command('trust')
  .description('Add a trusted service to the vault')
  .argument('<service>', 'Service identifier (e.g., 1ly, virtuals, or custom name)')
  .option('-k, --key <key>', 'Ed25519 public key (required for custom services)')
  .option('-s, --scopes <scopes>', 'Comma-separated list of allowed scopes')
  .option('-b, --budget <budget>', 'Daily budget (e.g., 10usdc/day, 50usdc)')
  .option('-a, --auto-approve-under <amount>', 'Auto-approve threshold (e.g., 1usdc)')
  .option('-l, --list', 'List all trusted services')
  .option('-r, --revoke', 'Revoke trust for this service')
  .option('-y, --yes', 'Skip confirmation prompts')
  .action(async (serviceId: string | undefined, options) => {
    try {
      if (options.list) {
        await listTrustedServices();
        return;
      }

      if (!serviceId) {
        await listTrustedServices();
        return;
      }

      if (options.revoke) {
        await revokeService(serviceId, options);
        return;
      }

      await addTrustedService(serviceId, options);
    } catch (err) {
      handleError(err);
    }
  });

// ============================================================================
// List Trusted Services
// ============================================================================

async function listTrustedServices(): Promise<void> {
  const storage = new VaultStorage();
  storage.initializeSchema();

  console.log();
  console.log(chalk.bold('Trusted Services'));
  console.log(dim('─'.repeat(70)));
  console.log();

  const services = storage.listTrustedServices();

  if (services.length === 0) {
    console.log(dim('  No trusted services'));
    console.log();
    console.log(dim('To trust a service:'));
    console.log(dim('  dcp trust 1ly                        # Trust known service'));
    console.log(dim('  dcp trust my-bot --key=ed25519:...   # Trust custom service'));
    console.log();
    return;
  }

  for (const service of services) {
    const status = service.enabled ? chalk.green('enabled') : chalk.red('disabled');
    const verified = service.verified ? chalk.blue(' (verified)') : '';
    const connected = service.connected_at ? chalk.green(' connected') : chalk.yellow(' not connected');

    console.log(`  ${highlight(service.service_id)}${verified}`);
    console.log(`    ${dim('Name:')}     ${service.name}`);
    console.log(`    ${dim('Status:')}   ${status}${connected}`);
    console.log(`    ${dim('Scopes:')}   ${service.scopes.join(', ')}`);
    console.log(`    ${dim('Budget:')}   ${service.budget.daily} ${service.budget.currency}/day`);
    if (service.budget.auto_approve_under > 0) {
      console.log(`    ${dim('Auto:')}     < ${service.budget.auto_approve_under} ${service.budget.currency}`);
    }
    console.log(`    ${dim('Trusted:')}  ${formatDate(service.trusted_at)}`);
    console.log();
  }

  console.log(dim('Commands:'));
  console.log(dim('  dcp trust <service>          # Add or update a service'));
  console.log(dim('  dcp trust <service> --revoke # Revoke trust'));
  console.log(dim('  dcp connect <service>        # Connect to service'));
  console.log();
}

// ============================================================================
// Add Trusted Service
// ============================================================================

async function addTrustedService(
  serviceId: string,
  options: {
    key?: string;
    scopes?: string;
    budget?: string;
    autoApproveUnder?: string;
    yes?: boolean;
  }
): Promise<void> {
  const storage = new VaultStorage();
  storage.initializeSchema();

  // Check if service already exists
  const existing = storage.getTrustedService(serviceId);
  if (existing) {
    info(`Service '${serviceId}' is already trusted`);
    console.log();

    // Offer to update
    const doUpdate = options.yes || await confirm('Update service configuration?', false);
    if (doUpdate) {
      await updateTrustedService(storage, serviceId, existing, options);
    }
    return;
  }

  // Check if this is a known service
  const known = getKnownService(serviceId);

  let publicKey: string;
  let name: string;
  let scopes: string[];
  let verified = false;

  if (known) {
    // Known service - use registry values
    publicKey = known.public_key;
    name = known.name;
    scopes = options.scopes ? parseScopes(options.scopes) : known.default_scopes;
    verified = true;

    console.log();
    console.log(chalk.bold(`Trust ${highlight(known.name)}?`));
    console.log(dim('─'.repeat(50)));
    console.log();
    if (known.description) {
      console.log(`  ${dim('Description:')} ${known.description}`);
    }
    console.log(`  ${dim('Service ID:')}  ${known.service_id}`);
    console.log(`  ${dim('Public Key:')}  ${formatKey(publicKey)}`);
    console.log(`  ${dim('Scopes:')}      ${scopes.join(', ')}`);
    console.log(`  ${dim('Verified:')}    ${chalk.green('Yes')}`);
    console.log();
  } else {
    // Custom service - require public key
    if (!options.key) {
      error('Public key is required for custom services');
      console.log();
      console.log(dim('Usage: dcp trust <service> --key=ed25519:... --scopes=...'));
      console.log();
      process.exit(1);
    }

    publicKey = options.key;

    // Validate public key format
    if (!isValidPublicKey(publicKey)) {
      error('Invalid public key format');
      console.log();
      console.log(dim('Expected format: ed25519:<base64-key> (32 bytes)'));
      console.log();
      process.exit(1);
    }

    // Get or prompt for scopes
    if (!options.scopes) {
      error('Scopes are required for custom services');
      console.log();
      console.log(dim('Usage: dcp trust <service> --key=ed25519:... --scopes=sign:solana'));
      console.log();
      process.exit(1);
    }

    scopes = parseScopes(options.scopes);
    name = serviceId;

    console.log();
    console.log(chalk.bold(`Trust custom service '${highlight(serviceId)}'?`));
    console.log(dim('─'.repeat(50)));
    console.log();
    console.log(`  ${dim('Public Key:')} ${formatKey(publicKey)}`);
    console.log(`  ${dim('Scopes:')}     ${scopes.join(', ')}`);
    console.log(`  ${dim('Verified:')}   ${chalk.yellow('No (custom service)')}`);
    console.log();
    warn('Custom services are not verified. Only trust services you know and trust.');
    console.log();
  }

  // Parse budget options
  const budget = parseBudget(options.budget || '10usdc/day');
  const autoApproveUnder = parseAmount(options.autoApproveUnder || '0');

  console.log(`  ${dim('Budget:')}     ${budget.daily} ${budget.currency}/day`);
  if (autoApproveUnder > 0) {
    console.log(`  ${dim('Auto:')}       Auto-approve under ${autoApproveUnder} ${budget.currency}`);
  }
  console.log();

  // Confirm
  if (!options.yes) {
    const doTrust = await confirm('Trust this service?', true);
    if (!doTrust) {
      info('Cancelled');
      return;
    }
  }

  // Unlock vault
  await unlockVault(storage, 'Unlock vault to add trusted service');

  // Ensure schema is initialized
  storage.initializeSchema();

  // Add the service
  const spin = spinner('Adding trusted service...');
  spin.start();

  try {
    storage.addTrustedService({
      service_id: serviceId,
      name,
      public_key: publicKey,
      scopes,
      budget: {
        daily: budget.daily,
        currency: budget.currency,
        auto_approve_under: autoApproveUnder,
      },
      verified,
    });

    spin.stop();
    console.log();
    success(`Trusted ${highlight(name)}`);
    console.log();
    console.log(dim('Next step: Connect to the service'));
    console.log(dim(`  dcp connect ${serviceId}`));
    console.log();
  } catch (err) {
    spin.stop();
    throw err;
  }
}

// ============================================================================
// Update Trusted Service
// ============================================================================

async function updateTrustedService(
  storage: VaultStorage,
  serviceId: string,
  existing: TrustedService,
  options: {
    key?: string;
    scopes?: string;
    budget?: string;
    autoApproveUnder?: string;
    yes?: boolean;
  }
): Promise<void> {
  storage.initializeSchema();
  const updates: Partial<Pick<TrustedService, 'public_key' | 'scopes' | 'budget' | 'verified'>> = {};

  if (options.key) {
    if (!isValidPublicKey(options.key)) {
      error('Invalid public key format');
      console.log();
      console.log(dim('Expected format: ed25519:<base64-key> (32 bytes)'));
      console.log();
      process.exit(1);
    }

    updates.public_key = options.key;
    const known = getKnownService(serviceId);
    if (known && known.public_key === options.key) {
      updates.verified = true;
    } else {
      updates.verified = false;
    }
  }

  if (options.scopes) {
    updates.scopes = parseScopes(options.scopes);
  }

  if (options.budget || options.autoApproveUnder) {
    const budget = options.budget ? parseBudget(options.budget) : {
      daily: existing.budget.daily,
      currency: existing.budget.currency,
    };
    const autoApproveUnder = options.autoApproveUnder
      ? parseAmount(options.autoApproveUnder)
      : existing.budget.auto_approve_under;

    updates.budget = {
      daily: budget.daily,
      currency: budget.currency,
      auto_approve_under: autoApproveUnder,
    };
  }

  if (Object.keys(updates).length === 0) {
    info('No updates specified');
    return;
  }

  console.log();
  console.log(chalk.bold('Update configuration:'));
  if (updates.public_key) {
    console.log(`  ${dim('Public Key:')} ${formatKey(updates.public_key)}`);
    if (updates.verified === false) {
      console.log(`  ${dim('Verified:')}   ${chalk.yellow('No (custom key)')}`);
    } else if (updates.verified === true) {
      console.log(`  ${dim('Verified:')}   ${chalk.green('Yes')}`);
    }
  }
  if (updates.scopes) {
    console.log(`  ${dim('Scopes:')} ${updates.scopes.join(', ')}`);
  }
  if (updates.budget) {
    console.log(`  ${dim('Budget:')} ${updates.budget.daily} ${updates.budget.currency}/day`);
    console.log(`  ${dim('Auto:')}   < ${updates.budget.auto_approve_under} ${updates.budget.currency}`);
  }
  console.log();

  if (!options.yes) {
    const doUpdate = await confirm('Apply updates?', true);
    if (!doUpdate) {
      info('Cancelled');
      return;
    }
  }

  await unlockVault(storage, 'Unlock vault to update service');

  storage.updateTrustedService(serviceId, updates);
  success(`Updated ${highlight(serviceId)}`);
}

// ============================================================================
// Revoke Service
// ============================================================================

async function revokeService(
  serviceId: string,
  options: { yes?: boolean }
): Promise<void> {
  const storage = new VaultStorage();
  storage.initializeSchema();

  const existing = storage.getTrustedService(serviceId);
  if (!existing) {
    error(`Service '${serviceId}' is not trusted`);
    return;
  }

  console.log();
  console.log(chalk.bold(`Revoke trust for ${highlight(existing.name)}?`));
  console.log(dim('─'.repeat(50)));
  console.log();
  console.log(`  ${dim('Service:')} ${existing.service_id}`);
  console.log(`  ${dim('Scopes:')}  ${existing.scopes.join(', ')}`);
  console.log(`  ${dim('Trusted:')} ${formatDate(existing.trusted_at)}`);
  console.log();
  warn('This will revoke all access for this service.');
  warn('Active sessions will be terminated.');
  console.log();

  if (!options.yes) {
    const doRevoke = await confirm('Revoke trust?', false);
    if (!doRevoke) {
      info('Cancelled');
      return;
    }
  }

  storage.revokeTrustedService(serviceId);
  success(`Revoked trust for ${highlight(existing.name)}`);
}

// ============================================================================
// Helper Functions
// ============================================================================

function parseScopes(scopesStr: string): string[] {
  return scopesStr
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseBudget(budgetStr: string): { daily: number; currency: string } {
  // Parse formats like "10usdc/day", "50usdc", "10 USDC/day"
  const match = budgetStr.match(/^([\d.]+)\s*(\w+)(?:\/day)?$/i);
  if (!match) {
    return { daily: 10, currency: 'USDC' }; // Default
  }

  return {
    daily: parseFloat(match[1]),
    currency: match[2].toUpperCase(),
  };
}

function parseAmount(amountStr: string): number {
  // Parse formats like "1usdc", "0.5", "1 USDC"
  const match = amountStr.match(/^([\d.]+)/);
  if (!match) return 0;
  return parseFloat(match[1]);
}

function formatKey(key: string): string {
  if (key.length <= 20) return key;
  return `${key.slice(0, 15)}...${key.slice(-5)}`;
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}
