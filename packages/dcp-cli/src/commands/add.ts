/**
 * dcp add <scope>
 *
 * Add personal data to the vault:
 * - Interactive prompts for common data types
 * - --data flag for JSON input
 * - Automatic sensitivity detection
 * - Encrypted with per-record DEK
 */

import { Command } from 'commander';
import {
  success,
  error,
  info,
  warn,
  spinner,
  unlockVault,
  input,
  maskedInput,
  confirm,
  handleError,
  highlight,
  formatScope,
  formatSensitivity,
} from '../utils.js';
import {
  VaultStorage,
  SensitivityLevel,
} from '@dcprotocol/core';
import { SCOPE_CONFIG } from '../scope-config.js';

export const addCommand = new Command('add')
  .description('Add personal data to the vault')
  .argument('<scope>', 'Data scope (e.g., address.home, identity.name, preferences.sizes)')
  .option('-d, --data <json>', 'JSON data (skip interactive prompts)')
  .option('-s, --sensitivity <level>', 'Override sensitivity level (standard, sensitive, critical)')
  .action(async (scope, options) => {
    try {
      await runAdd(scope, options);
    } catch (err) {
      handleError(err);
    }
  });

async function runAdd(
  scope: string,
  options: { data?: string; sensitivity?: string }
): Promise<void> {
  const storage = new VaultStorage();

  // Check vault is initialized
  if (!storage.isInitialized()) {
    error('Vault not initialized. Run: dcp init');
    process.exit(1);
  }

  // Check if scope already exists
  const existing = storage.getRecord(scope);
  if (existing) {
    warn(`Scope ${formatScope(scope)} already exists.`);
    const overwrite = await confirm('Overwrite existing data?', false);
    if (!overwrite) {
      info('Cancelled.');
      process.exit(0);
    }
  }

  // Get scope config or use defaults
  const config = SCOPE_CONFIG[scope];
  let sensitivityOverride: SensitivityLevel | undefined;
  if (options.sensitivity) {
    const value = options.sensitivity.toLowerCase();
    if (!['standard', 'sensitive', 'critical'].includes(value)) {
      error(`Invalid sensitivity: ${options.sensitivity}`);
      info('Valid values: standard, sensitive, critical');
      process.exit(1);
    }
    sensitivityOverride = value as SensitivityLevel;
  }
  const sensitivity =
    sensitivityOverride || config?.sensitivity || detectSensitivity(scope);
  const itemType = config?.itemType || detectItemType(scope);

  info(`Adding ${formatScope(scope)} (${formatSensitivity(sensitivity)})`);
  info('Press Esc or Ctrl+C to cancel.');
  console.log();

  // Get data
  let data: Record<string, unknown>;

  if (options.data) {
    // Parse JSON data from --data flag
    try {
      data = JSON.parse(options.data);
    } catch {
      error('Invalid JSON data');
      process.exit(1);
    }
  } else if (config?.fields) {
    // Interactive prompts for known scopes
    data = await promptForFields(config.fields);
    if (config.transform) {
      data = config.transform(data, scope);
    }
  } else {
    // Generic JSON input for unknown scopes
    info('Enter data as JSON (e.g., {"key": "value"}):');
    const jsonStr = await input('Data');
    try {
      data = JSON.parse(jsonStr);
    } catch {
      error('Invalid JSON data');
      process.exit(1);
    }
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

  // Ensure schema_version exists
  if (!('schema_version' in data)) {
    data.schema_version = '1.0';
  }

  // Store data
  const saveSpin = spinner('Encrypting and storing...');
  saveSpin.start();

  try {
    const masterKey = storage.getMasterKey();

    if (existing) {
      // Update existing record
      storage.updateRecord(existing.id, data, masterKey);
    } else {
      // Create new record
      storage.createRecord({
        scope,
        item_type: itemType,
        sensitivity,
        data,
      });
    }

    saveSpin.succeed('Data stored');

    console.log();
    success(`${formatScope(scope)} added to vault`);

    if (sensitivity === 'critical') {
      warn('CRITICAL data: Agents will only see a reference, never the actual values.');
    } else if (sensitivity === 'sensitive') {
      info('SENSITIVE data: Agents need consent + purpose check to read.');
    } else {
      info('STANDARD data: Agents need consent to read.');
    }
  } catch (err) {
    saveSpin.fail('Failed to store data');
    throw err;
  } finally {
    storage.lock();
  }
}

/**
 * Interactive prompts for fields
 */
async function promptForFields(
  fields: {
    name: string;
    label: string;
    masked?: boolean;
    optional?: boolean;
    array?: boolean;
    boolean?: boolean;
    json?: boolean;
  }[]
): Promise<Record<string, unknown>> {
  const data: Record<string, unknown> = {};

  for (const field of fields) {
    if (field.boolean) {
      const confirmed = await confirm(field.label, false);
      if (confirmed || !field.optional) {
        data[field.name] = confirmed;
      }
      continue;
    }

    if (field.json) {
      const value = await input(field.label);
      if (!value) {
        if (!field.optional) {
          data[field.name] = {};
        }
        continue;
      }
      try {
        data[field.name] = JSON.parse(value);
      } catch {
        error('Invalid JSON. Please try again.');
        return promptForFields(fields);
      }
      continue;
    }

    const value = field.masked
      ? await maskedInput(field.label)
      : await input(field.label);

    if (!value) {
      if (!field.optional) {
        data[field.name] = value;
      }
      continue;
    }

    if (field.array) {
      if (value.trim().startsWith('[')) {
        try {
          const arr = JSON.parse(value);
          if (Array.isArray(arr)) {
            data[field.name] = arr;
          }
        } catch {
          data[field.name] = value.split(',').map((v) => v.trim()).filter(Boolean);
        }
      } else {
        data[field.name] = value.split(',').map((v) => v.trim()).filter(Boolean);
      }
    } else {
      data[field.name] = value;
    }
  }

  return data;
}

/**
 * Detect sensitivity from scope name
 */
function detectSensitivity(scope: string): SensitivityLevel {
  if (
    scope.startsWith('identity.passport') ||
    scope.startsWith('identity.drivers_license') ||
    scope.startsWith('crypto.') ||
    scope.startsWith('credentials.')
  ) {
    return 'critical';
  }
  if (scope.startsWith('identity.') || scope.startsWith('address.') || scope.startsWith('health.')) {
    return 'sensitive';
  }
  return 'standard';
}

/**
 * Detect item type from scope name
 */
function detectItemType(scope: string): ItemType {
  if (scope.startsWith('identity.')) return 'IDENTITY';
  if (scope.startsWith('address.')) return 'ADDRESS';
  if (scope.startsWith('preferences.')) return 'PREFERENCES';
  if (scope.startsWith('crypto.')) return 'WALLET_KEY';
  if (scope.startsWith('credentials.')) return 'CREDENTIALS';
  if (scope.startsWith('health.')) return 'HEALTH';
  if (scope.startsWith('budget.')) return 'BUDGET';
  return 'PREFERENCES';
}
