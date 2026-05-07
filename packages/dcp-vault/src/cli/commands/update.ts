/**
 * dcp update <scope>
 *
 * Update existing data in the vault:
 * - Interactive prompts for common data types
 * - --data flag for JSON input
 * - Shows current values for reference
 */

import { Command } from 'commander';
import {
  success,
  error,
  info,
  spinner,
  unlockVault,
  input,
  maskedInput,
  confirm,
  handleError,
  highlight,
  formatScope,
  formatSensitivity,
  dim,
} from '../utils.js';
import {
  VaultStorage,
  SensitivityLevel,
  envelopeDecrypt,
  zeroize,
} from '@dcprotocol/core';
import chalk from 'chalk';
import { SCOPE_CONFIG } from '../scope-config.js';

export const updateCommand = new Command('update')
  .description('Update existing data in the vault')
  .argument('<scope>', 'Data scope to update (e.g., address.home)')
  .option('-d, --data <json>', 'JSON data (skip interactive prompts)')
  .action(async (scope, options) => {
    try {
      await runUpdate(scope, options);
    } catch (err) {
      handleError(err);
    }
  });

async function runUpdate(scope: string, options: { data?: string }): Promise<void> {
  const storage = new VaultStorage();

  // Check vault is initialized
  if (!storage.isInitialized()) {
    error('Vault not initialized. Run: dcp init');
    process.exit(1);
  }

  // Check if scope exists
  const existing = storage.getRecord(scope);
  if (!existing) {
    error(`Scope ${formatScope(scope)} does not exist.`);
    info('Use: dcp add ' + scope);
    process.exit(1);
  }

  // Check if it's a wallet (can't update wallets)
  if (existing.item_type === 'WALLET_KEY') {
    error('Cannot update wallet keys. Create a new wallet instead.');
    process.exit(1);
  }

  console.log();
  console.log(chalk.bold('Update ' + formatScope(scope)));
  console.log(dim('─'.repeat(50)));
  console.log();

  // Unlock vault first to show current values
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

  // Get and display current data
  const masterKey = storage.getMasterKey();
  const payload = storage.getEncryptedPayload(scope);

  let currentData: Record<string, unknown> = {};
  if (payload) {
    const decrypted = envelopeDecrypt(payload, masterKey);
    try {
      currentData = JSON.parse(decrypted.toString('utf8'));
    } catch {
      // Non-JSON data
    } finally {
      // CRITICAL: Zeroize decrypted data from memory
      zeroize(decrypted);
    }
  }

  console.log();
  info('Current values:');
  for (const [key, value] of Object.entries(currentData)) {
    if (existing.sensitivity === 'critical') {
      console.log(`  ${dim(key + ':')} ${dim('[hidden]')}`);
    } else {
      let display = '';
      if (Array.isArray(value)) {
        display = value.join(', ');
      } else if (value && typeof value === 'object') {
        display = JSON.stringify(value);
      } else {
        display = String(value);
      }
      console.log(`  ${dim(key + ':')} ${highlight(display)}`);
    }
  }
  console.log();

  // Get new data
  let newData: Record<string, unknown>;
  const config = SCOPE_CONFIG[scope];

  if (options.data) {
    // Parse JSON data from --data flag
    try {
      newData = JSON.parse(options.data);
    } catch {
      error('Invalid JSON data');
      storage.lock();
      process.exit(1);
    }
  } else if (config?.fields) {
    // Interactive prompts for known scopes
    info('Enter new values (leave blank to keep current):');
    console.log();
    newData = await promptForFieldsWithDefaults(config.fields, currentData);
    if (config.transform) {
      newData = config.transform(newData, scope);
    }
  } else {
    // Generic JSON input for unknown scopes
    info('Enter new data as JSON (e.g., {"key": "value"}):');
    const jsonStr = await input('Data');
    try {
      newData = JSON.parse(jsonStr);
    } catch {
      error('Invalid JSON data');
      storage.lock();
      process.exit(1);
    }
  }

  // Update record
  const saveSpin = spinner('Encrypting and storing...');
  saveSpin.start();

  try {
    if (!('schema_version' in newData)) {
      const currentVersion = (currentData as Record<string, unknown>).schema_version;
      newData.schema_version = typeof currentVersion === 'string' ? currentVersion : '1.0';
    }
    storage.updateRecord(existing.id, newData, masterKey);
    saveSpin.succeed('Data updated');

    console.log();
    success(`${formatScope(scope)} updated`);

    // Log to audit
    storage.logAudit('EXECUTE', 'success', {
      operation: 'update_record',
      scope,
      details: JSON.stringify({ updated_fields: Object.keys(newData) }),
    });
  } catch (err) {
    saveSpin.fail('Failed to update data');
    throw err;
  } finally {
    storage.lock();
  }
}

/**
 * Interactive prompts for fields with current values as defaults
 */
async function promptForFieldsWithDefaults(
  fields: {
    name: string;
    label: string;
    masked?: boolean;
    optional?: boolean;
    array?: boolean;
    boolean?: boolean;
    json?: boolean;
  }[],
  currentData: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const data: Record<string, unknown> = {};

  for (const field of fields) {
    const currentValue = String(currentData[field.name] || '');
    const isOptional = field.optional === true;

    // Show current value (masked for sensitive fields)
    const displayCurrent = field.masked && currentValue
      ? '****' + currentValue.slice(-4)
      : currentValue || '(empty)';

    const prompt = `${field.label} [${dim(displayCurrent)}]`;

    // Get new value
    if (field.boolean) {
      const currentBool = Boolean(currentData[field.name]);
      const confirmed = await confirm(prompt, currentBool);
      data[field.name] = confirmed;
      continue;
    }

    if (field.json) {
      const value = await input(prompt);
      if (!value) {
        if (currentData[field.name] !== undefined) {
          data[field.name] = currentData[field.name];
        } else if (!isOptional) {
          data[field.name] = {};
        }
        continue;
      }
      try {
        data[field.name] = JSON.parse(value);
      } catch {
        error('Invalid JSON. Please try again.');
        return promptForFieldsWithDefaults(fields, currentData);
      }
      continue;
    }

    const value = field.masked ? await maskedInput(prompt) : await input(prompt);

    // Use new value if provided, otherwise keep current
    if (value) {
      if (field.array) {
        if (value.trim().startsWith('[')) {
          try {
            const arr = JSON.parse(value);
            if (Array.isArray(arr)) {
              data[field.name] = arr;
              continue;
            }
          } catch {
            // fall back to comma split
          }
        }
        data[field.name] = value.split(',').map((v) => v.trim()).filter(Boolean);
      } else {
        data[field.name] = value;
      }
    } else if (currentValue) {
      const existing = currentData[field.name];
      data[field.name] = existing;
    } else if (!isOptional) {
      data[field.name] = '';
    }
  }

  return data;
}
