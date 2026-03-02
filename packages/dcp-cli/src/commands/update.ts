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
  getPassphrase,
  input,
  maskedInput,
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

// Scope metadata for interactive prompts (same as add.ts)
const SCOPE_CONFIG: Record<
  string,
  {
    sensitivity: SensitivityLevel;
    fields: { name: string; label: string; masked?: boolean }[];
  }
> = {
  'identity.name': {
    sensitivity: 'sensitive',
    fields: [
      { name: 'first', label: 'First name' },
      { name: 'last', label: 'Last name' },
      { name: 'middle', label: 'Middle name (optional)' },
    ],
  },
  'identity.email': {
    sensitivity: 'sensitive',
    fields: [{ name: 'email', label: 'Email address' }],
  },
  'identity.phone': {
    sensitivity: 'sensitive',
    fields: [
      { name: 'country_code', label: 'Country code (e.g., +1)' },
      { name: 'number', label: 'Phone number' },
    ],
  },
  'identity.passport': {
    sensitivity: 'critical',
    fields: [
      { name: 'number', label: 'Passport number', masked: true },
      { name: 'country', label: 'Issuing country' },
      { name: 'expiry', label: 'Expiry date (YYYY-MM-DD)', masked: true },
    ],
  },
  'address.home': {
    sensitivity: 'sensitive',
    fields: [
      { name: 'street', label: 'Street address' },
      { name: 'city', label: 'City' },
      { name: 'state', label: 'State/Province' },
      { name: 'zip', label: 'ZIP/Postal code' },
      { name: 'country', label: 'Country' },
    ],
  },
  'address.work': {
    sensitivity: 'sensitive',
    fields: [
      { name: 'street', label: 'Street address' },
      { name: 'city', label: 'City' },
      { name: 'state', label: 'State/Province' },
      { name: 'zip', label: 'ZIP/Postal code' },
      { name: 'country', label: 'Country' },
    ],
  },
  'preferences.sizes': {
    sensitivity: 'standard',
    fields: [
      { name: 'shirt', label: 'Shirt size (XS, S, M, L, XL, XXL)' },
      { name: 'pants', label: 'Pants size' },
      { name: 'shoe', label: 'Shoe size' },
    ],
  },
  'preferences.brands': {
    sensitivity: 'standard',
    fields: [
      { name: 'preferred', label: 'Preferred brands (comma-separated)' },
      { name: 'avoided', label: 'Avoided brands (comma-separated, optional)' },
    ],
  },
  'preferences.diet': {
    sensitivity: 'standard',
    fields: [
      { name: 'restrictions', label: 'Dietary restrictions (comma-separated)' },
      { name: 'allergies', label: 'Allergies (comma-separated)' },
    ],
  },
};

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
  const passphrase = await getPassphrase('Enter vault passphrase');

  const spin = spinner('Unlocking vault...');
  spin.start();

  try {
    await storage.unlock(passphrase);
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
      console.log(`  ${dim(key + ':')} ${highlight(String(value))}`);
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
    storage.updateRecord(existing.id, newData, masterKey);
    saveSpin.succeed('Data updated');

    console.log();
    success(`${formatScope(scope)} updated`);

    // Log to audit
    storage.logAudit('CONFIG', 'success', {
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
  fields: { name: string; label: string; masked?: boolean }[],
  currentData: Record<string, unknown>
): Promise<Record<string, string>> {
  const data: Record<string, string> = {};

  for (const field of fields) {
    const currentValue = String(currentData[field.name] || '');
    const isOptional = field.label.includes('optional');

    // Show current value (masked for sensitive fields)
    const displayCurrent = field.masked && currentValue
      ? '****' + currentValue.slice(-4)
      : currentValue || '(empty)';

    const prompt = `${field.label} [${dim(displayCurrent)}]`;

    // Get new value
    const value = field.masked
      ? await maskedInput(prompt)
      : await input(prompt);

    // Use new value if provided, otherwise keep current
    if (value) {
      data[field.name] = value;
    } else if (currentValue) {
      data[field.name] = currentValue;
    } else if (!isOptional) {
      data[field.name] = '';
    }
  }

  return data;
}
