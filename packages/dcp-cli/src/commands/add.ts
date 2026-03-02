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
  getPassphrase,
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
  ItemType,
} from '@dcprotocol/core';

// Scope metadata for interactive prompts (field names match PRD schema)
const SCOPE_CONFIG: Record<
  string,
  {
    sensitivity: SensitivityLevel;
    itemType: ItemType;
    fields: { name: string; label: string; masked?: boolean }[];
  }
> = {
  'identity.name': {
    sensitivity: 'sensitive',
    itemType: 'IDENTITY',
    fields: [
      { name: 'first', label: 'First name' },
      { name: 'last', label: 'Last name' },
      { name: 'middle', label: 'Middle name (optional)' },
    ],
  },
  'identity.email': {
    sensitivity: 'sensitive',
    itemType: 'IDENTITY',
    fields: [{ name: 'email', label: 'Email address' }],
  },
  'identity.phone': {
    sensitivity: 'sensitive',
    itemType: 'IDENTITY',
    fields: [
      { name: 'country_code', label: 'Country code (e.g., +1)' },
      { name: 'number', label: 'Phone number' },
    ],
  },
  'identity.passport': {
    sensitivity: 'critical',
    itemType: 'IDENTITY',
    fields: [
      { name: 'number', label: 'Passport number', masked: true },
      { name: 'country', label: 'Issuing country' },
      { name: 'expiry', label: 'Expiry date (YYYY-MM-DD)', masked: true },
    ],
  },
  'address.home': {
    sensitivity: 'sensitive',
    itemType: 'ADDRESS',
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
    itemType: 'ADDRESS',
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
    itemType: 'PREFERENCES',
    fields: [
      { name: 'shirt', label: 'Shirt size (XS, S, M, L, XL, XXL)' },
      { name: 'pants', label: 'Pants size' },
      { name: 'shoe', label: 'Shoe size' },
    ],
  },
  'preferences.brands': {
    sensitivity: 'standard',
    itemType: 'PREFERENCES',
    fields: [
      { name: 'preferred', label: 'Preferred brands (comma-separated)' },
      { name: 'avoided', label: 'Avoided brands (comma-separated, optional)' },
    ],
  },
  'preferences.diet': {
    sensitivity: 'standard',
    itemType: 'PREFERENCES',
    fields: [
      { name: 'restrictions', label: 'Dietary restrictions (comma-separated)' },
      { name: 'allergies', label: 'Allergies (comma-separated)' },
    ],
  },
};

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
  const sensitivity = (options.sensitivity as SensitivityLevel) ||
    config?.sensitivity ||
    detectSensitivity(scope);
  const itemType = config?.itemType || detectItemType(scope);

  info(`Adding ${formatScope(scope)} (${formatSensitivity(sensitivity)})`);
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
  fields: { name: string; label: string; masked?: boolean }[]
): Promise<Record<string, string>> {
  const data: Record<string, string> = {};

  for (const field of fields) {
    const isOptional = field.label.includes('optional');

    // Use masked input for sensitive fields (passport numbers, etc.)
    const value = field.masked
      ? await maskedInput(field.label)
      : await input(field.label);

    if (value || !isOptional) {
      data[field.name] = value;
    }
  }

  return data;
}

/**
 * Detect sensitivity from scope name
 */
function detectSensitivity(scope: string): SensitivityLevel {
  if (scope.startsWith('identity.passport') || scope.startsWith('crypto.')) {
    return 'critical';
  }
  if (scope.startsWith('identity.') || scope.startsWith('address.')) {
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
  return 'PREFERENCES';
}
