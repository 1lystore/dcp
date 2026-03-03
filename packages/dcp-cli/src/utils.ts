/**
 * CLI Utilities
 *
 * Common functions for:
 * - Colored output
 * - Spinners
 * - Error handling
 * - TTY detection
 */

import chalk from 'chalk';
import ora, { Ora } from 'ora';
import prompts from 'prompts';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import keytar from 'keytar';
import { createHash, randomBytes } from 'crypto';
import { encrypt, decrypt, VaultStorage } from '@dcprotocol/core';

function prompt<T extends prompts.PromptObject | prompts.PromptObject[]>(
  options: T
): Promise<prompts.Answers<string>> {
  return prompts(options, {
    onCancel: () => {
      throw new Error('Cancelled');
    },
  });
}

// ============================================================================
// Output Helpers
// ============================================================================

export function success(message: string): void {
  console.log(chalk.green('✓'), message);
}

export function error(message: string): void {
  console.error(chalk.red('✗'), message);
}

export function warn(message: string): void {
  console.log(chalk.yellow('!'), message);
}

export function info(message: string): void {
  console.log(chalk.blue('i'), message);
}

export function dim(message: string): string {
  return chalk.dim(message);
}

export function bold(message: string): string {
  return chalk.bold(message);
}

export function highlight(message: string): string {
  return chalk.cyan(message);
}

// ============================================================================
// Spinners
// ============================================================================

export function spinner(text: string): Ora {
  return ora({ text, color: 'cyan' });
}

// ============================================================================
// TTY Detection
// ============================================================================

export function isTTY(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

export function requireTTY(): void {
  if (!isTTY()) {
    error('This command requires an interactive terminal (TTY).');
    error('Run this command directly in your terminal, not from a script or subprocess.');
    process.exit(1);
  }
}

// ============================================================================
// Prompts
// ============================================================================

/**
 * Get passphrase from user (masked input)
 */
export async function getPassphrase(message: string = 'Enter passphrase'): Promise<string> {
  requireTTY();

  const response = await prompt({
    type: 'password',
    name: 'passphrase',
    message,
    validate: (value: string) => {
      if (!value || value.length === 0) {
        return 'Passphrase is required';
      }
      return true;
    },
  });

  return response.passphrase;
}

/**
 * Confirm passphrase (enter twice)
 */
export async function confirmPassphrase(): Promise<string> {
  requireTTY();

  const pass1 = await getPassphrase('Enter passphrase');
  const pass2 = await getPassphrase('Confirm passphrase');

  if (pass1 !== pass2) {
    throw new Error('Passphrases do not match');
  }

  return pass1;
}

/**
 * Yes/No confirmation prompt
 */
export async function confirm(message: string, defaultValue: boolean = false): Promise<boolean> {
  requireTTY();

  const response = await prompt({
    type: 'confirm',
    name: 'value',
    message,
    initial: defaultValue,
  });

  return response.value === true;
}

/**
 * Select from options
 */
export async function select<T extends string>(
  message: string,
  choices: { title: string; value: T }[]
): Promise<T> {
  requireTTY();

  const response = await prompt({
    type: 'select',
    name: 'value',
    message,
    choices,
  });

  return response.value;
}

/**
 * Text input
 */
export async function input(message: string, initial?: string): Promise<string> {
  requireTTY();

  const response = await prompt({
    type: 'text',
    name: 'value',
    message,
    initial,
  });

  return response.value || '';
}

/**
 * Masked text input (for sensitive data like passport numbers)
 */
export async function maskedInput(message: string): Promise<string> {
  requireTTY();

  const response = await prompt({
    type: 'password',
    name: 'value',
    message,
  });

  return response.value || '';
}

// ============================================================================
// Error Handling
// ============================================================================

export function handleError(err: unknown): never {
  if (err instanceof Error) {
    if (err.message === 'Cancelled') {
      info('Cancelled');
      process.exit(0);
    }
    error(err.message);
  } else {
    error(String(err));
  }
  process.exit(1);
}

// ============================================================================
// Session Unlock Cache (CLI)
// ============================================================================

const CLI_SESSION_MINUTES = Number(process.env.DCP_CLI_SESSION_MINUTES || '30');
const CLI_SESSION_SERVICE = 'dcp-cli';
const CLI_INSECURE_SESSION = process.env.DCP_CLI_INSECURE_SESSION === '1';
let keychainUnavailable = false;

function getSessionPaths(storage: VaultStorage): { sessionPath: string; account: string; keyPath: string } {
  const vaultDir = storage.getVaultDir?.() || path.join(os.homedir(), '.dcp');
  const hash = createHash('sha256').update(vaultDir).digest('hex').slice(0, 12);
  return {
    sessionPath: path.join(vaultDir, 'cli.session'),
    account: `session-key:${hash}`,
    keyPath: path.join(vaultDir, 'cli.session.key'),
  };
}

async function loadSessionKey(account: string, keyPath: string): Promise<Buffer | null> {
  try {
    const stored = await withTimeout(
      keytar.getPassword(CLI_SESSION_SERVICE, account),
      1500
    );
    if (!stored) return null;
    return Buffer.from(stored, 'base64');
  } catch {
    keychainUnavailable = true;
    if (!CLI_INSECURE_SESSION) return null;
    try {
      if (!fs.existsSync(keyPath)) return null;
      return Buffer.from(fs.readFileSync(keyPath, 'utf8'), 'base64');
    } catch {
      return null;
    }
  }
}

async function storeSessionKey(account: string, keyPath: string, key: Buffer): Promise<void> {
  try {
    await withTimeout(
      keytar.setPassword(CLI_SESSION_SERVICE, account, key.toString('base64')),
      1500
    );
  } catch {
    keychainUnavailable = true;
    if (!CLI_INSECURE_SESSION) return;
    try {
      fs.writeFileSync(keyPath, key.toString('base64'), { mode: 0o600 });
    } catch {
      // ignore
    }
  }
}

async function deleteSessionKey(account: string, keyPath: string): Promise<void> {
  try {
    await keytar.deletePassword(CLI_SESSION_SERVICE, account);
  } catch {
    // ignore
  }
  if (CLI_INSECURE_SESSION) {
    try {
      if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
    } catch {
      // ignore
    }
  }
}

async function tryUnlockFromSession(storage: VaultStorage): Promise<boolean> {
  if (!CLI_SESSION_MINUTES || CLI_SESSION_MINUTES <= 0) return false;

  const { sessionPath, account, keyPath } = getSessionPaths(storage);
  if (!fs.existsSync(sessionPath)) return false;

  let session: { encrypted_key: string; nonce: string; expires_at: string } | null = null;
  try {
    session = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
  } catch {
    session = null;
  }

  if (!session?.encrypted_key || !session?.nonce || !session?.expires_at) {
    fs.unlinkSync(sessionPath);
    await deleteSessionKey(account);
    return false;
  }

  const expiresAt = Date.parse(session.expires_at);
  if (!expiresAt || Date.now() > expiresAt) {
    fs.unlinkSync(sessionPath);
    await deleteSessionKey(account, keyPath);
    return false;
  }

  const sessionKey = await loadSessionKey(account, keyPath);
  if (!sessionKey) return false;

  try {
    const masterKey = decrypt(
      Buffer.from(session.encrypted_key, 'base64'),
      Buffer.from(session.nonce, 'base64'),
      sessionKey
    );
    storage.setMasterKey(masterKey);
    return true;
  } catch {
    fs.unlinkSync(sessionPath);
    await deleteSessionKey(account, keyPath);
    return false;
  }
}

async function writeSessionCache(storage: VaultStorage): Promise<void> {
  if (!CLI_SESSION_MINUTES || CLI_SESSION_MINUTES <= 0) return;

  const { sessionPath, account, keyPath } = getSessionPaths(storage);
  const sessionKey = randomBytes(32);
  const masterKey = storage.getMasterKey();

  const { ciphertext, nonce } = encrypt(masterKey, sessionKey);
  const expiresAt = new Date(Date.now() + CLI_SESSION_MINUTES * 60 * 1000).toISOString();

  fs.writeFileSync(
    sessionPath,
    JSON.stringify(
      {
        encrypted_key: ciphertext.toString('base64'),
        nonce: nonce.toString('base64'),
        expires_at: expiresAt,
        version: '1.0',
      },
      null,
      2
    ),
    { mode: 0o600 }
  );

  await storeSessionKey(account, keyPath, sessionKey);
}

export async function unlockVault(
  storage: VaultStorage,
  message: string = 'Enter vault passphrase',
  onPrompt?: () => void
): Promise<void> {
  keychainUnavailable = false;
  const unlocked = await tryUnlockFromSession(storage);
  if (unlocked) return;

  if (keychainUnavailable) {
    if (CLI_INSECURE_SESSION) {
      info('Keychain unavailable. Using insecure session cache (file-based).');
    } else {
      info('Keychain unavailable, falling back to passphrase.');
      info('Tip: set DCP_CLI_INSECURE_SESSION=1 to avoid repeated prompts (less secure).');
    }
  }

  if (onPrompt) onPrompt();
  const passphrase = await getPassphrase(message);
  await storage.unlock(passphrase);
  await writeSessionCache(storage);
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | null = null;
  const timeout = new Promise<T>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ============================================================================
// Formatting
// ============================================================================

/**
 * Format a scope name for display
 */
export function formatScope(scope: string): string {
  return chalk.cyan(scope);
}

/**
 * Format a chain name
 */
export function formatChain(chain: string): string {
  const colors: Record<string, typeof chalk.green> = {
    solana: chalk.magenta,
    base: chalk.blue,
    ethereum: chalk.blue,
  };
  return (colors[chain] || chalk.white)(chain);
}

/**
 * Format a date for display
 */
export function formatDate(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
}

/**
 * Format sensitivity level
 */
export function formatSensitivity(level: string): string {
  const colors: Record<string, typeof chalk.green> = {
    standard: chalk.green,
    sensitive: chalk.yellow,
    critical: chalk.red,
  };
  return (colors[level] || chalk.white)(level.toUpperCase());
}

/**
 * Box output for important messages
 */
export function box(lines: string[], title?: string): void {
  const maxLen = Math.max(...lines.map((l) => l.length), title?.length || 0);
  const border = '─'.repeat(maxLen + 2);

  console.log();
  if (title) {
    console.log(chalk.cyan(`┌─ ${title} ${'─'.repeat(Math.max(0, maxLen - title.length - 1))}┐`));
  } else {
    console.log(chalk.cyan(`┌${border}┐`));
  }
  for (const line of lines) {
    console.log(chalk.cyan('│'), line.padEnd(maxLen), chalk.cyan('│'));
  }
  console.log(chalk.cyan(`└${border}┘`));
  console.log();
}
