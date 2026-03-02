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

  const response = await prompts({
    type: 'password',
    name: 'passphrase',
    message,
  });

  if (!response.passphrase) {
    throw new Error('Passphrase is required');
  }

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

  const response = await prompts({
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

  const response = await prompts({
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

  const response = await prompts({
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

  const response = await prompts({
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
    error(err.message);
  } else {
    error(String(err));
  }
  process.exit(1);
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
