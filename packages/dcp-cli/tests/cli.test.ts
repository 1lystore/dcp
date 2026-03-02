/**
 * CLI Integration Tests
 *
 * Tests the CLI commands using child_process.
 * Note: These are integration tests that actually run commands.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// Use a temp directory for testing
const TEST_VAULT_DIR = path.join(os.tmpdir(), '.dcp-cli-test');

// Helper to run CLI commands
function runCli(args: string, options?: { stdin?: string }): string {
  const cliPath = path.join(__dirname, '..', 'dist', 'cli.js');
  const env = { ...process.env, HOME: os.tmpdir() };

  try {
    return execSync(`node ${cliPath} ${args}`, {
      encoding: 'utf8',
      env,
      timeout: 30000,
    }).trim();
  } catch (error: unknown) {
    const execError = error as { stdout?: Buffer; stderr?: Buffer };
    if (execError.stdout) {
      return execError.stdout.toString();
    }
    throw error;
  }
}

describe('CLI', () => {
  beforeEach(() => {
    // Clean up test vault directory before each test
    if (fs.existsSync(TEST_VAULT_DIR)) {
      fs.rmSync(TEST_VAULT_DIR, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    // Clean up after tests
    if (fs.existsSync(TEST_VAULT_DIR)) {
      fs.rmSync(TEST_VAULT_DIR, { recursive: true, force: true });
    }
  });

  describe('--help', () => {
    it('should display help text', () => {
      const output = runCli('--help');
      expect(output).toContain('Your AI agents sign transactions');
      expect(output).toContain('init');
      expect(output).toContain('create-wallet');
      expect(output).toContain('add');
      expect(output).toContain('list');
    });
  });

  describe('--version', () => {
    it('should display version', () => {
      const output = runCli('--version');
      expect(output).toMatch(/\d+\.\d+\.\d+/);
    });
  });

  describe('init --help', () => {
    it('should display init command help', () => {
      const output = runCli('init --help');
      expect(output).toContain('Initialize a new vault');
      expect(output).toContain('--force');
    });
  });

  describe('create-wallet --help', () => {
    it('should display create-wallet command help', () => {
      const output = runCli('create-wallet --help');
      expect(output).toContain('Generate a new wallet');
      expect(output).toContain('--chain');
    });
  });

  describe('add --help', () => {
    it('should display add command help', () => {
      const output = runCli('add --help');
      expect(output).toContain('Add personal data');
      expect(output).toContain('--data');
    });
  });

  describe('list --help', () => {
    it('should display list command help', () => {
      const output = runCli('list --help');
      expect(output).toContain('List all stored scopes');
      expect(output).toContain('--type');
      expect(output).toContain('--chain');
    });
  });

  describe('status --help', () => {
    it('should display status command help', () => {
      const output = runCli('status --help');
      expect(output).toContain('Show vault status');
    });
  });
});
