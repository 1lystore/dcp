/**
 * dcp agents
 *
 * List active agent sessions (PRD C6).
 *
 * Usage:
 *   dcp agents           # List all active sessions
 *   dcp agents --all     # Include expired/revoked sessions
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  dim,
  highlight,
  handleError,
} from '../utils.js';
import { VaultStorage } from '@dcprotocol/core';

export const agentsCommand = new Command('agents')
  .description('List active agent sessions')
  .option('-a, --all', 'Include expired and revoked sessions')
  .action(async (options: { all?: boolean }) => {
    try {
      await runAgents(options);
    } catch (err) {
      handleError(err);
    }
  });

async function runAgents(options: { all?: boolean }): Promise<void> {
  const storage = new VaultStorage();

  console.log();
  console.log(chalk.bold(options.all ? 'All Agent Sessions' : 'Active Agent Sessions'));
  console.log(dim('─'.repeat(70)));
  console.log();

  const sessions = options.all ? storage.listAllSessions() : storage.listActiveSessions();

  if (sessions.length === 0) {
    console.log(dim(options.all ? '  No sessions found' : '  No active sessions'));
    console.log();
    console.log(dim('Sessions are created when agents request access and you approve.'));
    console.log();
    return;
  }

  // Table header
  if (options.all) {
    console.log(
      `  ${dim('Agent'.padEnd(20))} ${dim('Scopes'.padEnd(8))} ${dim('Status'.padEnd(10))} ${dim('Expires'.padEnd(12))} ${dim('Last Used')}`
    );
  } else {
    console.log(
      `  ${dim('Agent'.padEnd(20))} ${dim('Scopes'.padEnd(8))} ${dim('Mode'.padEnd(10))} ${dim('Expires'.padEnd(12))} ${dim('Last Used')}`
    );
  }
  console.log(dim('  ' + '─'.repeat(66)));

  for (const session of sessions) {
    const scopes = session.granted_scopes.length;
    const expiresIn = formatExpiresIn(session.expires_at);
    const lastUsed = session.last_used_at ? formatLastUsed(session.last_used_at) : dim('never');

    const agentName = session.agent_name.length > 18
      ? session.agent_name.slice(0, 15) + '...'
      : session.agent_name.padEnd(18);

    // Determine status for --all view
    let statusCol: string;
    if (options.all) {
      if (session.revoked_at) {
        statusCol = chalk.red('revoked');
      } else if (new Date(session.expires_at) < new Date()) {
        statusCol = chalk.red('expired');
      } else {
        statusCol = chalk.green('active');
      }
      statusCol = statusCol.padEnd(10);
    } else {
      statusCol = session.consent_mode.padEnd(10);
    }

    console.log(
      `  ${highlight(agentName)}  ${String(scopes).padEnd(8)} ${statusCol} ${expiresIn.padEnd(12)} ${lastUsed}`
    );

    // Show granted scopes on next line if verbose
    if (scopes <= 3) {
      const scopeList = session.granted_scopes.join(', ');
      console.log(`    ${dim('Scopes:')} ${scopeList}`);
    }
  }

  console.log();
  console.log(dim('─'.repeat(70)));
  console.log();
  console.log(dim('To revoke: dcp revoke <agent_name>'));
  console.log();
}

/**
 * Format expires_at as relative time
 */
function formatExpiresIn(expiresAt: string): string {
  const expires = new Date(expiresAt);
  const now = new Date();
  const diffMs = expires.getTime() - now.getTime();

  if (diffMs < 0) return chalk.red('expired');

  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return chalk.yellow(`${diffMins}m`);

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return chalk.green(`${diffHours}h ${diffMins % 60}m`);

  const diffDays = Math.floor(diffHours / 24);
  return chalk.green(`${diffDays}d`);
}

/**
 * Format last_used_at as relative time
 */
function formatLastUsed(lastUsedAt: string): string {
  const lastUsed = new Date(lastUsedAt);
  const now = new Date();
  const diffMs = now.getTime() - lastUsed.getTime();

  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;

  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}
