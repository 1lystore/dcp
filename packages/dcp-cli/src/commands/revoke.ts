/**
 * dcp revoke <agent|session_id>
 *
 * Revoke agent access immediately (PRD C7).
 *
 * Usage:
 *   dcp revoke "Claude"     # Revoke all sessions for agent "Claude"
 *   dcp revoke <session_id> # Revoke specific session
 *   dcp revoke --all        # Revoke all active sessions
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  error,
  success,
  info,
  handleError,
  dim,
} from '../utils.js';
import { VaultStorage } from '@dcprotocol/core';

export const revokeCommand = new Command('revoke')
  .description('Revoke agent access')
  .argument('[agent_or_session]', 'Agent name or session ID to revoke')
  .option('-a, --all', 'Revoke all active sessions')
  .option('-f, --force', 'Skip confirmation')
  .action(async (agentOrSession: string | undefined, options: { all?: boolean; force?: boolean }) => {
    try {
      await runRevoke(agentOrSession, options);
    } catch (err) {
      handleError(err);
    }
  });

async function runRevoke(
  agentOrSession: string | undefined,
  options: { all?: boolean; force?: boolean }
): Promise<void> {
  const storage = new VaultStorage();

  if (options.all) {
    // Revoke all sessions
    await revokeAll(storage, options.force);
    return;
  }

  if (!agentOrSession) {
    error('Please specify an agent name or session ID');
    console.log();
    info('Usage: dcp revoke <agent_name>');
    info('       dcp revoke <session_id>');
    info('       dcp revoke --all');
    console.log();
    return;
  }

  // Try to find by session ID first
  const session = storage.getSession(agentOrSession);

  if (session) {
    // Revoke specific session
    await revokeSession(storage, session.id, session.agent_name);
    return;
  }

  // Otherwise, revoke by agent name
  await revokeByAgentName(storage, agentOrSession);
}

/**
 * Revoke all active sessions
 */
async function revokeAll(storage: VaultStorage, force?: boolean): Promise<void> {
  const sessions = storage.listActiveSessions();

  if (sessions.length === 0) {
    info('No active sessions to revoke');
    return;
  }

  console.log();
  console.log(chalk.bold(`Revoking ${sessions.length} session(s):`));
  console.log();

  for (const session of sessions) {
    console.log(`  - ${session.agent_name} (${session.id.slice(0, 8)}...)`);
  }

  console.log();

  if (!force) {
    // In a real CLI we'd prompt for confirmation
    // For now, just proceed
    console.log(dim('Use --force to skip this message'));
  }

  // Revoke each session
  let revoked = 0;
  for (const session of sessions) {
    if (storage.revokeSession(session.id)) {
      storage.logAudit('REVOKE', 'success', {
        agentName: session.agent_name,
        operation: 'revoke_all',
        details: JSON.stringify({ session_id: session.id }),
      });
      revoked++;
    }
  }

  console.log();
  success(`Revoked ${revoked} session(s)`);
  console.log();
}

/**
 * Revoke a specific session by ID
 */
async function revokeSession(
  storage: VaultStorage,
  sessionId: string,
  agentName: string
): Promise<void> {
  console.log();

  if (storage.revokeSession(sessionId)) {
    storage.logAudit('REVOKE', 'success', {
      agentName,
      operation: 'revoke_session',
      details: JSON.stringify({ session_id: sessionId }),
    });

    success(`Revoked session for ${agentName}`);
    console.log(dim(`  Session ID: ${sessionId}`));
  } else {
    error(`Failed to revoke session: ${sessionId}`);
  }

  console.log();
}

/**
 * Revoke all sessions for an agent name
 */
async function revokeByAgentName(storage: VaultStorage, agentName: string): Promise<void> {
  const sessions = storage.listActiveSessions();
  const agentSessions = sessions.filter(
    (s) => s.agent_name.toLowerCase() === agentName.toLowerCase()
  );

  if (agentSessions.length === 0) {
    error(`No active sessions found for agent: ${agentName}`);
    console.log();

    // Show available agents
    const uniqueAgents = [...new Set(sessions.map((s) => s.agent_name))];
    if (uniqueAgents.length > 0) {
      info('Active agents:');
      for (const agent of uniqueAgents) {
        console.log(`  - ${agent}`);
      }
    }

    console.log();
    return;
  }

  console.log();

  const count = storage.revokeAgentSessions(agentName);

  if (count > 0) {
    storage.logAudit('REVOKE', 'success', {
      agentName,
      operation: 'revoke_agent',
      details: JSON.stringify({ sessions_revoked: count }),
    });

    success(`Revoked ${count} session(s) for ${agentName}`);
  } else {
    error(`Failed to revoke sessions for: ${agentName}`);
  }

  console.log();
}
