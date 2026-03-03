/**
 * dcp approve <consent_id>
 *
 * Approve or deny a pending consent request from an MCP agent.
 * This enables the non-TTY consent flow (PRD CN3, CN10).
 *
 * Usage:
 *   dcp approve <consent_id>         # Approve once
 *   dcp approve <consent_id> -s      # Approve for session (30 min)
 *   dcp approve <consent_id> --deny  # Deny the request
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  error,
  success,
  info,
  handleError,
  dim,
  bold,
  highlight,
} from '../utils.js';
import { VaultStorage } from '@dcprotocol/core';

export const approveCommand = new Command('approve')
  .description('Approve or deny a pending consent request')
  .argument('[consent_id]', 'The consent request ID to approve')
  .option('-s, --session', 'Grant session consent (30 min idle, 4 hr max)')
  .option('-d, --deny', 'Deny the consent request')
  .option('-l, --list', 'List all pending consent requests')
  .action(async (consentId: string | undefined, options: { session?: boolean; deny?: boolean; list?: boolean }) => {
    try {
      if (options.list) {
        await listPendingConsents();
      } else if (!consentId) {
        // No consent ID provided, show list
        await listPendingConsents();
      } else {
        await runApprove(consentId, options);
      }
    } catch (err) {
      handleError(err);
    }
  });

/**
 * List all pending consent requests
 */
async function listPendingConsents(): Promise<void> {
  const storage = new VaultStorage();

  console.log();
  console.log(chalk.bold('Pending Consent Requests'));
  console.log(dim('─'.repeat(60)));
  console.log();

  const pending = storage.getPendingConsents();

  if (pending.length === 0) {
    console.log(dim('  No pending consent requests'));
    console.log();
    return;
  }

  for (const consent of pending) {
    const expiresIn = formatExpiresIn(consent.expires_at);
    let details: Record<string, unknown> = {};

    try {
      if (consent.details) {
        details = JSON.parse(consent.details);
      }
    } catch {
      // Ignore parse errors
    }

    console.log(`  ${highlight(consent.id)}`);
    console.log(`    ${dim('Agent:')}   ${consent.agent_name}`);
    console.log(`    ${dim('Action:')}  ${consent.action}`);
    console.log(`    ${dim('Scope:')}   ${consent.scope}`);

    if (details.description) {
      console.log(`    ${dim('Desc:')}    ${details.description}`);
    }
    if (details.amount !== undefined && details.currency) {
      console.log(`    ${dim('Amount:')}  ${details.amount} ${details.currency}`);
    }

    console.log(`    ${dim('Expires:')} ${expiresIn}`);
    console.log();
  }

  console.log(dim('To approve: dcp approve <consent_id>'));
  console.log(dim('To deny:    dcp approve <consent_id> --deny'));
  console.log();
}

/**
 * Approve or deny a specific consent request
 */
async function runApprove(
  consentId: string,
  options: { session?: boolean; deny?: boolean }
): Promise<void> {
  const storage = new VaultStorage();

  // Get the consent request
  const consent = storage.getPendingConsent(consentId);

  if (!consent) {
    error(`Consent request not found: ${consentId}`);
    console.log();
    info('Run: dcp approve --list');
    return;
  }

  // Check if expired
  if (new Date(consent.expires_at) < new Date()) {
    error('Consent request has expired');
    storage.resolveConsent(consentId, 'expired');
    return;
  }

  // Check if already resolved
  if (consent.status !== 'pending') {
    error(`Consent request already ${consent.status}`);
    return;
  }

  // Display consent details
  console.log();
  console.log(chalk.bold('Consent Request'));
  console.log(dim('─'.repeat(50)));
  console.log();
  console.log(`  ${dim('ID:')}      ${highlight(consent.id)}`);
  console.log(`  ${dim('Agent:')}   ${consent.agent_name}`);
  console.log(`  ${dim('Action:')}  ${consent.action}`);
  console.log(`  ${dim('Scope:')}   ${consent.scope}`);

  let details: Record<string, unknown> = {};
  try {
    if (consent.details) {
      details = JSON.parse(consent.details);
    }
  } catch {
    // Ignore parse errors
  }

  if (details.description) {
    console.log(`  ${dim('Desc:')}    ${details.description}`);
  }
  if (details.amount !== undefined && details.currency) {
    console.log(`  ${dim('Amount:')}  ${chalk.yellow(`${details.amount} ${details.currency}`)}`);
  }
  if (details.chain) {
    console.log(`  ${dim('Chain:')}   ${details.chain}`);
  }

  console.log();

  if (options.deny) {
    // Deny the request
    storage.resolveConsent(consentId, 'denied');

    // Log to audit
    storage.logAudit('DENY', 'denied', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: consent.action,
      details: 'Denied via CLI',
    });

    console.log(chalk.red('Denied'));
    console.log();
    return;
  }

  // Create a session if --session flag is set
  let sessionId: string | undefined;
  if (options.session) {
    const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000); // 4 hours max duration
    const session = storage.createSession(
      consent.agent_name,
      [consent.scope],
      'session',
      expiresAt
    );
    sessionId = session.id;

    // Log to audit
    storage.logAudit('GRANT', 'success', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: 'session_grant',
      details: JSON.stringify({ session_id: session.id, expires_at: expiresAt.toISOString() }),
    });
  } else {
    // Log to audit
    storage.logAudit('GRANT', 'success', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: 'once_grant',
    });
  }

  // Approve the request (with session_id if created)
  storage.resolveConsent(consentId, 'approved', sessionId);

  if (options.session && sessionId) {
    const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
    success(`Approved (session for 4 hours)`);
    console.log(dim(`  Session ID: ${sessionId}`));
  } else {
    success('Approved (once)');
  }

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

  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s`;

  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m`;

  return chalk.yellow(`${Math.floor(diffMins / 60)}h ${diffMins % 60}m`);
}
