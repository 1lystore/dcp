/**
 * dcp activity
 *
 * View audit log of vault activity (PRD C8).
 *
 * Usage:
 *   dcp activity                     # Show last 50 events
 *   dcp activity --last 24h          # Events from last 24 hours
 *   dcp activity --agent "Claude"    # Filter by agent
 *   dcp activity --type deny         # Filter by event type
 *   dcp activity -n 100              # Show 100 events
 */

import { Command } from 'commander';
import chalk from 'chalk';
import {
  dim,
  highlight,
  handleError,
} from '../utils.js';
import { VaultStorage, AuditEventType } from '@dcprotocol/core';

export const activityCommand = new Command('activity')
  .description('View vault activity log')
  .option('-n, --limit <count>', 'Number of events to show', '50')
  .option('-a, --agent <name>', 'Filter by agent name')
  .option('-t, --type <type>', 'Filter by event type (GRANT, DENY, EXECUTE, READ, REVOKE, CONFIG, EXPIRE)')
  .option('-l, --last <duration>', 'Show events from last duration (e.g., 1h, 24h, 7d)')
  .action(async (options: { limit: string; agent?: string; type?: string; last?: string }) => {
    try {
      await runActivity(options);
    } catch (err) {
      handleError(err);
    }
  });

async function runActivity(options: {
  limit: string;
  agent?: string;
  type?: string;
  last?: string;
}): Promise<void> {
  const storage = new VaultStorage();

  console.log();
  console.log(chalk.bold('Vault Activity'));
  console.log(dim('─'.repeat(80)));
  console.log();

  // Parse options
  const limit = parseInt(options.limit, 10) || 50;
  const since = options.last ? parseDuration(options.last) : undefined;
  const eventType = options.type?.toUpperCase() as AuditEventType | undefined;

  // Validate event type if provided
  if (eventType && !['GRANT', 'DENY', 'EXECUTE', 'READ', 'REVOKE', 'CONFIG', 'EXPIRE'].includes(eventType)) {
    console.log(chalk.red(`Invalid event type: ${options.type}`));
    console.log(dim('Valid types: GRANT, DENY, EXECUTE, READ, REVOKE, CONFIG, EXPIRE'));
    console.log();
    return;
  }

  // Get events
  const events = storage.getAuditEvents(limit, {
    eventType,
    agentName: options.agent,
    since,
  });

  if (events.length === 0) {
    console.log(dim('  No events found'));
    console.log();

    if (options.agent || options.type || options.last) {
      console.log(dim('Try removing filters to see more events.'));
    } else {
      console.log(dim('Events are logged when agents interact with the vault.'));
    }
    console.log();
    return;
  }

  // Show filter info
  const filterParts: string[] = [];
  if (options.agent) filterParts.push(`agent="${options.agent}"`);
  if (options.type) filterParts.push(`type=${options.type.toUpperCase()}`);
  if (options.last) filterParts.push(`since=${options.last}`);

  if (filterParts.length > 0) {
    console.log(dim(`  Filters: ${filterParts.join(', ')}`));
    console.log();
  }

  // Table header
  console.log(
    `  ${dim('Time'.padEnd(20))} ${dim('Type'.padEnd(10))} ${dim('Agent'.padEnd(18))} ${dim('Scope'.padEnd(20))} ${dim('Status')}`
  );
  console.log(dim('  ' + '─'.repeat(76)));

  for (const event of events) {
    const time = formatTime(event.created_at);
    const type = formatEventType(event.event_type);
    const agent = event.agent_name
      ? (event.agent_name.length > 16 ? event.agent_name.slice(0, 13) + '...' : event.agent_name.padEnd(16))
      : dim('user'.padEnd(16));
    const scope = event.scope
      ? (event.scope.length > 18 ? event.scope.slice(0, 15) + '...' : event.scope.padEnd(18))
      : dim('-'.padEnd(18));
    const outcome = formatOutcome(event.outcome);

    console.log(
      `  ${time.padEnd(20)} ${type.padEnd(10)} ${agent}  ${scope}  ${outcome}`
    );

    // Show operation details on next line if present
    if (event.operation || event.details) {
      const details: string[] = [];
      if (event.operation) details.push(event.operation);
      if (event.details) {
        try {
          const parsed = JSON.parse(event.details);
          if (typeof parsed === 'object') {
            const summary = Object.entries(parsed)
              .slice(0, 3)
              .map(([k, v]) => `${k}=${v}`)
              .join(', ');
            details.push(summary);
          } else {
            details.push(String(parsed));
          }
        } catch {
          if (event.details.length < 50) {
            details.push(event.details);
          }
        }
      }

      if (details.length > 0) {
        const detailText = details.join(' | ');
        const lines = wrapLine(detailText, 72);
        for (const line of lines) {
          console.log(`    ${dim(line)}`);
        }
      }
    }
  }

  console.log();
  console.log(dim('─'.repeat(80)));
  console.log();
  console.log(dim(`Showing ${events.length} event(s)`));
  console.log();
}

/**
 * Parse duration string (e.g., "24h", "7d", "1h") to Date
 */
function parseDuration(duration: string): Date | undefined {
  const match = duration.match(/^(\d+)([hdm])$/i);
  if (!match) {
    console.log(chalk.yellow(`Warning: Invalid duration "${duration}". Using default.`));
    return undefined;
  }

  const amount = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  const now = new Date();
  switch (unit) {
    case 'h':
      return new Date(now.getTime() - amount * 60 * 60 * 1000);
    case 'd':
      return new Date(now.getTime() - amount * 24 * 60 * 60 * 1000);
    case 'm':
      return new Date(now.getTime() - amount * 60 * 1000);
    default:
      return undefined;
  }
}

/**
 * Format timestamp as relative or absolute time
 */
function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();

  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;

  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ${diffMins % 60}m ago`;

  // For older events, show date
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Format event type with color
 */
function formatEventType(type: string): string {
  switch (type) {
    case 'GRANT':
      return chalk.green(type);
    case 'DENY':
      return chalk.red(type);
    case 'EXECUTE':
      return chalk.cyan(type);
    case 'READ':
      return chalk.blue(type);
    case 'REVOKE':
      return chalk.yellow(type);
    case 'CONFIG':
      return chalk.magenta(type);
    case 'EXPIRE':
      return chalk.gray(type);
    default:
      return type;
  }
}

function wrapLine(text: string, width: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current.length === 0) {
      current = word;
      continue;
    }
    if (current.length + word.length + 1 <= width) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }

  if (current.length > 0) {
    lines.push(current);
  }

  return lines.length > 0 ? lines : [''];
}

/**
 * Format outcome with color
 */
function formatOutcome(outcome: string): string {
  switch (outcome) {
    case 'success':
      return chalk.green('success');
    case 'denied':
      return chalk.red('denied');
    case 'error':
      return chalk.red('error');
    default:
      return outcome;
  }
}
