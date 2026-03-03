#!/usr/bin/env node
/**
 * DCP Vault CLI
 *
 * Human interface for managing the vault:
 * - Initialize vault
 * - Create/import wallets
 * - Add/list personal data
 * - Manage agents and sessions
 * - View activity and audit logs
 */

import { Command } from 'commander';
import { initCommand } from './commands/init.js';
import { createWalletCommand } from './commands/create-wallet.js';
import { addCommand } from './commands/add.js';
import { listCommand } from './commands/list.js';
import { readCommand } from './commands/read.js';
import { statusCommand } from './commands/status.js';
import { approveCommand } from './commands/approve.js';
import { agentsCommand } from './commands/agents.js';
import { revokeCommand } from './commands/revoke.js';
import { configCommand } from './commands/config.js';
import { activityCommand } from './commands/activity.js';
import { recoveryCommand } from './commands/recovery.js';
import { updateCommand } from './commands/update.js';
import { removeCommand } from './commands/remove.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const program = new Command();
const CLI_VERSION = getPackageVersion();

function getPackageVersion(): string {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const raw = fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8');
    const json = JSON.parse(raw) as { version?: string };
    return json.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

program
  .name('dcp')
  .description('Your AI agents sign transactions without touching your private key')
  .version(CLI_VERSION);

// Setup commands
program.addCommand(initCommand);
program.addCommand(createWalletCommand);
program.addCommand(addCommand);
program.addCommand(listCommand);
program.addCommand(readCommand);
program.addCommand(statusCommand);
program.addCommand(approveCommand);
program.addCommand(agentsCommand);
program.addCommand(revokeCommand);
program.addCommand(configCommand);
program.addCommand(activityCommand);
program.addCommand(recoveryCommand);
program.addCommand(updateCommand);
program.addCommand(removeCommand);

// Parse arguments
program.parse();
