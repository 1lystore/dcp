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
import { statusCommand } from './commands/status.js';
import { approveCommand } from './commands/approve.js';
import { agentsCommand } from './commands/agents.js';
import { revokeCommand } from './commands/revoke.js';
import { configCommand } from './commands/config.js';
import { activityCommand } from './commands/activity.js';
import { recoveryCommand } from './commands/recovery.js';
import { updateCommand } from './commands/update.js';
import { removeCommand } from './commands/remove.js';

const program = new Command();

program
  .name('dcp')
  .description('Your AI agents sign transactions without touching your private key')
  .version('0.1.0');

// Setup commands
program.addCommand(initCommand);
program.addCommand(createWalletCommand);
program.addCommand(addCommand);
program.addCommand(listCommand);
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
