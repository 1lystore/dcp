#!/usr/bin/env node

/**
 * DCP Agent CLI
 *
 * Lightweight binary for connecting AI agents to vaults via pairing grants.
 *
 * Usage:
 *   dcp-agent pair <grant>      - Pair with a vault using a pairing grant
 *   dcp-agent run [--mode]      - Run agent in specified mode:
 *                                   - proxy: HTTP REST proxy (default)
 *                                   - mcp: stdio MCP (Claude Desktop, Cursor, VS Code)
 *                                   - http-mcp: Streamable HTTP MCP (VPS, OpenClaw, Hermes)
 *   dcp-agent status            - Show agent status
 *   dcp-agent list              - List configured agents
 *   dcp-agent remove <agent_id> - Remove agent configuration
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora, { type Ora } from 'ora';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import qrcode from 'qrcode-terminal';
import {
  parseAndVerifyGrant,
  createConfigFromGrant,
  exchangePairingGrant,
  saveConfig,
  saveMobilePendingConfig,
  loadConfig,
  listConfigs,
  deleteConfig,
  getDefaultAgent,
  findAgent,
} from './config.js';
import { AgentProxy } from './proxy.js';
import { runMcpServer } from './mcp.js';
import { runHttpMcpServer } from './http-mcp.js';
import { AgentError } from './types.js';
import { processSecretsRequest, fetchSecret, fetchSecrets } from './secrets.js';
import { createMobilePairingInvite } from './mobile-pairing.js';
import {
  configureOpenClawCommand,
  installServiceCommand,
  uninstallServiceCommand,
} from './commands/install-service.js';
import type {
  MobileAgentClient,
  MobileAgentEnvironment,
  MobileDcpScope,
  PairOptions,
  RunOptions,
  StatusOptions,
} from './types.js';

// ============================================================================
// Helpers
// ============================================================================

function success(message: string): void {
  console.log(chalk.green('✓'), message);
}

function error(message: string): void {
  console.error(chalk.red('✗'), message);
}

/**
 * Redact sensitive fields from agent config for safe JSON output.
 * NEVER output private keys, session tokens, or pairing secrets.
 */
function redactConfigForOutput(config: Record<string, unknown>): Record<string, unknown> {
  const REDACTED = '[REDACTED]';
  const redacted = { ...config };

  // Redact service_keypair.private
  if (redacted.service_keypair && typeof redacted.service_keypair === 'object') {
    redacted.service_keypair = {
      ...(redacted.service_keypair as Record<string, unknown>),
      private: REDACTED,
    };
  }

  // Redact session token
  if ('session_token' in redacted && redacted.session_token) {
    redacted.session_token = REDACTED;
  }

  // Redact any field containing 'private', 'secret', or 'token' (case insensitive)
  for (const key of Object.keys(redacted)) {
    const lowerKey = key.toLowerCase();
    if (
      (lowerKey.includes('private') || lowerKey.includes('secret') || lowerKey.includes('token')) &&
      typeof redacted[key] === 'string' &&
      redacted[key] !== REDACTED
    ) {
      redacted[key] = REDACTED;
    }
  }

  return redacted;
}

function dim(message: string): string {
  return chalk.dim(message);
}

function spinner(text: string): Ora {
  return ora({ text, color: 'cyan' });
}

function box(lines: string[], title?: string): void {
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

function getPackageVersion(): string {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const raw = fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8');
    const json = JSON.parse(raw) as { version?: string };
    return json.version || '0.2.0';
  } catch {
    return '0.2.0';
  }
}

// ============================================================================
// Commands
// ============================================================================

async function pairCommand(grantToken: string, options: PairOptions): Promise<void> {
  const spin = spinner('Verifying pairing grant...');
  spin.start();

  try {
    // Parse and verify the grant
    const grant = parseAndVerifyGrant(grantToken);
    spin.text = 'Creating agent configuration...';

    // Create config from grant (generates keypair per protocol spec section 7.3)
    let config = createConfigFromGrant(grant);

    // Override name if provided
    if (options.name) {
      config.agent_name = options.name;
    }

    // Exchange grant with vault to register public key and get session token
    spin.text = 'Exchanging pairing grant with vault...';
    config = await exchangePairingGrant(grantToken, config);

    // Save config
    saveConfig(config);

    spin.stop();
    success('Agent paired successfully');

    console.log();
    console.log(`  ${dim('Agent ID:')}    ${config.agent_id}`);
    console.log(`  ${dim('Agent Name:')}  ${config.agent_name}`);
    console.log(`  ${dim('Vault ID:')}    ${config.vault_id}`);
    console.log(`  ${dim('Mode:')}        ${config.mode}`);
    console.log(`  ${dim('Relay:')}       ${config.relay_url}`);
    // Note: Permissions are now stored in vault policy DB only
    // tier and scopes may not be present in new grants
    if (config.tier) {
      console.log(`  ${dim('Tier:')}        ${config.tier}`);
    }
    if (config.permission_scopes?.length) {
      console.log(`  ${dim('Scopes:')}      ${config.permission_scopes.join(', ')}`);
    }
    console.log();

    box([
      'Agent is now configured!',
      '',
      'To start the agent:',
      `  dcp-agent run`,
      '',
      'To run in proxy mode:',
      `  dcp-agent run --mode proxy`,
    ], 'Next Steps');
  } catch (err) {
    spin.stop();
    if (err instanceof AgentError) {
      error(err.message);
      if (err.details) {
        console.log(dim(JSON.stringify(err.details, null, 2)));
      }
    } else {
      error(err instanceof Error ? err.message : 'Unknown error');
    }
    process.exit(1);
  }
}

interface MobilePairOptions {
  client?: MobileAgentClient;
  environment?: MobileAgentEnvironment;
  name?: string;
  relayUrl?: string;
  scope?: string[];
  dailyBudget?: string;
  currency?: 'SOL' | 'USDC';
  approvalThreshold?: string;
  ttlSeconds?: string;
  json?: boolean;
  noQr?: boolean;
}

function parseNumberOption(value: string | undefined, fallback: number, label: string): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative number`);
  }
  return parsed;
}

function defaultAgentName(client: MobileAgentClient): string {
  const names: Record<MobileAgentClient, string> = {
    'claude-desktop': 'Claude Desktop',
    cursor: 'Cursor',
    vscode: 'VS Code',
    hermes: 'Hermes',
    openclaw: 'OpenClaw',
    mcp: 'MCP Agent',
    custom: 'Custom Agent',
    hosted: 'Hosted Agent',
  };
  return names[client] || 'DCP Agent';
}

async function mobilePairCommand(options: MobilePairOptions): Promise<void> {
  try {
    const client = options.client || 'custom';
    const environment = options.environment || (client === 'hermes' || client === 'openclaw' ? 'vps' : 'local');
    const scopes = (options.scope?.length ? options.scope : ['read:wallet.address', 'sign:solana']) as MobileDcpScope[];
    const daily = parseNumberOption(options.dailyBudget, 0, '--daily-budget');
    const approvalThreshold = parseNumberOption(options.approvalThreshold, 0, '--approval-threshold');
    const ttlSeconds = parseNumberOption(options.ttlSeconds, 10 * 60, '--ttl-seconds');

    const created = createMobilePairingInvite({
      client,
      environment,
      agentName: options.name || defaultAgentName(client),
      relayUrl: options.relayUrl,
      requestedScopes: scopes,
      requestedBudget: {
        daily,
        currency: options.currency || 'USDC',
        approval_threshold: approvalThreshold,
      },
      ttlSeconds,
    });

    saveMobilePendingConfig(created.pendingConfig);

    if (options.json) {
      console.log(JSON.stringify({
        invite: created.invite,
        invite_url: created.inviteUrl,
      }, null, 2));
      return;
    }

    console.log();
    console.log(chalk.bold('DCP Mobile Pairing'));
    console.log(dim('Scan this QR with DCP Mobile, or paste the pairing URL into the app.'));
    console.log();

    if (!options.noQr) {
      qrcode.generate(created.inviteUrl, { small: true });
      console.log();
    }

    console.log(`  ${dim('Agent:')}      ${created.invite.agent_name}`);
    console.log(`  ${dim('Client:')}     ${created.invite.agent_client}`);
    console.log(`  ${dim('Environment:')} ${created.invite.environment}`);
    console.log(`  ${dim('Invite ID:')}   ${created.invite.invite_id}`);
    console.log(`  ${dim('Expires:')}     ${created.invite.expires_at}`);
    console.log();
    console.log(chalk.bold('Pairing URL:'));
    console.log(created.inviteUrl);
    console.log();
    console.log(dim('Pending agent key material was saved locally with 0600 permissions.'));
    console.log(dim('The mobile vault must approve the invite before this agent can request DCP actions.'));
  } catch (err) {
    error(err instanceof Error ? err.message : 'Failed to create mobile pairing invite');
    process.exit(1);
  }
}

function getAgentDataDir(): string {
  const homeDir = process.env.HOME || process.env.USERPROFILE || '.';
  return path.join(homeDir, '.dcp', 'agents');
}

async function runCommand(options: RunOptions): Promise<void> {
  // Get agent config
  let config;
  try {
    if (options.agent) {
      // Find specific agent by ID or name
      config = findAgent(options.agent);
      if (!config) {
        error(`Agent not found: ${options.agent}`);
        console.log(dim('Available agents:'));
        listConfigs().forEach((c) => console.log(dim(`  - ${c.agent_name} (${c.agent_id})`)));
        process.exit(1);
      }
    } else {
      config = getDefaultAgent();
      if (!config) {
        error('No agent configured. Run "dcp-agent pair <grant>" first.');
        process.exit(1);
      }
    }
  } catch (err) {
    error('Failed to load agent configuration');
    process.exit(1);
  }

  const mode = options.mode || config.mode || 'proxy';
  const port = parseInt(options.port || '8420', 10);

  // Handle daemon mode
  if (options.daemon) {
    const dataDir = getAgentDataDir();
    const pidFile = path.join(dataDir, `${config.agent_id}.pid`);
    const logFile = path.join(dataDir, `${config.agent_id}.log`);

    // Check if already running
    if (fs.existsSync(pidFile)) {
      const existingPid = fs.readFileSync(pidFile, 'utf8').trim();
      try {
        process.kill(parseInt(existingPid, 10), 0);
        error(`Agent already running (PID: ${existingPid})`);
        console.log(dim(`Stop it first: kill ${existingPid}`));
        process.exit(1);
      } catch {
        // Process not running, clean up stale PID file
        fs.unlinkSync(pidFile);
      }
    }

    // Build args for child process (same args minus --daemon)
    const args: string[] = ['run', '--mode', mode, '--port', String(port)];
    if (options.host) {
      args.push('--host', options.host);
    }
    if (options.debug) {
      args.push('--debug');
    }
    if (options.forceRelay) {
      args.push('--force-relay');
    }

    // Get the path to this script
    const __filename = fileURLToPath(import.meta.url);
    const scriptPath = path.resolve(__filename, '..');
    const binPath = path.join(scriptPath, '..', 'dist', 'index.js');

    // Open log file for writing with restricted permissions (0600)
    // SECURITY: Log files may contain sensitive request data - restrict to owner only
    const logFd = fs.openSync(logFile, 'a', 0o600);

    // Spawn detached child process
    const child = spawn(process.execPath, [binPath, ...args], {
      detached: true,
      stdio: ['ignore', logFd, logFd],
      env: process.env,
    });

    // Write PID file with restricted permissions (0600)
    fs.writeFileSync(pidFile, String(child.pid), { mode: 0o600 });

    // Detach from parent
    child.unref();
    fs.closeSync(logFd);

    success(`Agent started in background (PID: ${child.pid})`);
    console.log();
    console.log(`  ${dim('PID file:')}  ${pidFile}`);
    console.log(`  ${dim('Log file:')}  ${logFile}`);
    console.log(`  ${dim('Endpoint:')}  http://${options.host || '127.0.0.1'}:${port}`);
    console.log();
    console.log(dim(`To stop: kill ${child.pid}`));
    console.log(dim(`To view logs: tail -f ${logFile}`));
    console.log();
    process.exit(0);
  }

  // stdio MCP mode requires clean stdout - skip all console output and run immediately
  if (mode === 'mcp') {
    try {
      await runMcpServer(config, { forceRelay: options.forceRelay });
    } catch (err) {
      if (err instanceof AgentError) {
        process.stderr.write(`Error: ${err.message}\n`);
      } else {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : 'Failed to start MCP server'}\n`);
      }
      process.exit(1);
    }
    return;
  }

  // HTTP MCP mode (Streamable HTTP) for VPS/OpenClaw agents
  if (mode === 'http-mcp') {
    try {
      console.log();
      console.log(chalk.bold('DCP Agent - HTTP MCP Server'));
      console.log(dim('─'.repeat(50)));
      console.log();
      await runHttpMcpServer(config, {
        host: options.host || '127.0.0.1',
        port,
        forceRelay: options.forceRelay,
      });
      // Keep process alive
      await new Promise(() => {});
    } catch (err) {
      if (err instanceof AgentError) {
        error(err.message);
      } else {
        error(err instanceof Error ? err.message : 'Failed to start HTTP MCP server');
      }
      process.exit(1);
    }
    return;
  }

  // For non-MCP modes, show the banner
  console.log();
  console.log(chalk.bold('DCP Agent'));
  console.log(dim('─'.repeat(50)));
  console.log();
  console.log(`  ${dim('Agent:')}     ${config.agent_name} (${config.agent_id})`);
  console.log(`  ${dim('Vault:')}     ${config.vault_id}`);
  console.log(`  ${dim('Mode:')}      ${mode}`);
  console.log(`  ${dim('Tier:')}      ${config.tier}`);
  console.log(`  ${dim('Relay:')}     ${config.relay_url}`);
  if (options.forceRelay) {
    console.log(`  ${dim('Transport:')} ${chalk.yellow('RELAY (forced)')}`);
  }
  console.log();

  if (mode === 'proxy') {
    const spin = spinner('Starting proxy server...');
    spin.start();

    try {
      const proxy = new AgentProxy(config, port, { forceRelay: options.forceRelay });
      await proxy.start();

      spin.stop();
      success('Proxy started');

      box([
        'DCP Agent is running in proxy mode',
        '',
        `Local endpoint: http://127.0.0.1:${port}`,
        '',
        'Agent configuration:',
        `  DCP_URL=http://127.0.0.1:${port}`,
        '  DCP_MODE=local',
        '',
        'Press Ctrl+C to stop',
      ], 'Running');

      // Keep running
      process.on('SIGINT', async () => {
        console.log('\nShutting down...');
        await proxy.stop();
        process.exit(0);
      });

      process.on('SIGTERM', async () => {
        await proxy.stop();
        process.exit(0);
      });

      // Keep process alive
      await new Promise(() => {});
    } catch (err) {
      spin.stop();
      if (err instanceof AgentError) {
        error(err.message);
      } else {
        error(err instanceof Error ? err.message : 'Failed to start proxy');
      }
      process.exit(1);
    }
  } else if (mode === 'sdk') {
    error('SDK mode not yet implemented. Use proxy mode for now.');
    console.log(dim('Run: dcp-agent run --mode proxy'));
    process.exit(1);
  } else {
    error(`Unknown mode: ${mode}`);
    process.exit(1);
  }
}

function statusCommand(options: StatusOptions): void {
  const config = getDefaultAgent();

  if (!config) {
    if (options.json) {
      console.log(JSON.stringify({ configured: false }));
    } else {
      console.log();
      console.log(dim('No agent configured.'));
      console.log(dim('Run "dcp-agent pair <grant>" to configure an agent.'));
      console.log();
    }
    return;
  }

  if (options.json) {
    // SECURITY: Redact private keys and tokens before outputting
    const safeConfig = redactConfigForOutput({
      configured: true,
      ...config,
    });
    console.log(JSON.stringify(safeConfig, null, 2));
    return;
  }

  console.log();
  console.log(chalk.bold('DCP Agent Status'));
  console.log(dim('─'.repeat(50)));
  console.log();
  console.log(`  ${dim('Agent ID:')}    ${config.agent_id}`);
  console.log(`  ${dim('Agent Name:')}  ${config.agent_name}`);
  console.log(`  ${dim('Vault ID:')}    ${config.vault_id}`);
  console.log(`  ${dim('Mode:')}        ${config.mode}`);
  console.log(`  ${dim('Relay:')}       ${config.relay_url}`);
  console.log(`  ${dim('Paired:')}      ${config.paired_at}`);
  // Note: Permissions are now stored in vault policy DB only
  if (config.tier) {
    console.log(`  ${dim('Tier:')}        ${config.tier}`);
  }
  if (config.permission_scopes?.length) {
    console.log(`  ${dim('Scopes:')}      ${config.permission_scopes.join(', ')}`);
  }
  console.log();
}

function listCommand(options: StatusOptions): void {
  const configs = listConfigs();

  if (configs.length === 0) {
    if (options.json) {
      console.log(JSON.stringify([]));
    } else {
      console.log();
      console.log(dim('No agents configured.'));
      console.log(dim('Run "dcp-agent pair <grant>" to configure an agent.'));
      console.log();
    }
    return;
  }

  if (options.json) {
    // SECURITY: Redact private keys and tokens before outputting
    const safeConfigs = configs.map((c) => redactConfigForOutput(c as unknown as Record<string, unknown>));
    console.log(JSON.stringify(safeConfigs, null, 2));
    return;
  }

  console.log();
  console.log(chalk.bold('Configured Agents'));
  console.log(dim('─'.repeat(60)));
  console.log();

  for (const config of configs) {
    console.log(`  ${chalk.cyan(config.agent_name)}`);
    console.log(`    ${dim('ID:')}    ${config.agent_id}`);
    console.log(`    ${dim('Vault:')} ${config.vault_id}`);
    console.log(`    ${dim('Mode:')}  ${config.mode}${config.tier ? ` (${config.tier})` : ''}`);
    console.log();
  }
}

function removeCommand(agentId: string): void {
  const deleted = deleteConfig(agentId);

  if (deleted) {
    success(`Removed agent: ${agentId}`);
  } else {
    error(`Agent not found: ${agentId}`);
    process.exit(1);
  }
}

function stopCommand(): void {
  const config = getDefaultAgent();

  if (!config) {
    error('No agent configured.');
    process.exit(1);
  }

  const dataDir = getAgentDataDir();
  const pidFile = path.join(dataDir, `${config.agent_id}.pid`);

  if (!fs.existsSync(pidFile)) {
    console.log(dim('No daemon running (no PID file found).'));
    return;
  }

  const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);

  try {
    process.kill(pid, 'SIGTERM');
    fs.unlinkSync(pidFile);
    success(`Stopped agent daemon (PID: ${pid})`);
  } catch (err) {
    // Process might already be dead
    fs.unlinkSync(pidFile);
    console.log(dim(`Process ${pid} not running (cleaned up PID file).`));
  }
}

// ============================================================================
// CLI Setup
// ============================================================================

const program = new Command();

program
  .name('dcp-agent')
  .description('DCP Agent - Connect AI agents to vaults via pairing grants')
  .version(getPackageVersion());

program
  .command('pair <grant>')
  .description('Pair with a vault using a pairing grant token')
  .option('-n, --name <name>', 'Override agent name')
  .action(pairCommand);

const mobileCommand = program
  .command('mobile')
  .description('DCP Mobile pairing commands');

mobileCommand
  .command('pair')
  .description('Create a DCP Mobile pairing invite')
  .option('--client <client>', 'Agent client: claude-desktop, cursor, vscode, hermes, openclaw, mcp, custom, hosted', 'custom')
  .option('--environment <environment>', 'Environment: local, vps, hosted, dev')
  .option('-n, --name <name>', 'Agent display name')
  .option('--relay-url <url>', 'Mobile relay API/base URL')
  .option('--scope <scope>', 'Requested scope. Repeat for multiple scopes.', (value, previous: string[] = []) => [...previous, value])
  .option('--daily-budget <amount>', 'Requested daily budget', '0')
  .option('--currency <currency>', 'Budget currency: USDC or SOL', 'USDC')
  .option('--approval-threshold <amount>', 'Auto-approval threshold', '0')
  .option('--ttl-seconds <seconds>', 'Invite lifetime in seconds', '600')
  .option('--json', 'Print machine-readable JSON')
  .option('--no-qr', 'Do not print terminal QR')
  .action(mobilePairCommand);

program
  .command('run')
  .description('Run the agent')
  .option('-m, --mode <mode>', 'Run mode: proxy, mcp, http-mcp, or sdk (default: proxy)')
  .option('-p, --port <port>', 'Port for proxy mode (default: 8420)')
  .option('--host <host>', 'Host for HTTP MCP/proxy mode (default: 127.0.0.1)')
  .option('-a, --agent <id>', 'Agent ID or name to use (default: first configured)')
  .option('-d, --debug', 'Enable debug logging')
  .option('--daemon', 'Run in background (survives SSH disconnect)')
  .option('--force-relay', 'Force relay mode (skip local vault detection)')
  .action(runCommand);

program
  .command('status')
  .description('Show agent status')
  .option('-j, --json', 'Output as JSON')
  .action(statusCommand);

program
  .command('list')
  .description('List configured agents')
  .option('-j, --json', 'Output as JSON')
  .action(listCommand);

program
  .command('remove <agent_id>')
  .description('Remove an agent configuration')
  .action(removeCommand);

program
  .command('stop')
  .description('Stop the daemon agent')
  .action(stopCommand);

program
  .command('secrets')
  .description('OpenClaw secrets provider - reads from stdin, writes to stdout')
  .action(async () => {
    await processSecretsRequest();
  });

program
  .command('get-secret <scope>')
  .description('Get a single secret from the vault')
  .option('-j, --json', 'Output as JSON')
  .action(async (scope: string, options: { json?: boolean }) => {
    try {
      const value = await fetchSecret(scope);
      if (value === null) {
        error(`No value found for scope: ${scope}`);
        process.exit(1);
      }
      if (options.json) {
        console.log(JSON.stringify({ scope, value }));
      } else {
        console.log(value);
      }
    } catch (err) {
      if (err instanceof AgentError) {
        error(err.message);
      } else {
        error(err instanceof Error ? err.message : 'Unknown error');
      }
      process.exit(1);
    }
  });

// VPS service installation commands
program.addCommand(installServiceCommand);
program.addCommand(configureOpenClawCommand);
program.addCommand(uninstallServiceCommand);

program.parse();
