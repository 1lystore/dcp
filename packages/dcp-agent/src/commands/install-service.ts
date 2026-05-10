/**
 * VPS Install-Service Command
 *
 * Installs DCP Agent as a systemd service on Linux VPS.
 * Requires sudo privileges.
 *
 * Security:
 * - Creates dedicated system user (dcp-agent)
 * - Stores private key with 0600 permissions
 * - Service runs as non-root user
 * - Systemd security hardening enabled
 */

import { Command } from 'commander';
import { execFileSync, execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import chalk from 'chalk';
import {
  generateAgentKeypair,
  generateVerificationPhrase,
  parsePairingInvite,
  createPairingClaim,
  submitPairingClaim,
  waitForPairingApproval,
} from '../pairing.js';

// ============================================================================
// Constants
// ============================================================================

const DCP_USER = 'dcp-agent';
const DCP_DATA_DIR = '/var/lib/dcp-agent';
const DCP_KEY_FILE = `${DCP_DATA_DIR}/service.key`;
const DCP_CONFIG_FILE = `${DCP_DATA_DIR}/config.json`;
const DCP_NPM_CACHE_DIR = `${DCP_DATA_DIR}/.npm`;
const SYSTEMD_SERVICE = '/etc/systemd/system/dcp-agent.service';
const MCP_PORT = 8420;
const SERVICE_HEALTH_TIMEOUT_MS = 90000;

interface OpenClawTarget {
  host: string;
  url: string;
  containerId?: string;
  containerName?: string;
  network?: string;
  candidateHosts: string[];
}

interface OpenClawConfigResult {
  written: boolean;
  verified: boolean;
  method?: string;
}

// ============================================================================
// Helpers
// ============================================================================

function isRoot(): boolean {
  return process.getuid?.() === 0;
}

function success(msg: string): void {
  console.log(chalk.green('✓'), msg);
}

function warn(msg: string): void {
  console.log(chalk.yellow('⚠'), msg);
}

function error(msg: string): void {
  console.error(chalk.red('✗'), msg);
}

function execQuiet(cmd: string): string | null {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

function getPackageVersion(): string {
  const currentFile = fileURLToPath(import.meta.url);
  const candidates = [
    path.resolve(path.dirname(currentFile), '..', 'package.json'),
    path.resolve(path.dirname(currentFile), '..', '..', 'package.json'),
    path.resolve(path.dirname(currentFile), '..', '..', '..', 'package.json'),
  ];

  for (const candidate of candidates) {
    try {
      const pkg = JSON.parse(fs.readFileSync(candidate, 'utf8')) as { name?: string; version?: string };
      if (pkg.name === '@dcprotocol/agent' && pkg.version) {
        return pkg.version;
      }
    } catch {
      // Try the next possible package location.
    }
  }

  return '0.0.0';
}

function commandExists(command: string): boolean {
  return Boolean(execQuiet(`command -v ${command} 2>/dev/null`));
}

function isIpv4Host(host: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function isSafeLinuxUser(user: string): boolean {
  return /^[a-z_][a-z0-9_-]*[$]?$/.test(user);
}

function getOpenClawGatewayUsers(): string[] {
  const users = new Set<string>();
  const psRows = execQuiet('ps -eo user=,comm=,args= 2>/dev/null');

  if (psRows) {
    for (const row of psRows.split('\n')) {
      const trimmed = row.trim();
      if (!trimmed || !trimmed.toLowerCase().includes('openclaw')) continue;
      if (trimmed.includes(' mcp ') || trimmed.includes(' npx ')) continue;

      const parts = trimmed.split(/\s+/);
      const user = parts[0];
      const command = parts[1] || '';
      const args = parts.slice(2).join(' ');

      if (
        user &&
        isSafeLinuxUser(user) &&
        (command === 'openclaw' || args === 'openclaw' || args.startsWith('openclaw '))
      ) {
        users.add(user);
      }
    }
  }

  if (execQuiet('id openclaw 2>/dev/null')) {
    users.add('openclaw');
  }

  return [...users];
}

function detectOpenClawTarget(port: number): OpenClawTarget | null {
  const dockerRows = execQuiet(
    "docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Networks}}' 2>/dev/null"
  );

  if (dockerRows) {
    const row = dockerRows
      .split('\n')
      .map((line) => line.trim())
      .find((line) => {
        const lower = line.toLowerCase();
        return lower.includes('openclaw');
      });

    if (row) {
      const [containerId, containerName, , networks] = row.split('|');
      const network = networks?.split(',')[0]?.trim();
      const candidateHosts: string[] = [];
      if (network) {
        const gateway = execQuiet(
          `docker network inspect ${network} --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null`
        );
        if (gateway) {
          candidateHosts.push(gateway);
        }
      }

      candidateHosts.push('172.17.0.1', 'host.docker.internal');

      if (candidateHosts.length > 0) {
        const host = candidateHosts[0];
        return {
          host,
          url: `http://${host}:${port}/mcp`,
          containerId,
          containerName,
          network,
          candidateHosts,
        };
      }
    }
  }

  if (commandExists('openclaw')) {
    return {
      host: '127.0.0.1',
      url: `http://127.0.0.1:${port}/mcp`,
      candidateHosts: ['127.0.0.1'],
    };
  }

  return null;
}

function openClawConfigJson(url: string): string {
  return JSON.stringify({
    url,
    transport: 'streamable-http',
    connectionTimeoutMs: 300000,
  });
}

function configureOpenClawAsUser(user: string, target: OpenClawTarget): boolean {
  if (!isSafeLinuxUser(user)) return false;
  try {
    execFileSync('sudo', ['-u', user, 'openclaw', 'mcp', 'set', 'dcp', openClawConfigJson(target.url)], {
      stdio: 'pipe',
    });
    return true;
  } catch {
    return false;
  }
}

function verifyOpenClawAsUser(user: string, target: OpenClawTarget): boolean {
  if (!isSafeLinuxUser(user)) return false;
  try {
    const output = execFileSync('sudo', ['-u', user, 'openclaw', 'mcp', 'show', 'dcp', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10000,
    });
    return output.includes(target.url) && output.includes('streamable-http');
  } catch {
    return false;
  }
}

function configureOpenClaw(target: OpenClawTarget, preferredUser?: string): OpenClawConfigResult {
  if (preferredUser) {
    const written = configureOpenClawAsUser(preferredUser, target);
    return {
      written,
      verified: written && verifyOpenClawAsUser(preferredUser, target),
      method: `host user ${preferredUser}`,
    };
  }

  for (const user of getOpenClawGatewayUsers()) {
    if (configureOpenClawAsUser(user, target)) {
      return {
        written: true,
        verified: verifyOpenClawAsUser(user, target),
        method: `host user ${user}`,
      };
    }
  }

  const config = JSON.stringify({
    url: target.url,
    transport: 'streamable-http',
    connectionTimeoutMs: 300000,
  });

  if (target.containerId) {
    try {
      execFileSync('docker', ['exec', target.containerId, 'openclaw', 'mcp', 'set', 'dcp', config], {
        stdio: 'pipe',
      });
      return {
        written: true,
        verified: verifyOpenClawConfig(target),
        method: `container ${target.containerName || target.containerId}`,
      };
    } catch {
      // Fall through to host CLI if available.
    }
  }

  if (commandExists('openclaw')) {
    try {
      execFileSync('openclaw', ['mcp', 'set', 'dcp', config], { stdio: 'pipe' });
      return {
        written: true,
        verified: verifyOpenClawConfig(target),
        method: 'current user',
      };
    } catch {
      return { written: false, verified: false };
    }
  }

  return { written: false, verified: false };
}

function getServiceNpmCommand(): string {
  return process.env.DCP_SERVICE_NPM || '/usr/bin/env npm';
}

function buildSystemdService(version: string, mcpHost: string, port: number): string {
  const serviceNpm = getServiceNpmCommand();
  return `[Unit]
Description=DCP Agent Service
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=simple
User=${DCP_USER}
Group=${DCP_USER}
WorkingDirectory=${DCP_DATA_DIR}
ExecStart=${serviceNpm} exec --yes --package @dcprotocol/agent@${version} -- dcp-agent run --mode http-mcp --host ${mcpHost} --port ${port} --force-relay
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${DCP_DATA_DIR}

# Environment
Environment=DCP_DATA_DIR=${DCP_DATA_DIR}
Environment=HOME=${DCP_DATA_DIR}
Environment=NPM_CONFIG_CACHE=${DCP_NPM_CACHE_DIR}
Environment=NPM_CONFIG_UPDATE_NOTIFIER=false
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
`;
}

async function isHttpOk(url: string, timeoutMs = 5000): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

async function waitForHealth(host: string, port: number, timeoutMs = 30000): Promise<boolean> {
  const healthUrl = `http://${host}:${port}/health`;
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await isHttpOk(healthUrl, 3000)) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return false;
}

async function waitForEitherHealth(hosts: string[], port: number, timeoutMs = SERVICE_HEALTH_TIMEOUT_MS): Promise<string | null> {
  const startedAt = Date.now();
  const seen = new Set<string>();
  const uniqueHosts = hosts.filter((host) => {
    if (!host || seen.has(host)) return false;
    seen.add(host);
    return true;
  });

  while (Date.now() - startedAt < timeoutMs) {
    for (const host of uniqueHosts) {
      if (await isHttpOk(`http://${host}:${port}/health`, 3000)) {
        return host;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  return null;
}

function dockerExecOk(containerId: string, args: string[]): boolean {
  try {
    execFileSync('docker', ['exec', containerId, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10000,
    });
    return true;
  } catch {
    return false;
  }
}

function canOpenClawContainerReach(containerId: string, url: string): boolean {
  const nodeScript = `
const url = process.argv[1];
const timeout = setTimeout(() => process.exit(3), 8000);
fetch(url)
  .then((response) => {
    clearTimeout(timeout);
    process.exit(response.ok ? 0 : 2);
  })
  .catch(() => process.exit(1));
`;

  if (dockerExecOk(containerId, ['node', '-e', nodeScript, url])) {
    return true;
  }
  if (dockerExecOk(containerId, ['curl', '-fsS', url])) {
    return true;
  }
  if (dockerExecOk(containerId, ['wget', '-qO-', url])) {
    return true;
  }
  return false;
}

function verifyOpenClawConfig(target: OpenClawTarget): boolean {
  if (target.containerId) {
    try {
      const output = execFileSync('docker', ['exec', target.containerId, 'openclaw', 'mcp', 'show', 'dcp', '--json'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
      return output.includes(target.url) && output.includes('streamable-http');
    } catch {
      return false;
    }
  }

  if (commandExists('openclaw')) {
    try {
      const output = execFileSync('openclaw', ['mcp', 'show', 'dcp', '--json'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
      return output.includes(target.url) && output.includes('streamable-http');
    } catch {
      return false;
    }
  }

  return false;
}

async function resolveReachableOpenClawTarget(target: OpenClawTarget, port: number): Promise<OpenClawTarget> {
  if (!target.containerId) {
    return target;
  }

  const seen = new Set<string>();
  const hosts = target.candidateHosts.filter((host) => {
    if (!host || seen.has(host)) return false;
    seen.add(host);
    return true;
  });

  for (const host of hosts) {
    const healthUrl = `http://${host}:${port}/health`;
    if (canOpenClawContainerReach(target.containerId, healthUrl)) {
      return {
        ...target,
        host,
        url: `http://${host}:${port}/mcp`,
      };
    }
  }

  return target;
}

function addSafeDockerBridgeFirewallRule(target: OpenClawTarget, port: number): boolean {
  if (!commandExists('ufw')) return false;
  if (target.network !== 'bridge' || target.host !== '172.17.0.1') return false;

  try {
    execFileSync('ufw', [
      'allow',
      'in',
      'on',
      'docker0',
      'from',
      '172.17.0.0/16',
      'to',
      '172.17.0.1',
      'port',
      String(port),
      'proto',
      'tcp',
    ], { stdio: 'pipe' });
    execFileSync('ufw', ['reload'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function printManualOpenClawInstructions(url: string, port: number): void {
  console.log();
  console.log(chalk.bold('Manual OpenClaw MCP config'));
  console.log(chalk.dim('Use this if automatic OpenClaw setup is not verified.'));
  console.log();
  console.log(chalk.dim('Gateway-user install:'));
  console.log(`  sudo -u openclaw openclaw mcp set dcp '${openClawConfigJson(url)}'`);
  console.log();
  console.log(chalk.dim('Manual config shape:'));
  console.log(JSON.stringify({
    mcp: {
      servers: {
        dcp: {
          url,
          transport: 'streamable-http',
          connectionTimeoutMs: 300000,
        },
      },
    },
  }, null, 2));
  console.log();
  console.log(chalk.dim('Health check:'));
  console.log(`  curl -s http://${new URL(url).hostname}:${port}/health`);
  console.log();
  console.log(chalk.dim('After changing OpenClaw MCP config, start a fresh OpenClaw chat/session so the new tools are loaded.'));
  console.log();
}

// ============================================================================
// Command Implementation
// ============================================================================

export const installServiceCommand = new Command('install-service')
  .description('Install DCP Agent as a system service (requires sudo)')
  .argument('<pairing-invite>', 'Pairing invite from DCP Desktop (dcp_pair_v1_...)')
  .option('--no-start', 'Do not start the service after installation')
  .option('--port <port>', 'MCP server port (default: 8420)', String(MCP_PORT))
  .action(async (pairingInvite: string, options: { start: boolean; port: string }) => {
    const port = parseInt(options.port, 10) || MCP_PORT;

    // 1. Check root privileges
    if (!isRoot()) {
      error('install-service requires root privileges');
      console.log();
      console.log('Run with sudo:');
      console.log(chalk.dim(`  sudo npx @dcprotocol/agent install-service ${pairingInvite}`));
      console.log();
      process.exit(1);
    }

    // 2. Check platform
    if (process.platform !== 'linux') {
      error('install-service is only supported on Linux');
      console.log(chalk.dim('For macOS/Windows, use: dcp-agent pair <invite>'));
      process.exit(1);
    }

    // 3. Validate invite format (VPS uses dcp_vps_v1_ prefix)
    if (!pairingInvite.startsWith('dcp_vps_v1_')) {
      error('Invalid pairing invite format');
      console.log(chalk.dim('VPS invite must start with: dcp_vps_v1_'));
      console.log(chalk.dim('Generate a VPS pairing invite from DCP Desktop.'));
      process.exit(1);
    }

    console.log();
    console.log(chalk.bold('Installing DCP Agent Service'));
    console.log(chalk.dim('─'.repeat(50)));
    console.log();

    // 4. Parse the invite
    let inviteData;
    try {
      inviteData = parsePairingInvite(pairingInvite);
    } catch (err) {
      error(err instanceof Error ? err.message : 'Failed to parse invite');
      process.exit(1);
    }

    // 5. Create system user (if not exists)
    console.log('  Creating system user...');
    const userExists = execQuiet(`id ${DCP_USER} 2>/dev/null`);
    if (!userExists) {
      try {
        execSync(`useradd --system --no-create-home --shell /bin/false ${DCP_USER}`, {
          stdio: 'inherit',
        });
        success(`Created user: ${DCP_USER}`);
      } catch (err) {
        error(`Failed to create user: ${err instanceof Error ? err.message : 'Unknown error'}`);
        process.exit(1);
      }
    } else {
      console.log(chalk.dim(`    User ${DCP_USER} already exists`));
    }

    // 6. Create data directory
    console.log('  Creating data directory...');
    if (!fs.existsSync(DCP_DATA_DIR)) {
      fs.mkdirSync(DCP_DATA_DIR, { recursive: true, mode: 0o700 });
    }
    if (!fs.existsSync(DCP_NPM_CACHE_DIR)) {
      fs.mkdirSync(DCP_NPM_CACHE_DIR, { recursive: true, mode: 0o700 });
    }
    execSync(`chown -R ${DCP_USER}:${DCP_USER} ${DCP_DATA_DIR}`);
    execSync(`chmod 700 ${DCP_DATA_DIR}`);
    success(`Created: ${DCP_DATA_DIR}`);

    // 7. Generate keypair
    console.log('  Generating service keypair...');
    const { privateKey, publicKey } = generateAgentKeypair();

    // 8. Store private key securely
    console.log('  Storing private key...');
    fs.writeFileSync(
      DCP_KEY_FILE,
      Buffer.from(privateKey).toString('base64'),
      { mode: 0o600 }
    );
    execSync(`chown ${DCP_USER}:${DCP_USER} ${DCP_KEY_FILE}`);
    success(`Key stored: ${DCP_KEY_FILE} (mode 0600)`);

    // 8a. Submit pairing claim to relay
    console.log('  Submitting pairing claim to relay...');
    const hostname = os.hostname();
    const version = getPackageVersion();

    const claim = createPairingClaim(inviteData, privateKey, publicKey, hostname, version);
    const claimResult = await submitPairingClaim(claim, inviteData.relay_url);

    // SECURITY: Zeroize private key from memory AFTER signing the claim
    privateKey.fill(0);

    if (!claimResult.success) {
      error(`Failed to submit pairing claim: ${claimResult.error}`);
      console.log(chalk.dim('  Please check your invite and try again.'));
      if (fs.existsSync(DCP_KEY_FILE)) {
        fs.unlinkSync(DCP_KEY_FILE);
      }
      process.exit(1);
    }

    success('Pairing claim submitted');
    console.log(chalk.dim(`    Claim ID: ${claimResult.claim_id}`));

    // 9. Generate and display verification phrase
    const verificationPhrase = generateVerificationPhrase(publicKey, inviteData.invite_id);

    console.log();
    console.log('═══════════════════════════════════════════════════════════');
    console.log();
    console.log('  Verification phrase:');
    console.log();
    console.log(chalk.bold.cyan(`    ${verificationPhrase}`));
    console.log();
    console.log('═══════════════════════════════════════════════════════════');
    console.log();
    console.log(chalk.dim('Confirm this phrase matches in your DCP Desktop app,'));
    console.log(chalk.dim('then approve the pairing request.'));
    console.log();

    // 10. Wait for approval from vault (polls relay)
    console.log('  Waiting for approval from vault...');
    console.log(chalk.dim('    (Press Ctrl+C to cancel)'));
    console.log();

    const approvalResult = await waitForPairingApproval(
      claimResult.claim_id!,
      inviteData.relay_url
    );

    if (approvalResult.status !== 'approved' || !approvalResult.agent_id) {
      error(`Pairing request failed: ${approvalResult.status}${approvalResult.error ? ` - ${approvalResult.error}` : ''}`);
      console.log();
      console.log(chalk.dim('Generate a new pairing invite and try again.'));
      // Clean up key file since pairing failed
      if (fs.existsSync(DCP_KEY_FILE)) {
        fs.unlinkSync(DCP_KEY_FILE);
      }
      process.exit(1);
    }

    success('Pairing approved!');
    console.log(chalk.dim(`    Agent ID: ${approvalResult.agent_id}`));
    console.log();

    // 10a. Detect OpenClaw/Docker before writing the service. If OpenClaw runs
    // in Docker bridge mode, bind HTTP MCP to the private Docker gateway so the
    // container can reach it without exposing the port publicly.
    let openClawTarget = detectOpenClawTarget(port);
    let mcpHost = openClawTarget?.host || '127.0.0.1';
    if (openClawTarget?.containerName) {
      console.log(chalk.dim(`    OpenClaw detected: ${openClawTarget.containerName} on ${openClawTarget.network}`));
      console.log(chalk.dim(`    Private MCP URL: ${openClawTarget.url}`));
      console.log();
    }

    // 11. Store FULL config with agent_id (NO private key - that's in service.key)
    console.log('  Creating configuration...');
    const config = {
      // Agent identity (from approval)
      agent_id: approvalResult.agent_id,
      agent_name: hostname,
      mode: 'mcp',
      // Vault connection
      vault_id: inviteData.vault_id,
      relay_url: inviteData.relay_url,
      vault_public_key: inviteData.vault_public_key,
      vault_signing_key: inviteData.vault_signing_key,
      vault_hpke_public_key: inviteData.vault_public_key,
      vault_signing_public_key: inviteData.vault_signing_key,
      // Agent keypair (public only - private is in service.key)
      public_key: Buffer.from(publicKey).toString('base64'),
      // Metadata
      hostname,
      version,
      mcp_host: mcpHost,
      mcp_port: port,
      environment: 'vps',
      created_at: new Date().toISOString(),
      paired_at: new Date().toISOString(),
    };

    fs.writeFileSync(
      DCP_CONFIG_FILE,
      JSON.stringify(config, null, 2),
      { mode: 0o600 }
    );
    execSync(`chown ${DCP_USER}:${DCP_USER} ${DCP_CONFIG_FILE}`);
    success(`Config stored: ${DCP_CONFIG_FILE}`);

    // 12. Create systemd service
    console.log('  Creating systemd service...');
    fs.writeFileSync(SYSTEMD_SERVICE, buildSystemdService(version, mcpHost, port));
    success(`Service created: ${SYSTEMD_SERVICE}`);

    // 11. Enable service
    console.log('  Enabling service...');
    execSync('systemctl daemon-reload');
    execSync('systemctl enable dcp-agent');
    success('Service enabled');

    // 12. Start service (unless --no-start)
    if (options.start) {
      console.log('  Starting service...');
      try {
        execSync('systemctl restart dcp-agent');
        success('Service started');
      } catch {
        warn('Failed to start service (may need manual intervention)');
      }
    }

    let serviceHealthy = false;
    let openClawReachable = false;
    let openClawConfigWritten = false;
    let openClawConfigVerified = false;

    if (options.start) {
      console.log('  Checking DCP service health...');
      const healthyHost = await waitForEitherHealth([mcpHost, '127.0.0.1'], port);
      serviceHealthy = Boolean(healthyHost);
      if (serviceHealthy) {
        success(`DCP health OK: http://${healthyHost}:${port}/health`);
      } else {
        warn(`DCP health check failed: http://${mcpHost}:${port}/health`);
      }
    }

    if (options.start && openClawTarget?.containerId) {
      console.log('  Checking OpenClaw container reachability...');
      openClawTarget = await resolveReachableOpenClawTarget(openClawTarget, port);
      const containerId = openClawTarget.containerId;
      if (!containerId) {
        warn('OpenClaw container disappeared during reachability check');
      } else {
        openClawReachable = canOpenClawContainerReach(
          containerId,
          `http://${openClawTarget.host}:${port}/health`
        );

        if (!openClawReachable) {
          const originalMcpHost = mcpHost;
          let testedServiceHost = originalMcpHost;
          const testedHosts = new Set([openClawTarget.host]);
          for (const host of openClawTarget.candidateHosts) {
            if (!host || testedHosts.has(host)) continue;
            if (!isIpv4Host(host)) continue;
            testedHosts.add(host);

            console.log(chalk.dim(`    Trying Docker host ${host}...`));
            fs.writeFileSync(SYSTEMD_SERVICE, buildSystemdService(version, host, port));
            testedServiceHost = host;
            execSync('systemctl daemon-reload');
            try {
              execSync('systemctl restart dcp-agent');
            } catch {
              continue;
            }

            const candidateHealthy = await waitForHealth(host, port, 15000);
            if (!candidateHealthy) continue;

            if (canOpenClawContainerReach(containerId, `http://${host}:${port}/health`)) {
              mcpHost = host;
              openClawTarget = {
                ...openClawTarget,
                host,
                url: `http://${host}:${port}/mcp`,
              };
              serviceHealthy = true;
              openClawReachable = true;
              break;
            }
          }

          if (!openClawReachable && testedServiceHost !== originalMcpHost) {
            fs.writeFileSync(SYSTEMD_SERVICE, buildSystemdService(version, originalMcpHost, port));
            execSync('systemctl daemon-reload');
            try {
              execSync('systemctl restart dcp-agent');
              serviceHealthy = await waitForHealth(originalMcpHost, port, 15000);
            } catch {
              serviceHealthy = false;
            }
          }
        }

        if (openClawReachable) {
          serviceHealthy = true;
          success(`OpenClaw can reach DCP: http://${openClawTarget.host}:${port}/health`);
        } else {
          if (addSafeDockerBridgeFirewallRule(openClawTarget, port)) {
            openClawReachable = canOpenClawContainerReach(
              containerId,
              `http://${openClawTarget.host}:${port}/health`
            );
            if (openClawReachable) {
              serviceHealthy = true;
              success('Added safe UFW docker0 rule for DCP');
              success(`OpenClaw can reach DCP: http://${openClawTarget.host}:${port}/health`);
            }
          }
        }

        if (!openClawReachable) {
          warn('OpenClaw container could not reach DCP from tested Docker host addresses');
        }
      }
    }

    if (options.start && openClawTarget && !openClawTarget.containerId) {
      openClawReachable = await isHttpOk(`http://${openClawTarget.host}:${port}/health`);
      if (openClawReachable) {
        serviceHealthy = true;
        success(`Host OpenClaw can reach DCP: http://${openClawTarget.host}:${port}/health`);
      }
    }

    if (config.mcp_host !== mcpHost) {
      config.mcp_host = mcpHost;
      fs.writeFileSync(
        DCP_CONFIG_FILE,
        JSON.stringify(config, null, 2),
        { mode: 0o600 }
      );
      execSync(`chown ${DCP_USER}:${DCP_USER} ${DCP_CONFIG_FILE}`);
    }

    if (openClawTarget) {
      console.log('  Configuring OpenClaw MCP...');
      const openClawConfig = configureOpenClaw(openClawTarget);
      if (openClawConfig.written) {
        openClawConfigWritten = true;
        openClawConfigVerified = openClawConfig.verified;
        success(`OpenClaw MCP configured: dcp -> ${openClawTarget.url}`);
        if (openClawConfig.method) {
          console.log(chalk.dim(`    Method: ${openClawConfig.method}`));
        }
        if (openClawConfigVerified) {
          success('OpenClaw MCP config verified');
        } else {
          warn('OpenClaw MCP config was written, but verification failed');
        }
      } else {
        warn('OpenClaw was detected, but automatic MCP configuration failed');
        console.log(chalk.dim(`    Run manually: openclaw mcp set dcp '{"url":"${openClawTarget.url}","transport":"streamable-http","connectionTimeoutMs":300000}'`));
      }
    }

    if (options.start && !serviceHealthy) {
      const finalHealthyHost = await waitForEitherHealth([mcpHost, '127.0.0.1'], port, 10000);
      serviceHealthy = Boolean(finalHealthyHost);
    }

    // 13. Display success message
    console.log();
    console.log(chalk.bold.green('DCP Agent service installed and paired successfully!'));
    console.log();
    console.log(`  Agent ID: ${chalk.cyan(approvalResult.agent_id)}`);
    console.log();
    console.log('  Service status:');
    console.log(chalk.dim(`    systemctl status dcp-agent`));
    console.log();
    console.log('  View logs:');
    console.log(chalk.dim(`    journalctl -u dcp-agent -f`));
    console.log();
    console.log('  MCP endpoint:');
    console.log(chalk.dim(`    http://${mcpHost}:${port}/mcp`));
    console.log();
    console.log('  Install checks:');
    console.log(`    DCP service health: ${serviceHealthy ? chalk.green('ok') : chalk.yellow(options.start ? 'failed' : 'not checked')}`);
    if (openClawTarget) {
      console.log(`    OpenClaw detected: ${chalk.green('yes')}`);
      console.log(`    OpenClaw can reach DCP: ${openClawReachable ? chalk.green('yes') : chalk.yellow(options.start ? 'no' : 'not checked')}`);
      console.log(`    OpenClaw config written: ${openClawConfigWritten ? chalk.green('yes') : chalk.yellow('no')}`);
      console.log(`    OpenClaw config verified: ${openClawConfigVerified ? chalk.green('yes') : chalk.yellow('no')}`);
    } else {
      console.log(`    OpenClaw detected: ${chalk.yellow('no')}`);
    }
    console.log();

    if (!openClawTarget || !openClawConfigVerified) {
      printManualOpenClawInstructions(`http://${mcpHost}:${port}/mcp`, port);
    }

    // 14. Show service status
    if (options.start) {
      try {
        console.log(chalk.dim('─'.repeat(50)));
        console.log();
        execSync('systemctl status dcp-agent --no-pager -l', { stdio: 'inherit' });
      } catch {
        // Status command might exit with non-zero even when service is running
      }
    }
  });

export const configureOpenClawCommand = new Command('configure-openclaw')
  .description('Configure OpenClaw to use the local DCP Agent MCP server')
  .option('--user <user>', 'Linux user that runs the OpenClaw gateway, for example: openclaw')
  .option('--url <url>', 'DCP MCP URL, for example: http://172.17.0.1:8420/mcp')
  .option('--host <host>', 'DCP MCP host when --url is not provided')
  .option('--port <port>', 'DCP MCP port (default: 8420)', String(MCP_PORT))
  .option('--manual', 'Only print manual OpenClaw config instructions')
  .action((options: { user?: string; url?: string; host?: string; port: string; manual?: boolean }) => {
    const port = parseInt(options.port, 10) || MCP_PORT;
    let host = options.host || '127.0.0.1';

    try {
      if (!options.url && fs.existsSync(DCP_CONFIG_FILE)) {
        const stored = JSON.parse(fs.readFileSync(DCP_CONFIG_FILE, 'utf8')) as { mcp_host?: string; mcp_port?: number };
        host = stored.mcp_host || host;
      }
    } catch {
      // Fall back to provided/default host.
    }

    const url = options.url || `http://${host}:${port}/mcp`;
    const target: OpenClawTarget = {
      host: new URL(url).hostname,
      url,
      candidateHosts: [new URL(url).hostname],
    };

    if (options.manual) {
      printManualOpenClawInstructions(url, port);
      return;
    }

    console.log();
    console.log(chalk.bold('Configuring OpenClaw MCP'));
    console.log(chalk.dim('─'.repeat(50)));
    console.log();
    console.log(chalk.dim(`  DCP MCP URL: ${url}`));
    if (options.user) {
      console.log(chalk.dim(`  Gateway user: ${options.user}`));
    }
    console.log();

    const result = configureOpenClaw(target, options.user);
    if (result.written) {
      success(`OpenClaw MCP configured: dcp -> ${url}`);
      if (result.method) {
        console.log(chalk.dim(`    Method: ${result.method}`));
      }
      if (result.verified) {
        success('OpenClaw MCP config verified');
      } else {
        warn('OpenClaw MCP config was written, but verification failed');
        printManualOpenClawInstructions(url, port);
      }
    } else {
      error('Failed to configure OpenClaw automatically');
      printManualOpenClawInstructions(url, port);
      process.exit(1);
    }
  });

// ============================================================================
// Uninstall Command
// ============================================================================

export const uninstallServiceCommand = new Command('uninstall-service')
  .description('Uninstall DCP Agent system service (requires sudo)')
  .option('--keep-data', 'Keep agent data directory')
  .action((options: { keepData: boolean }) => {
    if (!isRoot()) {
      error('uninstall-service requires root privileges');
      console.log();
      console.log('Run with sudo:');
      console.log(chalk.dim('  sudo npx @dcprotocol/agent uninstall-service'));
      console.log();
      process.exit(1);
    }

    if (process.platform !== 'linux') {
      error('uninstall-service is only supported on Linux');
      process.exit(1);
    }

    console.log();
    console.log(chalk.bold('Uninstalling DCP Agent Service'));
    console.log(chalk.dim('─'.repeat(50)));
    console.log();

    // Stop service
    console.log('  Stopping service...');
    execQuiet('systemctl stop dcp-agent');

    // Disable service
    console.log('  Disabling service...');
    execQuiet('systemctl disable dcp-agent');

    // Remove service file
    if (fs.existsSync(SYSTEMD_SERVICE)) {
      console.log('  Removing service file...');
      fs.unlinkSync(SYSTEMD_SERVICE);
      execSync('systemctl daemon-reload');
    }

    // Remove data directory (unless --keep-data)
    if (!options.keepData && fs.existsSync(DCP_DATA_DIR)) {
      console.log('  Removing data directory...');
      fs.rmSync(DCP_DATA_DIR, { recursive: true, force: true });
    }

    console.log();
    success('DCP Agent service uninstalled');

    if (options.keepData) {
      console.log(chalk.dim(`  Data directory preserved: ${DCP_DATA_DIR}`));
    }
    console.log();
  });
