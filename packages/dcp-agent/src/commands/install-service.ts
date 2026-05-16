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
const DCP_AGENT_ENTRY = path.join(DCP_DATA_DIR, 'node_modules', '@dcprotocol', 'agent', 'dist', 'index.js');
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

interface HermesTarget {
  kind: 'host' | 'docker';
  user: string;
  command: string;
  configPath?: string;
  home?: string;
  hermesHome?: string;
  host?: string;
  url?: string;
  containerId?: string;
  containerName?: string;
  network?: string;
  candidateHosts?: string[];
}

interface HermesConfigResult {
  detected: boolean;
  written: boolean;
  verified: boolean;
  reachable?: boolean;
  target?: HermesTarget;
  error?: string;
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

function isAbsoluteExecutable(filePath: string): boolean {
  return path.isAbsolute(filePath) && fs.existsSync(filePath) && Boolean(fs.statSync(filePath).mode & 0o111);
}

function isIpv4Host(host: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function isSafeLinuxUser(user: string): boolean {
  return /^[a-z_][a-z0-9_-]*[$]?$/.test(user);
}

function runAsUser(user: string, args: string[], timeout = 10000): string | null {
  if (!isSafeLinuxUser(user)) return null;
  try {
    if (user === 'root' && isRoot()) {
      return execFileSync(args[0], args.slice(1), {
        encoding: 'utf8',
        env: { ...process.env, HOME: '/root' },
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout,
      }).trim();
    }
    return execFileSync('sudo', ['-H', '-u', user, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout,
    }).trim();
  } catch {
    return null;
  }
}

function runAsUserWithEnv(user: string, env: Record<string, string>, args: string[], timeout = 10000): string | null {
  const envArgs = Object.entries(env).map(([key, value]) => `${key}=${value}`);
  if (user === 'root' && isRoot()) {
    try {
      return execFileSync('/usr/bin/env', [...envArgs, ...args], {
        encoding: 'utf8',
        env: { ...process.env, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout,
      }).trim();
    } catch {
      return null;
    }
  }
  return runAsUser(user, ['env', ...envArgs, ...args], timeout);
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

function getHermesCandidateUsers(): string[] {
  const users = new Set<string>();
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser && sudoUser !== 'root' && isSafeLinuxUser(sudoUser)) {
    users.add(sudoUser);
  }

  const psRows = execQuiet('ps -eo user=,comm=,args= 2>/dev/null');
  if (psRows) {
    for (const row of psRows.split('\n')) {
      const trimmed = row.trim();
      if (!trimmed || !trimmed.toLowerCase().includes('hermes')) continue;
      if (trimmed.includes(' dcp-agent ') || trimmed.includes(' npx ')) continue;

      const parts = trimmed.split(/\s+/);
      const user = parts[0];
      const command = parts[1] || '';
      const args = parts.slice(2).join(' ');

      if (
        user &&
        isSafeLinuxUser(user) &&
        (command === 'hermes' || args === 'hermes' || args.startsWith('hermes ') || args.includes('/hermes '))
      ) {
        users.add(user);
      }
    }
  }

  const passwdRows = execQuiet('getent passwd 2>/dev/null');
  if (passwdRows) {
    for (const row of passwdRows.split('\n')) {
      const [user, , uidRaw, , , home] = row.split(':');
      const uid = Number(uidRaw);
      if (!user || !home || !isSafeLinuxUser(user)) continue;
      if (user !== 'root' && (!Number.isFinite(uid) || uid < 1000)) continue;
      if (fs.existsSync(path.join(home, '.hermes', 'config.yaml'))) {
        users.add(user);
      }
    }
  }

  if (fs.existsSync('/root/.hermes/config.yaml')) {
    users.add('root');
  }

  return [...users];
}

function getProcessEnviron(pid: string): Record<string, string> {
  try {
    const raw = fs.readFileSync(`/proc/${pid}/environ`, 'utf8');
    const env: Record<string, string> = {};
    for (const entry of raw.split('\0')) {
      if (!entry) continue;
      const index = entry.indexOf('=');
      if (index <= 0) continue;
      env[entry.slice(0, index)] = entry.slice(index + 1);
    }
    return env;
  } catch {
    return {};
  }
}

function getHermesProcessHomes(): Map<string, string> {
  const homes = new Map<string, string>();
  const psRows = execQuiet('ps -eo pid=,user=,comm=,args= 2>/dev/null');
  if (!psRows) return homes;

  for (const row of psRows.split('\n')) {
    const trimmed = row.trim();
    if (!trimmed || !trimmed.toLowerCase().includes('hermes')) continue;
    const parts = trimmed.split(/\s+/);
    const pid = parts[0];
    const user = parts[1];
    if (!pid || !user || !isSafeLinuxUser(user)) continue;
    const env = getProcessEnviron(pid);
    if (env.HERMES_HOME) {
      homes.set(user, env.HERMES_HOME);
    }
  }

  return homes;
}

function getHermesActiveProfileHome(user: string): string | undefined {
  const home = runAsUser(user, ['bash', '-lc', 'printf "%s" "$HOME"']);
  if (!home) return undefined;

  const activeProfilePath = path.join(home, '.hermes', 'active_profile');
  try {
    const activeProfile = fs.readFileSync(activeProfilePath, 'utf8').trim();
    if (!activeProfile || activeProfile === 'default') return undefined;
    const profileHome = path.join(home, '.hermes', 'profiles', activeProfile);
    if (fs.existsSync(profileHome)) {
      return profileHome;
    }
  } catch {
    // Default profile.
  }

  return undefined;
}

function findHermesCommandForUser(user: string): string | null {
  const script = [
    'command -v hermes',
    'test -x "$HOME/.local/bin/hermes" && printf "%s\\n" "$HOME/.local/bin/hermes"',
    'test -x "$HOME/.hermes/hermes-agent/venv/bin/hermes" && printf "%s\\n" "$HOME/.hermes/hermes-agent/venv/bin/hermes"',
  ].join(' || ');
  const output = runAsUser(user, ['bash', '-lc', script]);
  return output?.split('\n').map((line) => line.trim()).find(Boolean) || null;
}

function detectHermesTarget(preferredUser?: string): HermesTarget | null {
  const processHomes = getHermesProcessHomes();
  const candidates = preferredUser && isSafeLinuxUser(preferredUser)
    ? [preferredUser, ...getHermesCandidateUsers().filter((user) => user !== preferredUser)]
    : getHermesCandidateUsers();

  for (const user of candidates) {
    const command = findHermesCommandForUser(user);
    if (!command) continue;

    const hermesHome = processHomes.get(user) || getHermesActiveProfileHome(user);
    const configEnv: Record<string, string> = hermesHome ? { HERMES_HOME: hermesHome } : {};
    const configPath = runAsUserWithEnv(user, configEnv, [command, 'config', 'path']);
    const home = runAsUser(user, ['bash', '-lc', 'printf "%s" "$HOME"']);
    return {
      kind: 'host',
      user,
      command,
      configPath: configPath || undefined,
      home: home || undefined,
      hermesHome,
    };
  }

  return null;
}

function getDockerGatewayCandidates(networks?: string): string[] {
  if ((networks || '').split(',').map((network) => network.trim()).includes('host')) {
    return ['127.0.0.1'];
  }

  const candidateHosts: string[] = [];
  for (const network of (networks || '').split(',')) {
    const trimmed = network.trim();
    if (!trimmed) continue;
    try {
      const raw = execFileSync('docker', ['network', 'inspect', trimmed], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 10000,
      });
      const parsed = JSON.parse(raw) as Array<{ IPAM?: { Config?: Array<{ Gateway?: string }> } }>;
      for (const item of parsed) {
        for (const config of item.IPAM?.Config || []) {
          if (config.Gateway && isIpv4Host(config.Gateway)) {
            candidateHosts.push(config.Gateway);
          }
        }
      }
    } catch {
      // Fall back to common Docker host aliases below.
    }
  }

  candidateHosts.push('172.17.0.1', 'host.docker.internal');
  return [...new Set(candidateHosts)];
}

function detectHermesDockerTarget(port: number): HermesTarget | null {
  const dockerRows = execQuiet(
    "docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Networks}}' 2>/dev/null"
  );
  if (!dockerRows) return null;

  const row = dockerRows
    .split('\n')
    .map((line) => line.trim())
    .find((line) => {
      const lower = line.toLowerCase();
      return lower.includes('hermes') || lower.includes('nousresearch/hermes-agent');
    });
  if (!row) return null;

  const [containerId, containerName, , networks] = row.split('|');
  const candidateHosts = getDockerGatewayCandidates(networks);
  const host = candidateHosts[0] || '172.17.0.1';

  return {
    kind: 'docker',
    user: 'hermes',
    command: '/opt/hermes/.venv/bin/hermes',
    configPath: '/opt/data/config.yaml',
    host,
    url: `http://${host}:${port}/mcp`,
    containerId,
    containerName,
    network: networks?.split(',')[0]?.trim(),
    candidateHosts,
  };
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
      const candidateHosts = getDockerGatewayCandidates(networks);

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

function getServiceNpmPath(): string {
  const npmPath = process.env.DCP_SERVICE_NPM || '/usr/bin/npm';
  if (!isAbsoluteExecutable(npmPath)) {
    throw new Error(`DCP_SERVICE_NPM must be an absolute executable path: ${npmPath}`);
  }
  return npmPath;
}

function getServiceNodeCommand(): string {
  const nodePath = process.env.DCP_SERVICE_NODE || process.execPath;
  if (!isAbsoluteExecutable(nodePath)) {
    throw new Error(`DCP_SERVICE_NODE must be an absolute executable path: ${nodePath}`);
  }
  return nodePath;
}

function installServiceRuntime(version: string): void {
  const serviceNpm = getServiceNpmPath();
  const packageSpec = `@dcprotocol/agent@${version}`;

  execFileSync(
    'sudo',
    [
      '-u',
      DCP_USER,
      'env',
      `HOME=${DCP_DATA_DIR}`,
      `NPM_CONFIG_CACHE=${DCP_NPM_CACHE_DIR}`,
      'NPM_CONFIG_UPDATE_NOTIFIER=false',
      serviceNpm,
      'install',
      '--omit=dev',
      '--no-audit',
      '--no-fund',
      '--prefix',
      DCP_DATA_DIR,
      packageSpec,
    ],
    {
      stdio: 'inherit',
    }
  );

  if (!fs.existsSync(DCP_AGENT_ENTRY)) {
    throw new Error(`Installed DCP agent entrypoint not found: ${DCP_AGENT_ENTRY}`);
  }
}

function buildSystemdService(version: string, mcpHost: string, port: number): string {
  const serviceNode = getServiceNodeCommand();
  return `[Unit]
Description=DCP Agent Service
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=simple
User=${DCP_USER}
Group=${DCP_USER}
WorkingDirectory=${DCP_DATA_DIR}
ExecStart=${serviceNode} ${DCP_AGENT_ENTRY} run --mode http-mcp --host ${mcpHost} --port ${port} --force-relay
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

function dockerExecOutput(containerId: string, args: string[], timeout = 10000): string | null {
  try {
    return execFileSync('docker', ['exec', containerId, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout,
    }).trim();
  } catch {
    return null;
  }
}

function dockerExecOutputAsUser(containerId: string, user: string, args: string[], timeout = 10000): string | null {
  try {
    return execFileSync('docker', ['exec', '-u', user, containerId, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout,
    }).trim();
  } catch {
    return null;
  }
}

function dockerExecHermes(containerId: string, args: string[], timeout = 15000): string | null {
  const commandCandidates = [
    ['/opt/hermes/.venv/bin/hermes', ...args],
    ['hermes', ...args],
  ];

  for (const command of commandCandidates) {
    const output = dockerExecOutputAsUser(containerId, 'hermes', command, timeout) ||
      dockerExecOutput(containerId, command, timeout);
    if (output !== null) return output;
  }

  return null;
}

function canContainerReach(containerId: string, url: string): boolean {
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

function canOpenClawContainerReach(containerId: string, url: string): boolean {
  return canContainerReach(containerId, url);
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

function printManualHermesInstructions(url: string, user?: string): void {
  const prefix = user && isSafeLinuxUser(user) && user !== 'root' ? `sudo -H -u ${user} ` : '';
  console.log();
  console.log(chalk.bold('Manual Hermes MCP config'));
  console.log(chalk.dim('Use this if automatic Hermes setup is not verified.'));
  console.log();
  console.log(`${prefix}hermes config set mcp_servers.dcp.url ${url}`);
  console.log(`${prefix}hermes config set mcp_servers.dcp.enabled true`);
  console.log(`${prefix}hermes config set mcp_servers.dcp.tools.prompts false`);
  console.log(`${prefix}hermes config set mcp_servers.dcp.tools.resources false`);
  console.log();
  console.log(chalk.dim('Then run /reload-mcp in Hermes or restart Hermes.'));
  console.log();
}

function printManualHermesDockerInstructions(url: string, containerName?: string): void {
  const container = containerName || '<hermes-container>';
  console.log();
  console.log(chalk.bold('Manual Hermes Docker MCP config'));
  console.log(chalk.dim('Use this if automatic Hermes Docker setup is not verified.'));
  console.log();
  console.log(`docker exec ${container} /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.url ${url}`);
  console.log(`docker exec ${container} /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.enabled true`);
  console.log(`docker exec ${container} /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.tools.prompts false`);
  console.log(`docker exec ${container} /opt/hermes/.venv/bin/hermes config set mcp_servers.dcp.tools.resources false`);
  console.log();
  console.log(chalk.dim('Then run /reload-mcp in Hermes or restart the Hermes container.'));
  console.log();
}

function verifyHostHermesConfig(target: HermesTarget, url: string): boolean {
  const configPath = target.configPath;
  if (configPath && fs.existsSync(configPath)) {
    try {
      const raw = fs.readFileSync(configPath, 'utf8');
      return raw.includes('mcp_servers') && raw.includes('dcp') && raw.includes(url);
    } catch {
      // Fall back to CLI output.
    }
  }

  const config = runAsUserWithEnv(
    target.user,
    target.hermesHome ? { HERMES_HOME: target.hermesHome } : {},
    [target.command, 'config', 'show'],
    15000
  );
  return Boolean(config && config.includes('mcp_servers') && config.includes('dcp') && config.includes(url));
}

function isHostHermesManaged(target: HermesTarget): boolean {
  if (target.hermesHome && fs.existsSync(path.join(target.hermesHome, '.managed'))) {
    return true;
  }
  if (target.configPath && fs.existsSync(path.join(path.dirname(target.configPath), '.managed'))) {
    return true;
  }
  return false;
}

function configureHermesDocker(target: HermesTarget, url: string): HermesConfigResult {
  if (!target.containerId) {
    return {
      detected: true,
      written: false,
      verified: false,
      reachable: false,
      target,
      error: 'missing Hermes container id',
    };
  }

  if (dockerExecOk(target.containerId, ['test', '-f', '/opt/data/.managed'])) {
    return {
      detected: true,
      written: false,
      verified: false,
      reachable: false,
      target,
      error: 'Hermes config is managed; edit mcp_servers declaratively',
    };
  }

  const writes = [
    ['config', 'set', 'mcp_servers.dcp.url', url],
    ['config', 'set', 'mcp_servers.dcp.enabled', 'true'],
    ['config', 'set', 'mcp_servers.dcp.tools.prompts', 'false'],
    ['config', 'set', 'mcp_servers.dcp.tools.resources', 'false'],
  ].map((args) => dockerExecHermes(target.containerId!, args));

  const written = writes.every((output) => output !== null);
  const config = dockerExecOutput(target.containerId, ['cat', '/opt/data/config.yaml']);
  const verified = Boolean(config && config.includes('mcp_servers') && config.includes('dcp') && config.includes(url));
  const parsedUrl = new URL(url);
  const reachable = canContainerReach(target.containerId, `http://${parsedUrl.hostname}:${parsedUrl.port || MCP_PORT}/health`);

  return {
    detected: true,
    written,
    verified,
    reachable,
    target,
    error: written ? undefined : 'docker exec hermes config set failed',
  };
}

function configureHermes(target: HermesTarget, url: string): HermesConfigResult {
  if (target.kind === 'docker') {
    return configureHermesDocker(target, url);
  }

  try {
    if (isHostHermesManaged(target)) {
      return {
        detected: true,
        written: false,
        verified: false,
        reachable: false,
        target,
        error: 'Hermes config is managed; edit mcp_servers declaratively',
      };
    }

    const configEnv: Record<string, string> = target.hermesHome ? { HERMES_HOME: target.hermesHome } : {};
    const writes = [
      ['config', 'set', 'mcp_servers.dcp.url', url],
      ['config', 'set', 'mcp_servers.dcp.enabled', 'true'],
      ['config', 'set', 'mcp_servers.dcp.tools.prompts', 'false'],
      ['config', 'set', 'mcp_servers.dcp.tools.resources', 'false'],
    ].map((args) => runAsUserWithEnv(target.user, configEnv, [target.command, ...args], 15000));

    const written = writes.every((output) => output !== null);
    if (!written) {
      return {
        detected: true,
        written: false,
        verified: false,
        target,
        error: 'hermes config set failed',
      };
    }

    const verified = verifyHostHermesConfig(target, url);

    return {
      detected: true,
      written: true,
      verified,
      reachable: true,
      target,
    };
  } catch (err) {
    return {
      detected: true,
      written: false,
      verified: false,
      reachable: false,
      target,
      error: err instanceof Error ? err.message : 'unknown error',
    };
  }
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

    if (!commandExists('systemctl')) {
      error('systemd is required for install-service, but systemctl was not found');
      process.exit(1);
    }

    const hostname = os.hostname();
    const version = getPackageVersion();
    if (version === '0.0.0') {
      error('Could not resolve @dcprotocol/agent package version');
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

    console.log('  Installing service runtime...');
    try {
      installServiceRuntime(version);
      success(`Installed @dcprotocol/agent@${version} into ${DCP_DATA_DIR}`);
    } catch (err) {
      error(`Failed to install service runtime: ${err instanceof Error ? err.message : 'Unknown error'}`);
      process.exit(1);
    }

    // 7. Generate keypair
    console.log('  Generating service keypair...');
    const { privateKey, publicKey } = generateAgentKeypair();

    // 8a. Submit pairing claim to relay
    console.log('  Submitting pairing claim to relay...');

    const claim = createPairingClaim(inviteData, privateKey, publicKey, hostname, version);
    const claimResult = await submitPairingClaim(claim, inviteData.relay_url);

    if (!claimResult.success) {
      error(`Failed to submit pairing claim: ${claimResult.error}`);
      console.log(chalk.dim('  Please check your invite and try again.'));
      privateKey.fill(0);
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
      privateKey.fill(0);
      process.exit(1);
    }

    success('Pairing approved!');
    console.log(chalk.dim(`    Agent ID: ${approvalResult.agent_id}`));
    console.log();

    console.log('  Storing private key...');
    fs.writeFileSync(
      DCP_KEY_FILE,
      Buffer.from(privateKey).toString('base64'),
      { mode: 0o600 }
    );
    privateKey.fill(0);
    execSync(`chown ${DCP_USER}:${DCP_USER} ${DCP_KEY_FILE}`);
    success(`Key stored: ${DCP_KEY_FILE} (mode 0600)`);

    // 10a. Detect local agent runtimes before writing the service. If an MCP
    // client runs in Docker bridge mode, bind HTTP MCP to a private Docker
    // gateway so the container can reach it without exposing the port publicly.
    let openClawTarget = detectOpenClawTarget(port);
    let hermesTarget = detectHermesDockerTarget(port) || detectHermesTarget();
    let mcpHost = openClawTarget?.host || (hermesTarget?.kind === 'docker' ? hermesTarget.host : undefined) || '127.0.0.1';
    if (openClawTarget?.containerName) {
      console.log(chalk.dim(`    OpenClaw detected: ${openClawTarget.containerName} on ${openClawTarget.network}`));
      console.log(chalk.dim(`    Private MCP URL: ${openClawTarget.url}`));
      console.log();
    }
    if (hermesTarget?.kind === 'docker') {
      console.log(chalk.dim(`    Hermes Docker detected: ${hermesTarget.containerName || hermesTarget.containerId} on ${hermesTarget.network}`));
      console.log(chalk.dim(`    Private MCP URL: ${hermesTarget.url}`));
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
    let hermesReachable = hermesTarget?.kind === 'host' ? true : false;
    let hermesConfig: HermesConfigResult = {
      detected: false,
      written: false,
      verified: false,
    };

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

    if (options.start && hermesTarget?.kind === 'docker' && hermesTarget.containerId) {
      console.log('  Checking Hermes container reachability...');
      hermesReachable = canContainerReach(
        hermesTarget.containerId,
        `http://${mcpHost}:${port}/health`
      );

      if (!hermesReachable && !openClawReachable) {
        const originalMcpHost = mcpHost;
        let testedServiceHost = originalMcpHost;
        const testedHosts = new Set([mcpHost]);
        for (const host of hermesTarget.candidateHosts || []) {
          if (!host || testedHosts.has(host)) continue;
          if (!isIpv4Host(host)) continue;
          testedHosts.add(host);

          console.log(chalk.dim(`    Trying Docker host ${host} for Hermes...`));
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

          if (canContainerReach(hermesTarget.containerId, `http://${host}:${port}/health`)) {
            mcpHost = host;
            hermesTarget = {
              ...hermesTarget,
              host,
              url: `http://${host}:${port}/mcp`,
            };
            serviceHealthy = true;
            hermesReachable = true;
            break;
          }
        }

        if (!hermesReachable && testedServiceHost !== originalMcpHost) {
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

      if (hermesReachable) {
        serviceHealthy = true;
        success(`Hermes can reach DCP: http://${mcpHost}:${port}/health`);
      } else if (openClawReachable) {
        warn('Hermes container could not reach DCP without changing the OpenClaw-reachable MCP host');
      } else {
        warn('Hermes container could not reach DCP from tested Docker host addresses');
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

    if (hermesTarget) {
      const hermesUrl = hermesTarget.kind === 'docker'
        ? (hermesTarget.url || `http://${mcpHost}:${port}/mcp`)
        : `http://${mcpHost}:${port}/mcp`;
      console.log('  Configuring Hermes MCP...');
      hermesConfig = configureHermes(hermesTarget, hermesUrl);
      if (hermesConfig.written) {
        success(`Hermes MCP configured: dcp -> ${hermesUrl}`);
        if (hermesTarget.kind === 'docker') {
          console.log(chalk.dim(`    Container: ${hermesTarget.containerName || hermesTarget.containerId}`));
        } else {
          console.log(chalk.dim(`    User: ${hermesTarget.user}`));
        }
        if (hermesTarget.configPath) {
          console.log(chalk.dim(`    Config: ${hermesTarget.configPath}`));
        }
        if (hermesConfig.verified) {
          success('Hermes MCP config verified');
        } else {
          warn('Hermes MCP config was written, but verification failed');
        }
      } else {
        warn(`Hermes was detected, but automatic MCP configuration failed${hermesConfig.error ? `: ${hermesConfig.error}` : ''}`);
      }
    }

    if (options.start && !serviceHealthy) {
      const finalHealthyHost = await waitForEitherHealth([mcpHost, '127.0.0.1'], port, 10000);
      serviceHealthy = Boolean(finalHealthyHost);
    }

    // 13. Display success message
    console.log();
    if (options.start && !serviceHealthy) {
      console.log(chalk.bold.yellow('DCP Agent paired, but the service is not healthy yet.'));
    } else {
      console.log(chalk.bold.green('DCP Agent service installed and paired successfully!'));
    }
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
    if (hermesConfig.detected) {
      console.log(`    Hermes detected: ${chalk.green('yes')}`);
      if (hermesConfig.target?.kind === 'docker') {
        console.log(`    Hermes can reach DCP: ${hermesConfig.reachable ? chalk.green('yes') : chalk.yellow(options.start ? 'no' : 'not checked')}`);
      }
      console.log(`    Hermes config written: ${hermesConfig.written ? chalk.green('yes') : chalk.yellow('no')}`);
      console.log(`    Hermes config verified: ${hermesConfig.verified ? chalk.green('yes') : chalk.yellow('no')}`);
    } else {
      console.log(`    Hermes detected: ${chalk.yellow('no')}`);
    }
    console.log();

    if (!openClawTarget || !openClawConfigVerified) {
      printManualOpenClawInstructions(`http://${mcpHost}:${port}/mcp`, port);
    }
    if (hermesConfig.target?.kind === 'docker' && (!hermesConfig.verified || !hermesConfig.reachable)) {
      printManualHermesDockerInstructions(`http://${mcpHost}:${port}/mcp`, hermesConfig.target.containerName);
    } else if (!hermesConfig.detected || !hermesConfig.verified) {
      printManualHermesInstructions(`http://${mcpHost}:${port}/mcp`, hermesConfig.target?.user);
    } else {
      console.log(chalk.dim('After changing Hermes MCP config, run /reload-mcp in Hermes or restart Hermes.'));
      console.log();
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

    if (options.start && !serviceHealthy) {
      process.exitCode = 1;
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
