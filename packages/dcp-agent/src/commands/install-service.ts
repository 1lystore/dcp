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
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
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
const SYSTEMD_SERVICE = '/etc/systemd/system/dcp-agent.service';
const MCP_PORT = 8420;

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
  try {
    const pkgPath = new URL('../../package.json', import.meta.url);
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version?: string };
    return pkg.version || '0.2.0';
  } catch {
    return '0.2.0';
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
    execSync(`chown ${DCP_USER}:${DCP_USER} ${DCP_DATA_DIR}`);
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
      mcp_host: '127.0.0.1',
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
    const serviceFile = `[Unit]
Description=DCP Agent Service
After=network.target

[Service]
Type=simple
User=${DCP_USER}
Group=${DCP_USER}
WorkingDirectory=${DCP_DATA_DIR}
ExecStart=/usr/bin/env npx --yes @dcprotocol/agent run --mode http-mcp --port ${port}
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
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
`;

    fs.writeFileSync(SYSTEMD_SERVICE, serviceFile);
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
        execSync('systemctl start dcp-agent');
        success('Service started');
      } catch {
        warn('Failed to start service (may need manual intervention)');
      }
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
    console.log(chalk.dim(`    http://127.0.0.1:${port}/mcp`));
    console.log();

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
