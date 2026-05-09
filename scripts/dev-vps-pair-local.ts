#!/usr/bin/env npx tsx
/**
 * Dev helper: pair a VPS-style DCP agent on the local machine.
 *
 * This intentionally skips Linux systemd/user installation, but keeps the real
 * remote pairing flow:
 * - parse dcp_vps_v1 invite
 * - generate sidecar keypair
 * - write service.key
 * - submit signed claim to relay
 * - wait for Desktop approval
 * - write VPS-style config.json
 *
 * Usage:
 *   npx tsx scripts/dev-vps-pair-local.ts 'dcp_vps_v1_...' --data-dir ~/dcp-vps-test
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  createPairingClaim,
  generateAgentKeypair,
  generateVerificationPhrase,
  parsePairingInvite,
  submitPairingClaim,
  waitForPairingApproval,
} from '../packages/dcp-agent/src/pairing.js';

function usage(): never {
  console.error('Usage: npx tsx scripts/dev-vps-pair-local.ts <dcp_vps_v1_...> --data-dir <path>');
  process.exit(1);
}

function expandHome(input: string): string {
  if (input === '~') return os.homedir();
  if (input.startsWith('~/')) return path.join(os.homedir(), input.slice(2));
  return input;
}

function parseArgs(): { invite: string; dataDir: string; port: number } {
  const args = process.argv.slice(2);
  const invite = args[0];
  if (!invite || invite.startsWith('--')) usage();

  let dataDir = '~/dcp-vps-test';
  let port = 8420;

  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--data-dir') {
      dataDir = args[++i] || usage();
    } else if (arg === '--port') {
      port = Number(args[++i] || '');
      if (!Number.isInteger(port) || port <= 0) usage();
    } else {
      usage();
    }
  }

  return { invite, dataDir: expandHome(dataDir), port };
}

function writePrivateFile(filePath: string, contents: string): void {
  fs.writeFileSync(filePath, contents, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

async function main(): Promise<void> {
  const { invite, dataDir, port } = parseArgs();

  if (!invite.startsWith('dcp_vps_v1_')) {
    throw new Error('Invite must start with dcp_vps_v1_');
  }

  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dataDir, 0o700);

  console.log('\nDCP local VPS pairing test');
  console.log('Data dir:', dataDir);

  const inviteData = parsePairingInvite(invite);
  console.log('Vault:', inviteData.vault_id);
  console.log('Relay:', inviteData.relay_url);
  console.log('Invite:', inviteData.invite_id);

  const { privateKey, publicKey } = generateAgentKeypair();
  const serviceKeyPath = path.join(dataDir, 'service.key');
  const configPath = path.join(dataDir, 'config.json');

  writePrivateFile(serviceKeyPath, Buffer.from(privateKey).toString('base64'));
  console.log('Wrote service key:', serviceKeyPath);

  const hostname = `${os.hostname()}-local-vps-test`;
  const version = '0.2.0-dev';
  const claim = createPairingClaim(inviteData, privateKey, publicKey, hostname, version);
  const claimResult = await submitPairingClaim(claim, inviteData.relay_url);
  privateKey.fill(0);

  if (!claimResult.success || !claimResult.claim_id) {
    fs.rmSync(serviceKeyPath, { force: true });
    throw new Error(`Failed to submit pairing claim: ${claimResult.error || 'unknown error'}`);
  }

  const verificationPhrase = generateVerificationPhrase(publicKey, inviteData.invite_id);
  console.log('\nVerification phrase:');
  console.log(`  ${verificationPhrase}`);
  console.log('\nApprove this pending VPS claim in DCP Desktop only if the phrase matches.\n');
  console.log('Waiting for approval...');

  const approval = await waitForPairingApproval(claimResult.claim_id, inviteData.relay_url);
  if (approval.status !== 'approved' || !approval.agent_id) {
    fs.rmSync(serviceKeyPath, { force: true });
    fs.rmSync(configPath, { force: true });
    throw new Error(`Pairing failed: ${approval.status}${approval.error ? ` - ${approval.error}` : ''}`);
  }

  const now = new Date().toISOString();
  const config = {
    agent_id: approval.agent_id,
    agent_name: hostname,
    mode: 'mcp',
    vault_id: inviteData.vault_id,
    relay_url: inviteData.relay_url,
    vault_public_key: inviteData.vault_public_key,
    vault_signing_key: inviteData.vault_signing_key,
    vault_hpke_public_key: inviteData.vault_public_key,
    vault_signing_public_key: inviteData.vault_signing_key,
    public_key: Buffer.from(publicKey).toString('base64'),
    hostname,
    version,
    mcp_host: '127.0.0.1',
    mcp_port: port,
    environment: 'vps',
    created_at: now,
    paired_at: now,
  };

  writePrivateFile(configPath, JSON.stringify(config, null, 2));
  console.log('\nPairing approved.');
  console.log('Agent ID:', approval.agent_id);
  console.log('Wrote config:', configPath);
  console.log('\nNext command:');
  console.log(`  DCP_DATA_DIR='${dataDir}' dcp-agent run --mode http-mcp --port ${port}`);
}

main().catch((err) => {
  console.error('\nError:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
