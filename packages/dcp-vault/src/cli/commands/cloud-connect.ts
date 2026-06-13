/**
 * dcp cloud-connect — manage Cloud-Connect links for cloud agents (OSS standalone).
 *
 * Lets a self-hoster drive the whole flow from the terminal without the desktop:
 *   dcp cloud-connect link <name> [--scopes ...] [--relay <url>]   # issue a connect-link
 *   dcp cloud-connect pending                                      # see who's waiting
 *   dcp cloud-connect approve <agentId> <matchCode>                # approve on-device
 *   dcp cloud-connect deny <agentId>
 *   dcp cloud-connect list
 *   dcp cloud-connect revoke <agentId>
 *
 * Storage-direct (same machine as the vault). Issuing needs the vault's relay
 * identity (kept in config), which this loads/creates the same way the server does.
 */

import { Command } from 'commander';
import { randomUUID } from 'crypto';
import {
  VaultStorage,
  getBudgetEngine,
  generateSigningKeyPair,
  createConnectLink,
} from '@dcprotocol/core';
import { generateKeyPair } from '@dcprotocol/relay-client';
import { success, error, info, dim, bold, handleError } from '../utils.js';

interface RelayIdentity {
  vaultId: string;
  relayUrl: string;
  hpkePublicKeyB64: string;
  signingPublicKeyB64: string;
  signingPrivateKey: Buffer;
}

function openVault(): { storage: VaultStorage; budget: ReturnType<typeof getBudgetEngine> } {
  const storage = new VaultStorage();
  storage.initializeSchema();
  const budget = getBudgetEngine(storage);
  return { storage, budget };
}

/** Load (or create) the vault's relay identity from config — mirrors the server. */
async function loadIdentity(budget: ReturnType<typeof getBudgetEngine>): Promise<RelayIdentity> {
  const config = budget.getConfig();

  let vaultId = config.vault_id;
  if (!vaultId) {
    vaultId = `vault_${randomUUID()}`;
    budget.setConfig('vault_id', vaultId);
  }

  const relayUrl = config.relay_url || process.env.DCP_RELAY_URL || '';

  let hpkePublicKeyB64 = config.relay_hpke_public_key || '';
  if (!hpkePublicKeyB64) {
    const kp = await generateKeyPair();
    hpkePublicKeyB64 = kp.publicKey.toString('base64');
    budget.setConfig('relay_hpke_public_key', hpkePublicKeyB64);
    budget.setConfig('relay_hpke_private_key', kp.privateKey.toString('base64'));
  }

  let signingPublicKeyB64 = config.relay_signing_public_key || '';
  let signingPrivateKeyB64 = config.relay_signing_private_key || '';
  if (!signingPublicKeyB64 || !signingPrivateKeyB64) {
    const s = generateSigningKeyPair();
    signingPublicKeyB64 = s.publicKey.toString('base64');
    signingPrivateKeyB64 = s.privateKey.toString('base64');
    budget.setConfig('relay_signing_public_key', signingPublicKeyB64);
    budget.setConfig('relay_signing_private_key', signingPrivateKeyB64);
  }

  return {
    vaultId,
    relayUrl,
    hpkePublicKeyB64,
    signingPublicKeyB64,
    signingPrivateKey: Buffer.from(signingPrivateKeyB64, 'base64'),
  };
}

/** Derive the public MCP resource URL the agent connects to from a relay URL. */
function mcpUrlFor(relayUrl: string, vaultId: string): string {
  if (!relayUrl) return '';
  const https = relayUrl.replace(/^wss:\/\//, 'https://').replace(/^ws:\/\//, 'http://').replace(/\/+$/, '');
  return `${https}/v/${vaultId}/mcp`;
}

// ---------------------------------------------------------------------------

const linkCommand = new Command('link')
  .description('Issue a one-time connect-link for a cloud agent')
  .argument('<name>', 'A name for the agent (e.g. openclaw-aws)')
  .option('-s, --scopes <scopes>', 'Comma-separated scopes (e.g. read:wallet.address,sign:solana)', '')
  .option('-r, --relay <url>', 'Relay base URL (default: DCP_RELAY_URL / saved config)')
  .option('--budget-daily <n>', 'Daily budget (default: 0)', '0')
  .option('--currency <ccy>', 'Budget currency (default: USD)', 'USD')
  .option('--auto-approve <n>', 'Auto-approve under this amount (default: 0)', '0')
  .action(async (name: string, options) => {
    try {
      const { storage, budget } = openVault();
      const identity = await loadIdentity(budget);
      const relayUrl = options.relay || identity.relayUrl;
      if (!relayUrl) {
        error('No relay configured. Pass --relay <url> or set DCP_RELAY_URL.');
        process.exit(1);
      }

      const scopes = String(options.scopes || '')
        .split(',')
        .map((s: string) => s.trim())
        .filter(Boolean);
      const agentId = `agent_${randomUUID().replace(/-/g, '').slice(0, 16)}`;

      const link = createConnectLink(
        {
          vault_id: identity.vaultId,
          agent_id: agentId,
          agent_name: name,
          mode: 'mcp',
          relay_url: mcpUrlFor(relayUrl, identity.vaultId),
          vault_hpke_public_key: identity.hpkePublicKeyB64,
          vault_signing_public_key: identity.signingPublicKeyB64,
        },
        identity.signingPrivateKey
      );

      storage.createCloudConnectLink({
        link_id: link.link_id,
        secret: link.secret,
        agent_id: agentId,
        name,
        permission_scopes: scopes,
        budget: {
          daily: Math.max(0, Number(options.budgetDaily) || 0),
          currency: options.currency || 'USD',
          auto_approve_under: Math.max(0, Number(options.autoApprove) || 0),
        },
        expires_at: link.expires_at,
      });

      console.log();
      success('Connect-link created. Paste it into your cloud agent:');
      console.log();
      console.log(bold(link.token));
      console.log();
      console.log(dim(`Agent id:    ${agentId}`));
      console.log(dim(`Key pin:     ${link.vault_hpke_fingerprint.slice(0, 24)}…`));
      console.log(dim(`Expires:     ${link.expires_at}`));
      info('Then run `dcp cloud-connect pending` and approve, verifying the match code.');
      process.exit(0);
    } catch (err) {
      handleError(err);
    }
  });

const pendingCommand = new Command('pending')
  .description('List cloud agents waiting for your approval')
  .action(async () => {
    try {
      const { storage } = openVault();
      const pending = storage.listPendingCloudConnectApprovals();
      if (pending.length === 0) {
        info('No cloud agents waiting for approval.');
        return process.exit(0);
      }
      for (const p of pending) {
        console.log();
        console.log(bold(`${p.name}  ${dim(`(${p.agent_id})`)}`));
        console.log(`  Match code: ${bold(p.match_code || '—')}  ${dim('(confirm it matches the agent)')}`);
        console.log(dim(`  Source:     ${p.source_ip || 'unknown'}`));
        console.log(dim(`  Scopes:     ${p.permission_scopes.join(', ') || 'none'}`));
        console.log(
          dim(`  Budget:     ${p.budget.daily} ${p.budget.currency}/day, auto-approve under ${p.budget.auto_approve_under}`)
        );
        console.log(dim(`  Approve:    dcp cloud-connect approve ${p.agent_id} ${p.match_code || '<code>'}`));
      }
      process.exit(0);
    } catch (err) {
      handleError(err);
    }
  });

const approveCommand = new Command('approve')
  .description('Approve a pending cloud agent (verify the match code first)')
  .argument('<agentId>', 'Agent id from `pending`')
  .argument('<matchCode>', 'The match code shown on the agent side')
  .action(async (agentId: string, matchCode: string) => {
    try {
      const { storage } = openVault();
      const link = storage.getCloudConnectLinkByAgent(agentId);
      if (!link || link.status !== 'redeemed') {
        error('No pending approval for this agent.');
        process.exit(1);
      }
      if (!link.match_code || link.match_code.toUpperCase() !== matchCode.trim().toUpperCase()) {
        error('Match code does not match. Aborting (anti-phishing).');
        process.exit(1);
      }
      const result = storage.approveCloudConnectLink(link.link_id);
      if (!result.ok) {
        error(`Approval failed: ${result.reason}`);
        process.exit(1);
      }
      success(`Approved “${link.name}”. It can now operate via its own channel.`);
      process.exit(0);
    } catch (err) {
      handleError(err);
    }
  });

const denyCommand = new Command('deny')
  .description('Deny a pending cloud agent')
  .argument('<agentId>', 'Agent id from `pending`')
  .action(async (agentId: string) => {
    try {
      const { storage } = openVault();
      const link = storage.getCloudConnectLinkByAgent(agentId);
      if (!link) {
        error('No cloud-connect link for this agent.');
        process.exit(1);
      }
      storage.denyCloudConnectLink(link.link_id);
      success('Denied.');
      process.exit(0);
    } catch (err) {
      handleError(err);
    }
  });

const listCommand = new Command('list')
  .description('List all cloud-connect links')
  .action(async () => {
    try {
      const { storage } = openVault();
      const links = storage.listCloudConnectLinks();
      if (links.length === 0) {
        info('No cloud-connect links yet.');
        return process.exit(0);
      }
      for (const l of links) {
        console.log(`${bold(l.name)}  ${dim(l.agent_id)}  [${l.status}]  ${dim(l.created_at)}`);
      }
      process.exit(0);
    } catch (err) {
      handleError(err);
    }
  });

const revokeCommand = new Command('revoke')
  .description('Instantly revoke a cloud agent')
  .argument('<agentId>', 'Agent id to revoke')
  .action(async (agentId: string) => {
    try {
      const { storage } = openVault();
      const link = storage.getCloudConnectLinkByAgent(agentId);
      if (link) {
        storage.revokeCloudConnectLink(link.link_id);
      } else if (!storage.revokeAgentConnection(agentId)) {
        error('Agent not found.');
        process.exit(1);
      }
      success('Revoked. (If the vault server is running it also tells the relay to drop the agent.)');
      process.exit(0);
    } catch (err) {
      handleError(err);
    }
  });

export const cloudConnectCommand = new Command('cloud-connect')
  .description('Connect cloud agents (OpenClaw/Hermes/Claude.ai) via a one-time link')
  .addCommand(linkCommand)
  .addCommand(pendingCommand)
  .addCommand(approveCommand)
  .addCommand(denyCommand)
  .addCommand(listCommand)
  .addCommand(revokeCommand);
