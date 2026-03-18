/**
 * dcp proxy
 *
 * Run a local proxy for remote agents (PRD Section B4 - Tier 3).
 *
 * The proxy:
 * 1. Runs a local HTTP server that mimics DCP REST endpoints
 * 2. Forwards requests through the relay to the actual vault using @dcprotocol/client
 *
 * This allows agents on remote VPS machines to connect via localhost
 * without holding any secrets.
 */

import { Command } from 'commander';
import chalk from 'chalk';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DcpClient, DcpError, generateSigningKeyPair } from '@dcprotocol/client';
import {
  error,
  success,
  handleError,
  dim,
  spinner,
  box,
} from '../utils.js';
import { DEFAULT_RELAY_URL } from '@dcprotocol/core';

// ============================================================================
// Command Definition
// ============================================================================

export const proxyCommand = new Command('proxy')
  .description('Run a local proxy for remote agents (Tier 3)')
  .option('-v, --vault <id>', 'Vault ID to proxy for (required)')
  .option('-r, --relay <url>', `Relay URL (default: ${DEFAULT_RELAY_URL})`)
  .option('-k, --hpke-key <key>', 'Vault HPKE public key (base64)')
  .option('-p, --port <port>', 'Local port to listen on (default: 8420)', '8420')
  .option('-s, --service-id <id>', 'Service identity (required for relay access)')
  .option('--service-key <key>', 'Service Ed25519 private key (required for relay access)')
  .option('--pair <token>', 'Pair this proxy using a pairing token (generates keys)')
  .option('-a, --agent-name <name>', 'Agent name to use for all proxied requests')
  .option('-d, --daemonize', 'Run in background')
  .action(async (options) => {
    try {
      await runProxy(options);
    } catch (err) {
      handleError(err);
    }
  });

// ============================================================================
// Proxy Configuration
// ============================================================================

interface ProxyOptions {
  vault?: string;
  relay?: string;
  hpkeKey?: string;
  port?: string;
  serviceId?: string;
  serviceKey?: string;
  pair?: string;
  agentName?: string;
  daemonize?: boolean;
}

interface ProxyConfig {
  vaultId: string;
  relayUrl: string;
  vaultHpkePublicKey: string;
  localPort: number;
  serviceId: string;
  servicePrivateKey: string;
  agentName: string;
}

// ============================================================================
// Run Proxy
// ============================================================================

async function runProxy(options: ProxyOptions): Promise<void> {
  // Vault ID
  if (!options.vault) {
    const vaultId = process.env.DCP_VAULT_ID;
    if (!vaultId) {
      error('Vault ID is required');
      console.log();
      console.log(dim('Usage: dcp proxy --vault=vault_abc123'));
      console.log(dim('   or: DCP_VAULT_ID=vault_abc123 dcp proxy'));
      console.log();
      process.exit(1);
    }
    options.vault = vaultId;
  }

  // HPKE public key
  const hpkeKey = options.hpkeKey || process.env.DCP_VAULT_HPKE_PUBLIC_KEY;
  if (!hpkeKey) {
    error('Vault HPKE public key is required');
    console.log();
    console.log(dim('Usage: dcp proxy --vault=... --hpke-key=<base64>'));
    console.log(dim('   or: DCP_VAULT_HPKE_PUBLIC_KEY=<base64> dcp proxy ...'));
    console.log();
    process.exit(1);
  }

  const relayUrl = options.relay || process.env.DCP_RELAY_URL || DEFAULT_RELAY_URL;

  // Service identity (required for relay)
  let serviceId = options.serviceId || process.env.DCP_SERVICE_ID;
  let serviceKey = options.serviceKey || process.env.DCP_SERVICE_PRIVATE_KEY;

  if (options.pair) {
    if (!serviceId) {
      serviceId = `proxy_${Date.now().toString(36)}`;
    }

    const keys = generateSigningKeyPair();
    const publicKey = keys.publicKey.toString('base64');
    const privateKey = keys.privateKey.toString('base64');

    const identityPath = getProxyIdentityPath(serviceId);
    fs.mkdirSync(path.dirname(identityPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(identityPath, JSON.stringify({
      service_id: serviceId,
      public_key: `ed25519:${publicKey}`,
      private_key: privateKey,
      created_at: new Date().toISOString(),
    }, null, 2), { mode: 0o600 });

    const client = new DcpClient({
      mode: 'relay',
      vaultId: options.vault,
      relayUrl,
      vaultHpkePublicKey: hpkeKey,
      serviceId,
      servicePrivateKey: privateKey,
      agentName: options.agentName || 'dcp-proxy',
    });

    const spinPair = spinner('Pairing proxy with vault...');
    spinPair.start();
    try {
      await client.pairService({
        pairingToken: options.pair,
        servicePublicKey: `ed25519:${publicKey}`,
        serviceName: options.agentName || serviceId,
      });
      spinPair.stop();
      success('Proxy paired');
    } catch (err) {
      spinPair.stop();
      throw err;
    } finally {
      await client.close();
    }

    serviceKey = privateKey;
  } else {
    if (!serviceId && process.env.DCP_SERVICE_ID) {
      serviceId = process.env.DCP_SERVICE_ID;
    }
    if (!serviceKey && serviceId) {
      const identity = loadProxyIdentity(serviceId);
      if (identity) {
        serviceKey = identity.private_key;
      }
    }
  }

  if (!serviceId || !serviceKey) {
    error('Service ID and private key are required for relay access');
    console.log();
    console.log(dim('Usage: dcp proxy --service-id=<id> --service-key=<ed25519_private_key>'));
    console.log(dim('   or: DCP_SERVICE_ID=... DCP_SERVICE_PRIVATE_KEY=... dcp proxy'));
    console.log(dim('   or: dcp proxy --pair <token> --service-id=<id>'));
    console.log();
    process.exit(1);
  }

  const config: ProxyConfig = {
    vaultId: options.vault,
    relayUrl,
    vaultHpkePublicKey: hpkeKey,
    localPort: parseInt(options.port || '8420', 10),
    serviceId,
    servicePrivateKey: serviceKey,
    agentName: options.agentName || process.env.DCP_AGENT_NAME || 'dcp-proxy',
  };

  console.log();
  console.log(chalk.bold('DCP Proxy'));
  console.log(dim('─'.repeat(50)));
  console.log();
  console.log(`  ${dim('Vault ID:')}  ${config.vaultId}`);
  console.log(`  ${dim('Relay:')}     ${config.relayUrl}`);
  console.log(`  ${dim('Local:')}     http://127.0.0.1:${config.localPort}`);
  console.log(`  ${dim('Service:')}   ${config.serviceId}`);
  console.log(`  ${dim('Agent:')}     ${config.agentName}`);
  console.log();

  const spin = spinner('Starting proxy...');
  spin.start();

  try {
    const proxy = new DcpProxy(config);
    await proxy.start();

    spin.stop();
    console.log();
    success('Proxy started');
    console.log();

    box([
      'DCP Proxy is running',
      '',
      `Agents can connect to: http://127.0.0.1:${config.localPort}`,
      '',
      'Agent configuration:',
      `  DCP_URL=http://127.0.0.1:${config.localPort}`,
      '  DCP_MODE=local',
      '',
      'Press Ctrl+C to stop',
    ], 'Running');

    // Keep process alive
    await new Promise(() => {});
  } catch (err) {
    spin.stop();
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Proxy Identity Helpers
// ---------------------------------------------------------------------------

function getProxyIdentityPath(serviceId: string): string {
  return path.join(os.homedir(), '.dcp', 'proxy', `${serviceId}.json`);
}

function loadProxyIdentity(serviceId: string): { private_key: string } | null {
  try {
    const identityPath = getProxyIdentityPath(serviceId);
    if (!fs.existsSync(identityPath)) return null;
    const raw = fs.readFileSync(identityPath, 'utf8');
    const parsed = JSON.parse(raw) as { private_key?: string };
    if (!parsed.private_key) return null;
    return { private_key: parsed.private_key };
  } catch {
    return null;
  }
}

// ============================================================================
// DCP Proxy Class
// ============================================================================

class DcpProxy {
  private config: ProxyConfig;
  private httpServer: http.Server | null = null;
  private client: DcpClient;

  constructor(config: ProxyConfig) {
    this.config = config;
    this.client = new DcpClient({
      mode: 'relay',
      vaultId: config.vaultId,
      relayUrl: config.relayUrl,
      vaultHpkePublicKey: config.vaultHpkePublicKey,
      serviceId: config.serviceId,
      servicePrivateKey: config.servicePrivateKey,
      agentName: config.agentName,
    });
  }

  async start(): Promise<void> {
    await this.startHttpServer();
  }

  private async startHttpServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.httpServer = http.createServer(async (req, res) => {
        await this.handleRequest(req, res);
      });

      this.httpServer.on('error', (err) => {
        if ((err as NodeJS.ErrnoException).code === 'EADDRINUSE') {
          error(`Port ${this.config.localPort} is already in use`);
          process.exit(1);
        }
        reject(err);
      });

      this.httpServer.listen(this.config.localPort, '127.0.0.1', () => {
        resolve();
      });
    });
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // Enable CORS for local agents
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      const url = new URL(req.url || '/', `http://127.0.0.1:${this.config.localPort}`);
      const path = url.pathname;
      const method = req.method || 'GET';
      const body = await this.readJsonBody(req);

      if (method === 'GET' && path === '/health') {
        this.sendJson(res, 200, {
          status: 'ok',
          initialized: true,
          unlocked: true,
          version: 'proxy',
          mode: 'proxy',
        });
        return;
      }

      if (method === 'GET' && path.startsWith('/address/')) {
        const chain = path.split('/')[2];
        const result = await this.client.getAddress(chain as 'solana' | 'base' | 'ethereum');
        this.sendJson(res, 200, {
          chain: result.chain,
          address: result.address,
        });
        return;
      }

      if (method === 'GET' && path === '/budget/check') {
        const amount = parseFloat(url.searchParams.get('amount') || '');
        const currency = url.searchParams.get('currency') || '';
        const chain = url.searchParams.get('chain') || undefined;

        const result = await this.client.budgetCheck({
          amount,
          currency,
          chain: chain as 'solana' | 'base' | 'ethereum' | undefined,
        });

        this.sendJson(res, 200, {
          allowed: result.allowed,
          limits: result.limits
            ? {
                per_tx: result.limits.perTx,
                daily: result.limits.daily,
                approval_threshold: result.limits.approvalThreshold,
              }
            : undefined,
          remaining: {
            daily: result.remainingDaily,
            per_tx: result.remainingTx,
          },
          requires_approval: result.requiresApproval,
          reason: result.reason,
        });
        return;
      }

      if (method === 'POST' && path === '/v1/vault/sign') {
        const result = await this.client.signTx({
          chain: body.chain,
          unsignedTx: body.unsigned_tx,
          amount: body.amount,
          currency: body.currency,
          description: body.description,
          idempotencyKey: body.idempotency_key,
          destination: body.destination,
        });
        this.sendJson(res, 200, {
          signed_tx: result.signedTx,
          signature: result.signature,
          chain: result.chain,
          remaining_daily: result.remainingDaily,
          session_id: result.sessionId,
        });
        return;
      }

      if (method === 'POST' && path === '/v1/vault/sign_message') {
        const result = await this.client.signMessage({
          chain: body.chain,
          message: body.message,
          encoding: body.encoding,
          description: body.description,
        });
        this.sendJson(res, 200, {
          signature: result.signature,
          public_key: result.publicKey,
          chain: result.chain,
          session_id: result.sessionId,
        });
        return;
      }

      if (method === 'POST' && path === '/v1/vault/sign_typed_data') {
        const result = await this.client.signTypedData({
          chain: body.chain,
          typedData: body.typed_data,
          description: body.description,
        });
        this.sendJson(res, 200, {
          signature: result.signature,
          public_key: result.publicKey,
          chain: result.chain,
          session_id: result.sessionId,
        });
        return;
      }

      if (method === 'POST' && path === '/v1/vault/sign_x402') {
        const result = await this.client.signX402({
          network: body.network,
          payload: body.payload,
          amount: body.amount,
          currency: body.currency,
          recipient: body.recipient,
          purpose: body.purpose,
          typedData: body.typed_data,
        });
        this.sendJson(res, 200, {
          signature: result.signature,
          public_key: result.publicKey,
          chain: result.chain,
          session_id: result.sessionId,
        });
        return;
      }

      if (method === 'POST' && path === '/v1/vault/read') {
        const result = await this.client.readCredential(body.scope, body.fields);
        this.sendJson(res, 200, {
          scope: result.scope,
          data: result.data,
          sensitivity: result.sensitivity,
          is_reference: result.isReference,
          session_id: result.sessionId,
        });
        return;
      }

      if (method === 'POST' && path === '/v1/vault/write') {
        const result = await this.client.writeCredential(body.scope, body.data);
        this.sendJson(res, 200, {
          scope: result.scope,
          created: result.created,
          updated: result.updated,
          sensitivity: result.sensitivity,
          session_id: result.sessionId,
        });
        return;
      }

      this.sendJson(res, 404, {
        error: { code: 'NOT_FOUND', message: 'Unknown endpoint' },
      });
    } catch (err) {
      this.handleProxyError(err, res);
    }
  }

  private async readJsonBody(req: http.IncomingMessage): Promise<Record<string, any>> {
    if (req.method === 'GET') return {};

    let body = '';
    for await (const chunk of req) {
      body += chunk;
    }

    if (!body) return {};

    try {
      return JSON.parse(body) as Record<string, any>;
    } catch {
      return {};
    }
  }

  private handleProxyError(err: unknown, res: http.ServerResponse): void {
    if (err instanceof DcpError) {
      if (err.code === 'CONSENT_REQUIRED') {
        this.sendJson(res, 200, {
          requires_consent: true,
          consent_id: err.details.consent_id,
          expires_at: err.details.expires_at,
          message: err.message,
        });
        return;
      }

      const status = err.code === 'VAULT_OFFLINE' ? 503 : 400;
      this.sendJson(res, status, err.toJSON());
      return;
    }

    const message = err instanceof Error ? err.message : 'Internal error';
    this.sendJson(res, 500, {
      error: { code: 'PROXY_ERROR', message },
    });
  }

  private sendJson(res: http.ServerResponse, status: number, payload: Record<string, unknown>): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  async stop(): Promise<void> {
    if (this.httpServer) {
      this.httpServer.close();
      this.httpServer = null;
    }
    await this.client.close();
  }
}
