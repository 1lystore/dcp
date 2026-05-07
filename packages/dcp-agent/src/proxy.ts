/**
 * DCP Agent Proxy Mode
 *
 * Runs a local HTTP server that proxies requests to the vault via relay.
 * Similar to dcp-proxy but uses pairing grants instead of service auth.
 */

import * as http from 'node:http';
import { AgentConnection } from './connection.js';
import { AgentConfig, AgentError } from './types.js';

// ============================================================================
// Proxy Server
// ============================================================================

export class AgentProxy {
  private config: AgentConfig;
  private connection: AgentConnection;
  private server: http.Server | null = null;
  private port: number;
  private forceRelay: boolean;

  constructor(config: AgentConfig, port: number = 8420, options?: { forceRelay?: boolean }) {
    this.config = config;
    this.forceRelay = options?.forceRelay ?? false;
    this.connection = new AgentConnection(config, { forceRelay: this.forceRelay });
    this.port = port;
  }

  /**
   * Start the proxy server
   */
  async start(): Promise<void> {
    // Connect to vault
    await this.connection.connect();

    // Start HTTP server
    await this.startHttpServer();
  }

  /**
   * Stop the proxy server
   */
  async stop(): Promise<void> {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    await this.connection.close();
  }

  /**
   * Get the port the server is running on
   */
  getPort(): number {
    return this.port;
  }

  private startHttpServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        await this.handleRequest(req, res);
      });

      this.server.on('error', (err) => {
        if ((err as NodeJS.ErrnoException).code === 'EADDRINUSE') {
          reject(new AgentError('CONNECTION_FAILED', `Port ${this.port} is already in use`));
          return;
        }
        reject(err);
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        resolve();
      });
    });
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      const url = new URL(req.url || '/', `http://127.0.0.1:${this.port}`);
      const reqPath = url.pathname;
      const method = req.method || 'GET';
      const body = await this.readJsonBody(req);

      // Health check
      if (method === 'GET' && reqPath === '/health') {
        this.sendJson(res, 200, {
          status: 'ok',
          agent_id: this.config.agent_id,
          agent_name: this.config.agent_name,
          vault_id: this.config.vault_id,
          mode: 'proxy',
          ...this.connection.getState(),
        });
        return;
      }

      // Capabilities
      if (method === 'GET' && (reqPath === '/capabilities' || reqPath === '/v1/capabilities')) {
        this.sendJson(res, 200, this.buildCapabilities());
        return;
      }

      // Get address
      if (method === 'GET' && reqPath.startsWith('/address/')) {
        const chain = reqPath.split('/')[2] as 'solana' | 'base' | 'ethereum';
        const result = await this.connection.getAddress(chain);
        this.sendJson(res, 200, result);
        return;
      }

      // Budget check
      if (method === 'GET' && reqPath === '/budget/check') {
        const amount = parseFloat(url.searchParams.get('amount') || '0');
        const currency = url.searchParams.get('currency') || 'USDC';
        const chain = url.searchParams.get('chain') as 'solana' | 'base' | 'ethereum' | undefined;

        const result = await this.connection.budgetCheck({ amount, currency, chain });
        this.sendJson(res, 200, result);
        return;
      }

      // Sign transaction
      if (method === 'POST' && reqPath === '/v1/vault/sign') {
        const result = await this.connection.signTx({
          chain: body.chain,
          unsignedTx: body.unsigned_tx,
          amount: body.amount,
          currency: body.currency,
          description: body.description,
          idempotencyKey: body.idempotency_key,
          destination: body.destination,
        });
        this.sendJson(res, 200, result);
        return;
      }

      // Sign message
      if (method === 'POST' && reqPath === '/v1/vault/sign_message') {
        const result = await this.connection.signMessage({
          chain: body.chain,
          message: body.message,
          encoding: body.encoding,
          description: body.description,
        });
        this.sendJson(res, 200, result);
        return;
      }

      // Sign typed data
      if (method === 'POST' && reqPath === '/v1/vault/sign_typed_data') {
        const result = await this.connection.signTypedData({
          chain: body.chain,
          typedData: body.typed_data,
          description: body.description,
        });
        this.sendJson(res, 200, result);
        return;
      }

      // Read credential
      if (method === 'POST' && reqPath === '/v1/vault/read') {
        const result = await this.connection.readCredential(body.scope, body.fields);
        this.sendJson(res, 200, result);
        return;
      }

      // Write credential
      if (method === 'POST' && reqPath === '/v1/vault/write') {
        const result = await this.connection.writeCredential(body.scope, body.data);
        this.sendJson(res, 200, result);
        return;
      }

      // Not found
      this.sendJson(res, 404, {
        error: { code: 'NOT_FOUND', message: 'Unknown endpoint' },
      });
    } catch (err) {
      this.handleError(err, res);
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

  private handleError(err: unknown, res: http.ServerResponse): void {
    if (err instanceof AgentError) {
      const status = err.code === 'RATE_LIMITED' ? 429 : 400;
      this.sendJson(res, status, err.toJSON());
      return;
    }

    const message = err instanceof Error ? err.message : 'Internal error';
    this.sendJson(res, 500, {
      error: { code: 'INTERNAL_ERROR', message },
    });
  }

  private sendJson(res: http.ServerResponse, status: number, payload: Record<string, unknown>): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  private buildCapabilities(): Record<string, unknown> {
    return {
      name: 'dcp-agent',
      version: '0.2.0',
      agent_id: this.config.agent_id,
      agent_name: this.config.agent_name,
      mode: this.config.mode,
      tier: this.config.tier,
      vault_id: this.config.vault_id,
      relay_url: this.config.relay_url,
      local_url: `http://127.0.0.1:${this.port}`,
      permission_scopes: this.config.permission_scopes,
      budget: this.config.budget,
      routes: [
        { method: 'GET', path: '/health', description: 'Health check' },
        { method: 'GET', path: '/capabilities', description: 'List capabilities' },
        { method: 'GET', path: '/address/:chain', description: 'Get wallet address' },
        { method: 'GET', path: '/budget/check', description: 'Check budget limits' },
        { method: 'POST', path: '/v1/vault/sign', description: 'Sign transaction' },
        { method: 'POST', path: '/v1/vault/sign_message', description: 'Sign message' },
        { method: 'POST', path: '/v1/vault/sign_typed_data', description: 'Sign EIP-712 data' },
        { method: 'POST', path: '/v1/vault/read', description: 'Read credential' },
        { method: 'POST', path: '/v1/vault/write', description: 'Write credential' },
      ],
    };
  }
}
