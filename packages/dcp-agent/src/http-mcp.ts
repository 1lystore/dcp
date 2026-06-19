/**
 * DCP Agent HTTP MCP Server
 *
 * Streamable HTTP MCP transport for VPS/OpenClaw agents.
 * Per MCP spec: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
 *
 * This complements stdio MCP (for Claude Desktop/Cursor/VS Code) with HTTP MCP
 * (for VPS agents, OpenClaw, Hermes, and other URL-based MCP clients).
 *
 * Endpoint: http://127.0.0.1:8420/mcp
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
  isInitializeRequest,
} from '@modelcontextprotocol/sdk/types.js';

import { DcpError } from '@dcprotocol/client';
import { AgentConnection } from './connection.js';
import { SolanaReader, ReadInputError } from '@dcprotocol/wallet-core';
import {
  CANONICAL_SCOPE_GUIDE,
  SCOPE_PROPERTY_DESCRIPTION,
  VAULT_BUDGET_CHECK_DESCRIPTION,
  VAULT_GET_ADDRESS_DESCRIPTION,
  VAULT_GET_BALANCES_DESCRIPTION,
  VAULT_GET_TX_HISTORY_DESCRIPTION,
  VAULT_GET_TX_STATUS_DESCRIPTION,
  VAULT_READ_DESCRIPTION,
  VAULT_SCOPE_GUIDE_DESCRIPTION,
  VAULT_SEARCH_TOKENS_DESCRIPTION,
  VAULT_SIGN_MESSAGE_DESCRIPTION,
  VAULT_SIGN_TX_DESCRIPTION,
  VAULT_SIGN_X402_DESCRIPTION,
  VAULT_SWAP_DESCRIPTION,
  VAULT_TRANSFER_DESCRIPTION,
  VAULT_WRITE_DESCRIPTION,
} from './scope-guide.js';
import { AgentConfig, AgentError } from './types.js';
import { randomUUID } from 'node:crypto';

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 8420;
const MCP_PATH = '/mcp';
const HEALTH_PATH = '/health';

// Consent polling
const CONSENT_POLL_INTERVAL_MS = 2000;
const CONSENT_TIMEOUT_MS = 120000;

// ============================================================================
// Helpers
// ============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function log(message: string): void {
  console.log(`[DCP HTTP-MCP] ${message}`);
}

function logError(message: string): void {
  console.error(`[DCP HTTP-MCP] ERROR: ${message}`);
}

/**
 * Poll consent status until resolved
 */
async function pollConsentStatus(
  getStatus: (consentId: string) => Promise<{ status: string; sessionId?: string }>,
  consentId: string,
  expiresAt?: string
): Promise<{ status: string; session_id?: string }> {
  const startTime = Date.now();
  const expiryTime = expiresAt ? new Date(expiresAt).getTime() : startTime + CONSENT_TIMEOUT_MS;
  const timeout = Math.min(CONSENT_TIMEOUT_MS, expiryTime - startTime);

  log(`Waiting for consent approval (${consentId})...`);

  while (Date.now() - startTime < timeout) {
    await sleep(CONSENT_POLL_INTERVAL_MS);

    try {
      const data = await getStatus(consentId);

      if (data.status === 'approved') {
        log('Consent approved');
        return { status: data.status, session_id: data.sessionId };
      } else if (data.status === 'denied') {
        log('Consent denied');
        return { status: data.status, session_id: data.sessionId };
      } else if (data.status === 'expired' || data.status === 'not_found') {
        log('Consent expired or not found');
        return { status: data.status, session_id: data.sessionId };
      }
    } catch {
      // Network error, keep trying
    }
  }

  log('Consent timeout');
  return { status: 'timeout' };
}

// ============================================================================
// HTTP MCP Server Class
// ============================================================================

export interface HttpMcpServerOptions {
  host?: string;
  port?: number;
  forceRelay?: boolean;
}

export class HttpMcpServer {
  private config: AgentConfig;
  private connection: AgentConnection;
  private httpServer: ReturnType<typeof createServer> | null = null;
  private sessions = new Map<string, { server: Server; transport: StreamableHTTPServerTransport }>();
  private host: string;
  private port: number;
  private forceRelay: boolean;
  private reader: SolanaReader;

  constructor(config: AgentConfig, options?: HttpMcpServerOptions) {
    this.config = config;
    this.host = options?.host ?? DEFAULT_HOST;
    this.port = options?.port ?? DEFAULT_PORT;
    this.forceRelay = options?.forceRelay ?? process.env.DCP_FORCE_RELAY === '1';
    this.connection = new AgentConnection(config, { forceRelay: this.forceRelay });
    this.reader = new SolanaReader();
  }

  private createMcpServer(): Server {
    const server = new Server(
      {
        name: 'dcp-agent',
        version: '0.2.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolsHandler(server);
    this.setupCallToolHandler(server);
    return server;
  }

  private async parseJsonBody(req: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    if (chunks.length === 0) {
      return undefined;
    }

    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }

  private isInitializeMessage(body: unknown): boolean {
    if (Array.isArray(body)) {
      return body.some(isInitializeRequest);
    }
    return isInitializeRequest(body);
  }

  private async handleMcpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: unknown;
    if (req.method === 'POST') {
      try {
        body = await this.parseJsonBody(req);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32700, message: 'Parse error' },
          id: null,
        }));
        return;
      }
    }

    const rawSessionId = req.headers['mcp-session-id'];
    const sessionId = Array.isArray(rawSessionId) ? rawSessionId[0] : rawSessionId;
    let session = sessionId ? this.sessions.get(sessionId) : undefined;

    if (!session && req.method === 'POST' && !sessionId && this.isInitializeMessage(body)) {
      const server = this.createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          this.sessions.set(id, { server, transport });
        },
      });

      transport.onclose = () => {
        const id = transport.sessionId;
        if (id) {
          this.sessions.delete(id);
        }
      };

      await server.connect(transport);
      session = { server, transport };
    }

    if (!session) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Bad Request: No valid MCP session ID provided',
        },
        id: null,
      }));
      return;
    }

    await session.transport.handleRequest(req, res, body);
  }

  /**
   * Start the HTTP MCP server
   */
  async start(): Promise<void> {
    // Connect to vault via relay/local
    await this.connection.connect();

    // Create HTTP server
    this.httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);

      // Health check endpoint
      if (url.pathname === HEALTH_PATH && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', agent: this.config.agent_name }));
        return;
      }

      // MCP endpoint
      if (url.pathname === MCP_PATH) {
        try {
          await this.handleMcpRequest(req, res);
        } catch (err) {
          logError(`Request handling error: ${err instanceof Error ? err.message : String(err)}`);
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Internal server error' }));
          }
        }
        return;
      }

      // 404 for unknown paths
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    // Start listening
    await new Promise<void>((resolve, reject) => {
      this.httpServer!.on('error', reject);
      this.httpServer!.listen(this.port, this.host, () => {
        log(`Started on http://${this.host}:${this.port}`);
        log(`  MCP endpoint: http://${this.host}:${this.port}${MCP_PATH}`);
        log(`  Health check: http://${this.host}:${this.port}${HEALTH_PATH}`);
        log(`  Agent: ${this.config.agent_name}`);
        log(`  Vault: ${this.config.vault_id}`);
        log(`  Relay: ${this.forceRelay ? 'forced' : 'auto'}`);
        resolve();
      });
    });
  }

  /**
   * Stop the server
   */
  async stop(): Promise<void> {
    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
      });
    }
    for (const [sessionId, session] of this.sessions) {
      try {
        await session.transport.close();
        await session.server.close();
      } finally {
        this.sessions.delete(sessionId);
      }
    }
    await this.connection.close();
    log('Stopped');
  }

  /**
   * Set up the tools list handler
   */
  private setupToolsHandler(server: Server): void {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'vault_get_address',
            description: VAULT_GET_ADDRESS_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana. DCP is currently exposed as a Solana wallet.',
                },
              },
              required: ['chain'],
            },
          },
          {
            name: 'vault_budget_check',
            description: VAULT_BUDGET_CHECK_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                amount: {
                  type: 'number',
                  description: 'Transaction amount in the selected currency, for example 0.001 for SOL.',
                },
                currency: {
                  type: 'string',
                  description: 'Currency code. Use SOL, USDC, USDT, or 1LY.',
                },
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana when checking a Solana transaction.',
                },
              },
              required: ['amount', 'currency'],
            },
          },
          {
            name: 'vault_scope_guide',
            description: VAULT_SCOPE_GUIDE_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
          {
            name: 'vault_get_balances',
            description: VAULT_GET_BALANCES_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana. DCP is currently exposed as a Solana wallet.',
                },
              },
            },
          },
          {
            name: 'vault_get_tx_status',
            description: VAULT_GET_TX_STATUS_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                signature: {
                  type: 'string',
                  description: 'The base58 Solana transaction signature to look up.',
                },
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana.',
                },
              },
              required: ['signature'],
            },
          },
          {
            name: 'vault_get_tx_history',
            description: VAULT_GET_TX_HISTORY_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                limit: {
                  type: 'number',
                  description: 'Max signatures to return. Default 20, maximum 50.',
                },
                before: {
                  type: 'string',
                  description: 'Optional signature to paginate older activity from.',
                },
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana.',
                },
              },
            },
          },
          {
            name: 'vault_search_tokens',
            description: VAULT_SEARCH_TOKENS_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description: 'Token symbol, name, or mint to search for.',
                },
                limit: {
                  type: 'number',
                  description: 'Max results to return. Default 10, maximum 20.',
                },
              },
              required: ['query'],
            },
          },
          {
            name: 'vault_read',
            description: VAULT_READ_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                scope: {
                  type: 'string',
                  description: SCOPE_PROPERTY_DESCRIPTION,
                },
                fields: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Optional: specific fields to return',
                },
              },
              required: ['scope'],
            },
          },
          {
            name: 'vault_transfer',
            description: VAULT_TRANSFER_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana.',
                },
                to: {
                  type: 'string',
                  description: 'Recipient Solana address.',
                },
                amount: {
                  type: 'number',
                  description: 'Amount to send, for example 0.05 (SOL) or 1.5 (USDC).',
                },
                currency: {
                  type: 'string',
                  description: 'SOL for native, or a token symbol like USDC. For an arbitrary SPL token, also pass mint and decimals.',
                },
                mint: {
                  type: 'string',
                  description: 'Optional SPL token mint address (for tokens not in the registry). Requires decimals.',
                },
                decimals: {
                  type: 'number',
                  description: 'Optional token decimals; required when mint is provided.',
                },
                confirm: {
                  type: 'string',
                  enum: ['submitted', 'confirmed'],
                  description: "Optional. 'confirmed' (default) waits for on-chain confirmation; 'submitted' returns as soon as the tx is broadcast (faster; poll vault_get_tx_status to confirm).",
                },
                description: {
                  type: 'string',
                  description: 'Short human-readable explanation shown to the user for approval.',
                },
                idempotency_key: {
                  type: 'string',
                  description: 'Stable unique key for this intended transfer to prevent accidental double-sends.',
                },
              },
              required: ['chain', 'to', 'amount'],
            },
          },
          {
            name: 'vault_swap',
            description: VAULT_SWAP_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                chain: { type: 'string', enum: ['solana'], description: 'Use solana.' },
                from_token: { type: 'string', description: "Input token: 'SOL', a symbol like 'USDC', or a mint." },
                to_token: { type: 'string', description: "Output token: 'SOL', a symbol like 'USDC', or a mint." },
                amount: { type: 'number', description: 'Amount of the input token to swap.' },
                slippage_bps: { type: 'number', description: 'Slippage tolerance in basis points (default 50).' },
                from_decimals: { type: 'number', description: 'Decimals for from_token when it is an arbitrary mint.' },
                to_decimals: { type: 'number', description: 'Decimals for to_token when it is an arbitrary mint.' },
                confirm: { type: 'string', enum: ['submitted', 'confirmed'], description: "'confirmed' (default) waits; 'submitted' returns on broadcast." },
                description: { type: 'string', description: 'Short explanation shown to the user for approval.' },
                idempotency_key: { type: 'string', description: 'Stable unique key to prevent accidental double-swaps.' },
              },
              required: ['chain', 'from_token', 'to_token', 'amount'],
            },
          },
          {
            name: 'vault_sign_tx',
            description: VAULT_SIGN_TX_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana. DCP signs Solana transactions.',
                },
                unsigned_tx: {
                  type: 'string',
                  description: 'Unsigned Solana transaction encoded as base64.',
                },
                description: {
                  type: 'string',
                  description: 'Short human-readable explanation shown to the user for approval.',
                },
                amount: {
                  type: 'number',
                  description: 'Transaction amount for budget tracking and approval display.',
                },
                currency: {
                  type: 'string',
                  description: 'Currency code for budget tracking. Use 1LY for the SPL token mint Aih3sbAbu39Yn7jB2Qf4btZ5eWtDGQJH2gMfC4qdBAGS.',
                },
                destination: {
                  type: 'string',
                  description: 'Recipient/destination Solana address when available.',
                },
                idempotency_key: {
                  type: 'string',
                  description: 'Stable unique key for this intended transaction to prevent accidental duplicate signing.',
                },
              },
              required: ['chain', 'unsigned_tx'],
            },
          },
          {
            name: 'vault_sign_message',
            description: VAULT_SIGN_MESSAGE_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana. DCP signs Solana wallet messages.',
                },
                message: {
                  type: 'string',
                  description: 'Exact message to sign. Do not rewrite user-provided challenge text.',
                },
                encoding: {
                  type: 'string',
                  enum: ['utf8', 'base64'],
                  description: 'Use utf8 unless the message is already base64.',
                },
                description: {
                  type: 'string',
                  description: 'Short human-readable explanation shown to the user for approval.',
                },
              },
              required: ['chain', 'message'],
            },
          },
          {
            name: 'vault_sign_x402',
            description: VAULT_SIGN_X402_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                network: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Use solana. DCP signs Solana x402 payment payloads.',
                },
                payload: {
                  type: 'string',
                  description: 'Exact x402 payment payload encoded as base64. Do not rewrite it.',
                },
                amount: {
                  oneOf: [{ type: 'number' }, { type: 'string' }],
                  description: 'Payment amount for budget tracking and approval display.',
                },
                currency: {
                  type: 'string',
                  description: 'Currency code for budget tracking, for example SOL, USDC, USDT, or 1LY.',
                },
                recipient: {
                  type: 'string',
                  description: 'Payment recipient or merchant address when available.',
                },
                purpose: {
                  type: 'string',
                  description: 'Short human-readable purpose shown to the user for approval.',
                },
              },
              required: ['network', 'payload'],
            },
          },
          {
            name: 'vault_write',
            description: VAULT_WRITE_DESCRIPTION,
            inputSchema: {
              type: 'object',
              properties: {
                scope: {
                  type: 'string',
                  description: SCOPE_PROPERTY_DESCRIPTION,
                },
                data: {
                  type: 'object',
                  description: 'The data to store (object with key-value pairs)',
                },
              },
              required: ['scope', 'data'],
            },
          },
        ],
      };
    });
  }

  /**
   * Execute a tool call
   */
  private async executeToolCall(
    name: string,
    args: Record<string, unknown> | undefined
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    switch (name) {
      case 'vault_get_address': {
        const input = args as { chain: 'solana' };
        if (!input.chain) {
          throw new McpError(ErrorCode.InvalidParams, 'chain is required');
        }
        const result = await this.connection.getAddress(input.chain);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_budget_check': {
        const input = args as { amount: number; currency: string; chain?: 'solana' };
        if (input.amount === undefined || !input.currency) {
          throw new McpError(ErrorCode.InvalidParams, 'amount and currency are required');
        }
        const result = await this.connection.budgetCheck({
          amount: input.amount,
          currency: input.currency,
          chain: input.chain,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_scope_guide': {
        return {
          content: [{ type: 'text', text: CANONICAL_SCOPE_GUIDE }],
        };
      }

      case 'vault_get_balances': {
        const { address } = await this.connection.getAddress('solana');
        const result = await this.reader.getBalances(address);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_get_tx_status': {
        const input = args as { signature: string };
        if (!input.signature) {
          throw new McpError(ErrorCode.InvalidParams, 'signature is required');
        }
        const result = await this.reader.getTxStatus(input.signature);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_get_tx_history': {
        const input = (args ?? {}) as { limit?: number; before?: string };
        const { address } = await this.connection.getAddress('solana');
        const result = await this.reader.getTxHistory(address, {
          limit: input.limit,
          before: input.before,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_search_tokens': {
        const input = args as { query: string; limit?: number };
        if (!input.query) {
          throw new McpError(ErrorCode.InvalidParams, 'query is required');
        }
        const result = await this.reader.searchTokens(input.query, input.limit);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_read': {
        const input = args as { scope: string; fields?: string[] };
        if (!input.scope) {
          throw new McpError(ErrorCode.InvalidParams, 'scope is required');
        }
        const result = await this.connection.readCredential(input.scope, input.fields);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_transfer': {
        const input = args as {
          chain: 'solana';
          to: string;
          amount: number;
          currency?: string;
          mint?: string;
          decimals?: number;
          confirm?: 'submitted' | 'confirmed';
          description?: string;
          idempotency_key?: string;
        };
        if (!input.chain || !input.to || input.amount === undefined) {
          throw new McpError(ErrorCode.InvalidParams, 'chain, to, and amount are required');
        }
        const result = await this.connection.transfer({
          chain: input.chain,
          to: input.to,
          amount: input.amount,
          currency: input.currency,
          mint: input.mint,
          decimals: input.decimals,
          confirm: input.confirm,
          description: input.description,
          idempotencyKey: input.idempotency_key,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_swap': {
        const input = args as {
          chain: 'solana'; from_token: string; to_token: string; amount: number;
          slippage_bps?: number; from_decimals?: number; to_decimals?: number;
          confirm?: 'submitted' | 'confirmed'; description?: string; idempotency_key?: string;
        };
        if (!input.chain || !input.from_token || !input.to_token || input.amount === undefined) {
          throw new McpError(ErrorCode.InvalidParams, 'chain, from_token, to_token, and amount are required');
        }
        const result = await this.connection.swap({
          chain: input.chain,
          fromToken: input.from_token,
          toToken: input.to_token,
          amount: input.amount,
          slippageBps: input.slippage_bps,
          fromDecimals: input.from_decimals,
          toDecimals: input.to_decimals,
          confirm: input.confirm,
          description: input.description,
          idempotencyKey: input.idempotency_key,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_sign_tx': {
        const input = args as {
          chain: 'solana';
          unsigned_tx: string;
          description?: string;
          amount?: number;
          currency?: string;
          destination?: string;
          idempotency_key?: string;
        };
        if (!input.chain || !input.unsigned_tx) {
          throw new McpError(ErrorCode.InvalidParams, 'chain and unsigned_tx are required');
        }
        const result = await this.connection.signTx({
          chain: input.chain,
          unsignedTx: input.unsigned_tx,
          description: input.description,
          amount: input.amount,
          currency: input.currency,
          destination: input.destination,
          idempotencyKey: input.idempotency_key,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_sign_message': {
        const input = args as {
          chain: 'solana';
          message: string;
          encoding?: 'utf8' | 'base64';
          description?: string;
        };
        if (!input.chain || !input.message) {
          throw new McpError(ErrorCode.InvalidParams, 'chain and message are required');
        }
        const result = await this.connection.signMessage({
          chain: input.chain,
          message: input.message,
          encoding: input.encoding,
          description: input.description,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_sign_x402': {
        const input = args as {
          network: 'solana';
          payload: string;
          amount?: number | string;
          currency?: string;
          recipient?: string;
          purpose?: string;
        };
        if (!input.network || !input.payload) {
          throw new McpError(ErrorCode.InvalidParams, 'network and payload are required');
        }
        const result = await this.connection.signX402({
          network: input.network,
          payload: input.payload,
          amount: input.amount,
          currency: input.currency,
          recipient: input.recipient,
          purpose: input.purpose,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'vault_write': {
        const input = args as { scope: string; data: Record<string, unknown> };
        if (!input.scope || !input.data) {
          throw new McpError(ErrorCode.InvalidParams, 'scope and data are required');
        }
        const result = await this.connection.writeCredential(input.scope, input.data);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  }

  /**
   * Set up the call tool handler
   */
  private setupCallToolHandler(server: Server): void {
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        return await this.executeToolCall(name, args);
      } catch (error) {
        // Handle DcpError (especially CONSENT_REQUIRED)
        if (error instanceof DcpError) {
          if (error.code === 'CONSENT_REQUIRED') {
            const consentId = error.details.consent_id as string | undefined;
            const expiresAt = error.details.expires_at as string | undefined;

            if (!consentId) {
              throw new Error('CONSENT_REQUIRED error missing consent_id');
            }

            // Poll consent status until resolved
            const result = await pollConsentStatus(
              (id) => this.connection.getConsentStatus(id),
              consentId,
              expiresAt
            );

            if (result.status === 'approved') {
              // Retry the original request
              try {
                return await this.executeToolCall(name, args);
              } catch (retryError) {
                if (retryError instanceof DcpError) {
                  return {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify(
                          {
                            error: retryError.code,
                            message: retryError.message,
                          },
                          null,
                          2
                        ),
                      },
                    ],
                    isError: true,
                  };
                }
                throw retryError;
              }
            } else if (result.status === 'denied') {
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(
                      {
                        status: 'denied',
                        message: 'User denied the consent request.',
                      },
                      null,
                      2
                    ),
                  },
                ],
                isError: true,
              };
            } else {
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(
                      {
                        status: result.status,
                        message: `Consent ${result.status}. Please try again.`,
                        consent_id: consentId,
                      },
                      null,
                      2
                    ),
                  },
                ],
                isError: true,
              };
            }
          }

          if (error.code === 'CONSENT_DENIED') {
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      status: 'denied',
                      message: 'User denied the consent request.',
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
            };
          }

          // Other DcpErrors
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    error: error.code,
                    message: error.message,
                    details: error.details,
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }

        if (error instanceof AgentError) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(error.toJSON(), null, 2),
              },
            ],
            isError: true,
          };
        }

        if (error instanceof ReadInputError) {
          throw new McpError(ErrorCode.InvalidParams, error.message);
        }

        if (error instanceof McpError) {
          throw error;
        }

        const message = error instanceof Error ? error.message : String(error);
        throw new McpError(ErrorCode.InternalError, message);
      }
    });
  }
}

// ============================================================================
// Runner function
// ============================================================================

export async function runHttpMcpServer(
  config: AgentConfig,
  options?: HttpMcpServerOptions
): Promise<void> {
  const server = new HttpMcpServer(config, options);

  // Handle shutdown
  process.on('SIGINT', async () => {
    log('Shutting down...');
    await server.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await server.stop();
    process.exit(0);
  });

  await server.start();
}
