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
      const response = await fetch(`http://127.0.0.1:8421/consent/${consentId}/status`);
      if (!response.ok) continue;

      const data = (await response.json()) as { status: string; session_id?: string };

      if (data.status === 'approved') {
        log('Consent approved');
        return data;
      } else if (data.status === 'denied') {
        log('Consent denied');
        return data;
      } else if (data.status === 'expired' || data.status === 'not_found') {
        log('Consent expired or not found');
        return data;
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

  constructor(config: AgentConfig, options?: HttpMcpServerOptions) {
    this.config = config;
    this.host = options?.host ?? DEFAULT_HOST;
    this.port = options?.port ?? DEFAULT_PORT;
    this.forceRelay = options?.forceRelay ?? process.env.DCP_FORCE_RELAY === '1';
    this.connection = new AgentConnection(config, { forceRelay: this.forceRelay });
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
            description: 'Get the public wallet address for a blockchain. No consent required.',
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'The blockchain to get the address for',
                },
              },
              required: ['chain'],
            },
          },
          {
            name: 'vault_budget_check',
            description:
              'Check if a proposed transaction amount is within budget limits. Returns allowed status, limits, remaining budget, and whether approval is required. No consent required.',
            inputSchema: {
              type: 'object',
              properties: {
                amount: {
                  type: 'number',
                  description: 'The transaction amount to check',
                },
                currency: {
                  type: 'string',
                  description: 'The currency code (SOL, USDC, USDT)',
                },
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'Optional: The blockchain for chain-specific budget limits',
                },
              },
              required: ['amount', 'currency'],
            },
          },
          {
            name: 'vault_read',
            description: `Read data from the user's vault. Only use when the user explicitly asks you to read their info. Requires user consent.

Available scope patterns:
- identity.* — User identity (identity.name, identity.email, identity.phone, identity.home_address, etc.)
- credentials.api.* — API keys (credentials.api.openai, credentials.api.stripe, credentials.api.github, etc.)
- address.* — Saved addresses (address.home, address.work, address.shipping, etc.)

Example scopes: "identity.email", "credentials.api.openai", "address.home"`,
            inputSchema: {
              type: 'object',
              properties: {
                scope: {
                  type: 'string',
                  description: 'The scope to read. Patterns: identity.*, credentials.api.*, address.*',
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
            name: 'vault_sign_tx',
            description:
              'Sign a transaction using the vault wallet. Requires user consent. The private key never leaves the vault.',
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'The blockchain for the transaction',
                },
                unsigned_tx: {
                  type: 'string',
                  description: 'The unsigned transaction (base64 encoded)',
                },
                description: {
                  type: 'string',
                  description: 'Human-readable description of what the transaction does',
                },
                amount: {
                  type: 'number',
                  description: 'Transaction amount for budget tracking',
                },
                currency: {
                  type: 'string',
                  description: 'Currency code for budget tracking',
                },
                destination: {
                  type: 'string',
                  description: 'Destination address for the transaction',
                },
                idempotency_key: {
                  type: 'string',
                  description: 'Unique key to prevent duplicate transactions',
                },
              },
              required: ['chain', 'unsigned_tx'],
            },
          },
          {
            name: 'vault_sign_message',
            description: 'Sign an arbitrary message using the vault wallet. Requires user consent.',
            inputSchema: {
              type: 'object',
              properties: {
                chain: {
                  type: 'string',
                  enum: ['solana'],
                  description: 'The blockchain for the message signing',
                },
                message: {
                  type: 'string',
                  description: 'The message to sign (utf8 or base64)',
                },
                encoding: {
                  type: 'string',
                  enum: ['utf8', 'base64'],
                  description: 'Message encoding (default: utf8)',
                },
                description: {
                  type: 'string',
                  description: 'Human-readable description of what the message represents',
                },
              },
              required: ['chain', 'message'],
            },
          },
          {
            name: 'vault_write',
            description: `Store data in the user's vault. Only use when the user explicitly asks you to save/store something. Requires user consent.

Available scope patterns:
- identity.* — User identity (identity.name, identity.email, identity.phone, identity.home_address, etc.)
- credentials.api.* — API keys (credentials.api.openai, credentials.api.stripe, credentials.api.github, etc.)
- address.* — Saved addresses (address.home, address.work, address.shipping, etc.)

Example: scope="credentials.api.openai", data={"key": "sk-xxx", "name": "My OpenAI Key"}`,
            inputSchema: {
              type: 'object',
              properties: {
                scope: {
                  type: 'string',
                  description: 'The scope to write. Patterns: identity.*, credentials.api.*, address.*',
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
            const result = await pollConsentStatus(consentId, expiresAt);

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
