#!/usr/bin/env node
/**
 * DCP Vault MCP Server
 *
 * MCP (Model Context Protocol) server for AI agents to interact with DCP Vault.
 * Runs as a stdio subprocess - no background daemon, no port.
 *
 * From PRD Section 3.1.3:
 * - M1: Run as stdio subprocess
 * - M2: Auto-start when MCP client connects, die on disconnect
 *
 * MCP Tools:
 * - vault_list_scopes() - List available scopes (no consent)
 * - vault_get_address(chain) - Get public address (no consent)
 * - vault_budget_check(amount, currency) - Check budget (no consent)
 * - vault_read(scope, fields?) - Read data (consent required)
 * - vault_sign_tx(chain, unsigned_tx, description?) - Sign transaction (consent required)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import {
  VaultStorage,
  BudgetEngine,
  getStorage,
  getBudgetEngine,
  VaultError,
} from '@dcprotocol/core';

import {
  vault_list_scopes,
  vault_get_address,
  vault_budget_check,
  vault_read,
  vault_sign_tx,
  ToolContext,
} from './tools.js';

import {
  GetAddressInput,
  BudgetCheckInput,
  ReadInput,
  SignTxInput,
} from './types.js';

// ============================================================================
// Server State
// ============================================================================

let storage: VaultStorage;
let budget: BudgetEngine;
let agentName = 'MCP Agent';
let sessionId: string | undefined;

// ============================================================================
// MCP Server Setup
// ============================================================================

const server = new Server(
  {
    name: 'dcp',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'vault_list_scopes',
        description: 'List all available scopes in the vault. Returns scopes, types, sensitivity levels, and available operations. No consent required.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'vault_get_address',
        description: 'Get the public wallet address for a blockchain. No consent required.',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              enum: ['solana', 'base', 'ethereum'],
              description: 'The blockchain to get the address for',
            },
          },
          required: ['chain'],
        },
      },
      {
        name: 'vault_budget_check',
        description: 'Check if a proposed transaction amount is within budget limits. Returns allowed status, limits, remaining budget, and whether approval is required. No consent required.',
        inputSchema: {
          type: 'object',
          properties: {
            amount: {
              type: 'number',
              description: 'The transaction amount to check',
            },
            currency: {
              type: 'string',
              description: 'The currency code (SOL, ETH, USDC, BASE_ETH)',
            },
          },
          required: ['amount', 'currency'],
        },
      },
      {
        name: 'vault_read',
        description: 'Read data from a vault scope. Requires user consent on first access. CRITICAL data (like private keys) returns a reference only, never the actual data.',
        inputSchema: {
          type: 'object',
          properties: {
            scope: {
              type: 'string',
              description: 'The scope to read (e.g., "address.home", "preferences.sizes")',
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
        description: 'Sign a transaction using the vault wallet. Requires user consent. The private key never leaves the vault.',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              enum: ['solana', 'base', 'ethereum'],
              description: 'The blockchain for the transaction',
            },
            unsigned_tx: {
              type: 'string',
              description: 'The unsigned transaction (base64 for Solana, JSON for EVM)',
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
    ],
  };
});

// ============================================================================
// Tool Handler
// ============================================================================

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // Create tool context
  const ctx: ToolContext = {
    storage,
    budget,
    agentName,
    sessionId,
  };

  try {
    switch (name) {
      case 'vault_list_scopes': {
        const result = await vault_list_scopes(ctx);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'vault_get_address': {
        const input = args as unknown as GetAddressInput;
        if (!input.chain) {
          throw new McpError(ErrorCode.InvalidParams, 'chain is required');
        }
        const result = await vault_get_address(ctx, input);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'vault_budget_check': {
        const input = args as unknown as BudgetCheckInput;
        if (input.amount === undefined || !input.currency) {
          throw new McpError(ErrorCode.InvalidParams, 'amount and currency are required');
        }
        const result = await vault_budget_check(ctx, input);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'vault_read': {
        const input = args as unknown as ReadInput;
        if (!input.scope) {
          throw new McpError(ErrorCode.InvalidParams, 'scope is required');
        }
        const result = await vault_read(ctx, input);
        // Update session ID if changed
        sessionId = ctx.sessionId;
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'vault_sign_tx': {
        const input = args as unknown as SignTxInput;
        if (!input.chain || !input.unsigned_tx) {
          throw new McpError(ErrorCode.InvalidParams, 'chain and unsigned_tx are required');
        }
        const result = await vault_sign_tx(ctx, input);
        // Update session ID if changed
        sessionId = ctx.sessionId;
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  } catch (error) {
    if (error instanceof VaultError) {
      // Convert VaultError to MCP error format
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
    // Unknown error
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, message);
  }
});

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  try {
    // Initialize vault storage (does NOT require unlock)
    storage = getStorage();
    budget = getBudgetEngine(storage);

    // Check if vault is unlocked (but don't fail if not)
    // Operations that need the master key will fail with VAULT_LOCKED
    if (!storage.isUnlocked()) {
      process.stderr.write('Warning: Vault is locked. Run "dcp unlock" to unlock.\n');
      process.stderr.write('Some operations will fail until the vault is unlocked.\n');
    }

    // Extract agent name from environment if available
    if (process.env.MCP_AGENT_NAME) {
      agentName = process.env.MCP_AGENT_NAME;
    }

    // Start the server with stdio transport
    const transport = new StdioServerTransport();
    await server.connect(transport);

    // Log startup to stderr (stdout is for MCP protocol)
    process.stderr.write('DCP Vault MCP Server started\n');
  } catch (error) {
    process.stderr.write(`Failed to start MCP server: ${error}\n`);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGINT', () => {
  process.stderr.write('Shutting down...\n');
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.stderr.write('Shutting down...\n');
  process.exit(0);
});

// Start the server
main();
