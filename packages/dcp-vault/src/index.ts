/**
 * @dcprotocol/vault
 *
 * DCP Vault - Local vault runtime with CLI and server.
 * Consolidates the former dcp-server and dcp-cli packages.
 */

// Server exports
export { buildServer } from './server/index.js';

// CLI is available as a binary (dcp, dcp-vault)
// Import it directly if needed:
// import './cli/index.js';
