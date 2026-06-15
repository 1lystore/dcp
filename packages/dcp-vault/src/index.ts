/**
 * @dcprotocol/vault
 *
 * DCP Vault - Local vault runtime with CLI and server.
 * Provides the local vault server and CLI binaries.
 */

// Server exports
export { buildServer, handleCloudConnectMcp } from './server/index.js';

// CLI is available as a binary (dcp, dcp-vault)
// Import it directly if needed:
// import './cli/index.js';
