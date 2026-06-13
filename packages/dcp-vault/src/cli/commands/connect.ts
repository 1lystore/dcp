/**
 * dcp connect <service>
 *
 * Connect to a trusted service (protocol spec section B2).
 *
 * This command:
 * 1. Opens the service's auth URL in the browser
 * 2. User authenticates with the service
 * 3. DCP sends vault routing info (vault_id, hpke_public_key, relay_url)
 * 4. Service stores the mapping
 *
 * Usage:
 *   dcp connect 1ly                           # Connect to known service
 *   dcp connect my-bot --url=https://...      # Connect to custom service
 */

import { Command } from 'commander';
import chalk from 'chalk';
import * as http from 'http';
import * as crypto from 'crypto';
import {
  error,
  success,
  info,
  warn,
  handleError,
  dim,
  highlight,
  spinner,
  unlockVault,
  confirm,
  box,
} from '../utils.js';
import {
  VaultStorage,
  getKnownService,
  DEFAULT_RELAY_URL,
  type ServiceConnectionInfo,
} from '@dcprotocol/core';

// ============================================================================
// Command Definition
// ============================================================================

export const connectCommand = new Command('connect')
  .description('Connect to a trusted service')
  .argument('<service>', 'Service identifier (e.g., 1ly)')
  .option('-u, --url <url>', 'Service connection endpoint (for custom services)')
  .option('-a, --auth-url <url>', 'Service auth URL (for custom services)')
  .option('--no-browser', 'Do not open browser automatically')
  .option('-r, --relay-url <url>', 'Relay URL to use (required; or set DCP_RELAY_URL)')
  .action(async (serviceId: string, options) => {
    try {
      await connectToService(serviceId, options);
    } catch (err) {
      handleError(err);
    }
  });

// ============================================================================
// Connect to Service
// ============================================================================

async function connectToService(
  serviceId: string,
  options: {
    url?: string;
    authUrl?: string;
    browser?: boolean;
    relayUrl?: string;
  }
): Promise<void> {
  const storage = new VaultStorage();

  // Check if service is trusted
  const trustedService = storage.getTrustedService(serviceId);
  if (!trustedService) {
    error(`Service '${serviceId}' is not trusted`);
    console.log();
    console.log(dim('Trust the service first:'));
    console.log(dim(`  dcp trust ${serviceId}`));
    console.log();
    process.exit(1);
  }

  // Get service endpoints
  let connectUrl: string;
  let authUrl: string;

  const known = getKnownService(serviceId);
  if (known) {
    connectUrl = options.url || known.connect_url;
    authUrl = options.authUrl || known.auth_url;
  } else {
    // Custom service
    if (!options.url) {
      error('Connection URL is required for custom services');
      console.log();
      console.log(dim('Usage: dcp connect <service> --url=https://example.com/api/dcp/connect'));
      console.log();
      process.exit(1);
    }
    connectUrl = options.url;
    authUrl = options.authUrl || guessAuthUrl(connectUrl);
  }

  console.log();
  console.log(chalk.bold(`Connect to ${highlight(trustedService.name)}`));
  console.log(dim('─'.repeat(50)));
  console.log();
  console.log(`  ${dim('Service:')}  ${trustedService.service_id}`);
  console.log(`  ${dim('Scopes:')}   ${trustedService.scopes.join(', ')}`);
  console.log(`  ${dim('Budget:')}   ${trustedService.budget.daily} ${trustedService.budget.currency}/day`);
  console.log();

  // Unlock vault to get HPKE keys
  await unlockVault(storage, 'Unlock vault to connect');

  // Generate vault ID and HPKE keypair if not already present
  const { vaultId, hpkePublicKey } = await getOrCreateVaultIdentity(storage);
  const relayUrl = options.relayUrl || DEFAULT_RELAY_URL;

  if (!relayUrl) {
    console.error(
      'No relay URL configured. Pass --relay-url=<wss://your-relay> or set DCP_RELAY_URL ' +
        '(self-host your own @dcprotocol/relay).'
    );
    process.exit(1);
  }

  console.log(`  ${dim('Vault ID:')}  ${vaultId}`);
  console.log(`  ${dim('Relay:')}     ${relayUrl}`);
  console.log();

  // Prepare connection info
  const connectionInfo: ServiceConnectionInfo = {
    vault_id: vaultId,
    hpke_public_key: hpkePublicKey,
    relay_url: relayUrl,
    scopes_granted: trustedService.scopes,
  };

  // Start local callback server
  const { authToken, port } = await startCallbackServer();
  const callbackUrl = `http://localhost:${port}/callback`;

  // Build auth URL with callback
  const authUrlWithCallback = buildAuthUrl(authUrl, callbackUrl);

  console.log(dim('Opening browser for authentication...'));
  console.log();

  // Open browser
  if (options.browser !== false) {
    await openBrowser(authUrlWithCallback);
    info('Browser opened. Please authenticate with the service.');
  } else {
    console.log(dim('Open this URL in your browser:'));
    console.log();
    console.log(`  ${highlight(authUrlWithCallback)}`);
  }

  console.log();
  const spin = spinner('Waiting for authentication...');
  spin.start();

  // Wait for callback with auth token
  let receivedToken: string;
  try {
    receivedToken = await authToken;
    spin.stop();
    success('Authentication successful');
    console.log();
  } catch (err) {
    spin.stop();
    error('Authentication failed or timed out');
    throw err;
  }

  // Send connection info to service
  const connectSpin = spinner('Sending vault info to service...');
  connectSpin.start();

  try {
    await sendConnectionInfo(connectUrl, receivedToken, connectionInfo);
    connectSpin.stop();

    // Mark service as connected
    storage.markServiceConnected(serviceId);

    console.log();
    box([
      `Connected to ${trustedService.name}`,
      '',
      `Vault: ${vaultId}`,
      `Scopes: ${trustedService.scopes.join(', ')}`,
      `Budget: ${trustedService.budget.daily} ${trustedService.budget.currency}/day`,
      '',
      'Your keys never leave this machine.',
      `${trustedService.name} can now reach your vault via relay.`,
    ], 'Success');

  } catch (err) {
    connectSpin.stop();
    throw err;
  }
}

// ============================================================================
// Vault Identity
// ============================================================================

interface VaultIdentity {
  vaultId: string;
  hpkePublicKey: string;
}

async function getOrCreateVaultIdentity(storage: VaultStorage): Promise<VaultIdentity> {
  // Check if we have an existing vault identity
  const vaultConfig = storage.getRecord('system.vault_identity');

  if (vaultConfig) {
    // Decrypt and return existing identity
    const masterKey = storage.getMasterKey();
    const { envelopeDecrypt } = await import('@dcprotocol/core');

    const decrypted = envelopeDecrypt(
      {
        ciphertext: vaultConfig.ciphertext,
        nonce: vaultConfig.nonce,
        dek_wrapped: vaultConfig.dek_wrapped,
        dek_nonce: vaultConfig.dek_nonce,
      },
      masterKey
    );

    const identity = JSON.parse(decrypted.toString('utf8')) as VaultIdentity;
    return identity;
  }

  // Generate new vault identity
  const vaultId = `vault_${crypto.randomBytes(12).toString('hex')}`;

  // Generate HPKE X25519 keypair
  const { generateHpkeKeyPair } = await import('../crypto.js');
  const { publicKey, privateKey } = generateHpkeKeyPair();

  const identity: VaultIdentity = {
    vaultId,
    hpkePublicKey: publicKey.toString('base64'),
  };

  // Store identity (including private key for relay decryption)
  const identityData = {
    ...identity,
    hpkePrivateKey: privateKey.toString('base64'),
  };

  storage.createRecord({
    scope: 'system.vault_identity',
    item_type: 'CREDENTIALS',
    sensitivity: 'critical',
    data: identityData,
  });

  return identity;
}

// ============================================================================
// Local Callback Server
// ============================================================================

interface CallbackResult {
  authToken: Promise<string>;
  port: number;
}

async function startCallbackServer(): Promise<CallbackResult> {
  return new Promise((resolve, reject) => {
    let tokenResolve: (token: string) => void;
    let tokenReject: (err: Error) => void;

    const authToken = new Promise<string>((res, rej) => {
      tokenResolve = res;
      tokenReject = rej;
    });

    const server = http.createServer((req, res) => {
      if (req.url?.startsWith('/callback')) {
        const url = new URL(req.url, 'http://localhost');
        const token = url.searchParams.get('token');

        if (token) {
          // Send success response
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>DCP Connected</title>
              <style>
                body {
                  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                  display: flex;
                  justify-content: center;
                  align-items: center;
                  height: 100vh;
                  margin: 0;
                  background: #0a0a0a;
                  color: #fff;
                }
                .container {
                  text-align: center;
                  padding: 40px;
                }
                h1 { color: #10b981; }
                p { color: #888; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>Connected!</h1>
                <p>You can close this window and return to your terminal.</p>
              </div>
            </body>
            </html>
          `);

          // Resolve token
          tokenResolve(token);

          // Close server after short delay
          setTimeout(() => server.close(), 500);
        } else {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Missing token');
        }
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    // Listen on random port
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve({ authToken, port: addr.port });
      } else {
        reject(new Error('Failed to start callback server'));
      }
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      tokenReject(new Error('Authentication timed out'));
      server.close();
    }, 5 * 60 * 1000);

    server.on('error', (err) => {
      tokenReject(err);
    });
  });
}

// ============================================================================
// Send Connection Info
// ============================================================================

async function sendConnectionInfo(
  connectUrl: string,
  authToken: string,
  connectionInfo: ServiceConnectionInfo
): Promise<void> {
  const response = await fetch(connectUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(connectionInfo),
  });

  if (!response.ok) {
    const text = await response.text();
    let errorMsg = `Service returned ${response.status}`;
    try {
      const json = JSON.parse(text);
      if (json.error) errorMsg = json.error;
    } catch {
      if (text) errorMsg = text;
    }
    throw new Error(errorMsg);
  }

  const result = await response.json() as { ok: boolean; service_name?: string };
  if (!result.ok) {
    throw new Error('Service rejected connection');
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function guessAuthUrl(connectUrl: string): string {
  // Convert /api/dcp/connect to /auth/dcp
  try {
    const url = new URL(connectUrl);
    url.pathname = '/auth/dcp';
    return url.toString();
  } catch {
    return connectUrl.replace(/\/api\/dcp\/connect$/, '/auth/dcp');
  }
}

function buildAuthUrl(authUrl: string, callbackUrl: string): string {
  const url = new URL(authUrl);
  url.searchParams.set('callback', callbackUrl);
  url.searchParams.set('source', 'dcp-vault-cli');
  return url.toString();
}

async function openBrowser(url: string): Promise<void> {
  const { exec } = await import('child_process');
  const platform = process.platform;

  let command: string;
  if (platform === 'darwin') {
    command = `open "${url}"`;
  } else if (platform === 'win32') {
    command = `start "" "${url}"`;
  } else {
    command = `xdg-open "${url}"`;
  }

  return new Promise((resolve, reject) => {
    exec(command, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}
