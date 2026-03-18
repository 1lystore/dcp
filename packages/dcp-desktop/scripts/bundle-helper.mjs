#!/usr/bin/env node
/**
 * Bundle the DCP desktop helper and server with all JS dependencies.
 * Native addons are kept external and copied separately so their .node
 * binaries continue to work inside the packaged app.
 */

import { build } from 'esbuild';
import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, cpSync, rmSync } from 'fs';
import { dirname, join, relative } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '..', 'src-tauri', 'resources');
const helperOutFile = join(outDir, 'dcp-helper-bundle.cjs');
const serverOutFile = join(outDir, 'dcp-server-bundle.cjs');
const nodeModulesOut = join(outDir, 'node_modules');
const serverRuntimeDir = join(outDir, 'dcp-server-runtime');
const serverRuntimeAppDir = join(serverRuntimeDir, 'app');
const serverRuntimeNodeModulesDir = join(serverRuntimeDir, 'node_modules');
const monorepoRoot = join(__dirname, '..', '..', '..');
const monorepoNodeModules = join(monorepoRoot, 'node_modules');
const serverEntry = join(monorepoRoot, 'packages', 'dcp-server', 'dist', 'index.js');
const serverPackageDir = join(monorepoRoot, 'packages', 'dcp-server');

// Native modules that can't be bundled - need their .node binaries
const NATIVE_MODULES = [
  'better-sqlite3',
  'sodium-native',
  'keytar',
  // Transitive native deps
  'node-gyp-build',
];

// Native modules that must stay external.
const EXTERNAL_MODULES = [
  ...NATIVE_MODULES,
  'bindings',
  'file-uri-to-path',
];

// The helper source code
const helperSource = `
const {
  VaultStorage,
  generateRecoveryMnemonic,
  deriveKeyFromMnemonic,
  zeroize,
  createWallet,
  isChainSupported,
} = require('@dcprotocol/core');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function reply(obj) {
  process.stdout.write(JSON.stringify(obj));
}

function fail(message) {
  reply({ ok: false, error: message });
  process.exit(1);
}

async function main() {
  const raw = await readStdin();
  if (!raw) fail('No input provided');

  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    fail('Invalid JSON input');
  }

  const action = input.action;
  const passphrase = input.passphrase || '';
  const chains = Array.isArray(input.chains) ? input.chains : [];
  const vaultDir = input.vault_dir || process.env.VAULT_DIR;

  if (!action) fail('Missing action');

  if (action === 'init') {
    if (passphrase.length < 8) fail('Passphrase must be at least 8 characters');
    const storage = new VaultStorage(vaultDir);
    if (storage.isInitialized()) fail('Vault already initialized');

    const recoveryPhrase = generateRecoveryMnemonic();
    const masterKey = deriveKeyFromMnemonic(recoveryPhrase);
    try {
      storage.initializeSchema();
      await storage.storeMasterKeyWithPassphrase(masterKey, passphrase);
    } catch (err) {
      fail(err?.message || 'Failed to initialize vault');
    } finally {
      zeroize(masterKey);
    }

    reply({ ok: true, recovery_phrase: recoveryPhrase.split(' ') });
    process.exit(0);
  }

  if (action === 'create_wallets') {
    if (passphrase.length < 8) fail('Passphrase must be at least 8 characters');
    const storage = new VaultStorage(vaultDir);
    if (!storage.isInitialized()) fail('Vault not initialized');

    try {
      await storage.unlock(passphrase);
    } catch (err) {
      fail(err?.message || 'Failed to unlock vault');
    }

    const wallets = [];
    try {
      for (const chainRaw of chains) {
        const chain = String(chainRaw).toLowerCase();
        if (!isChainSupported(chain)) fail(\`Unsupported chain: \${chain}\`);
        const scope = \`crypto.wallet.\${chain}\`;
        const existing = storage.getRecord(scope);
        if (existing?.public_address) {
          wallets.push({ chain, address: existing.public_address });
          continue;
        }
        const masterKey = storage.getMasterKey();
        const { encrypted, info } = createWallet(chain, masterKey);
        storage.createRecord({
          scope,
          item_type: 'WALLET_KEY',
          sensitivity: 'critical',
          data: encrypted,
          chain,
          public_address: info.public_address,
        });
        wallets.push({ chain, address: info.public_address });
      }
    } catch (err) {
      fail(err?.message || 'Failed to create wallets');
    } finally {
      storage.lock();
    }

    reply({ ok: true, wallets });
    process.exit(0);
  }

  fail(\`Unknown action: \${action}\`);
}

main().catch(err => fail(err?.message || 'Unexpected error'));
`;

// Write temp source file
const tempSource = join(__dirname, '.helper-temp.js');
writeFileSync(tempSource, helperSource);

// Ensure output directory exists
if (!existsSync(outDir)) {
  mkdirSync(outDir, { recursive: true });
}

function listServerRuntimePaths() {
  let stdout = '';
  try {
    stdout = execFileSync(
      'npm',
      ['ls', '--omit=dev', '--all', '--parseable', '-w', '@dcprotocol/server'],
      { cwd: monorepoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    );
  } catch (err) {
    stdout = String(err.stdout || '');
  }

  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith(monorepoRoot) && line !== monorepoRoot);
}

function destinationForRuntimePath(srcPath) {
  if (srcPath === serverPackageDir) {
    return serverRuntimeAppDir;
  }

  if (srcPath.startsWith(`${monorepoNodeModules}/`)) {
    return join(serverRuntimeDir, relative(monorepoRoot, srcPath));
  }

  const packageJsonPath = join(srcPath, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return null;
  }

  const packageName = JSON.parse(readFileSync(packageJsonPath, 'utf8')).name;
  if (!packageName) {
    return null;
  }

  return join(serverRuntimeNodeModulesDir, ...packageName.split('/'));
}

function stageServerRuntime() {
  if (existsSync(serverRuntimeDir)) {
    rmSync(serverRuntimeDir, { recursive: true });
  }

  mkdirSync(serverRuntimeDir, { recursive: true });
  mkdirSync(serverRuntimeNodeModulesDir, { recursive: true });

  const copied = new Set();
  for (const srcPath of listServerRuntimePaths()) {
    const destPath = destinationForRuntimePath(srcPath);
    if (!destPath || copied.has(destPath)) {
      continue;
    }

    mkdirSync(dirname(destPath), { recursive: true });
    cpSync(srcPath, destPath, { recursive: true, dereference: true });
    copied.add(destPath);
  }

  console.log(`[bundle-helper] Server runtime staged in ${serverRuntimeDir}`);
}

console.log('[bundle-helper] Bundling DCP helper with @dcprotocol/core...');
console.log('[bundle-helper] Native modules will be copied separately:', NATIVE_MODULES.join(', '));

try {
  // Step 1: Bundle the helper, keeping native modules external
  await build({
    entryPoints: [tempSource],
    bundle: true,
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    outfile: helperOutFile,
    minify: false,
    external: EXTERNAL_MODULES,
    mainFields: ['module', 'main'],
    nodePaths: [monorepoNodeModules],
  });

  console.log(`[bundle-helper] Helper bundle created: ${helperOutFile}`);

  if (!existsSync(serverEntry)) {
    throw new Error(`Server bundle input not found: ${serverEntry}. Run npm -w @dcprotocol/server run build first.`);
  }

  await build({
    entryPoints: [serverEntry],
    bundle: true,
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    outfile: serverOutFile,
    minify: false,
    external: EXTERNAL_MODULES,
    mainFields: ['module', 'main'],
    nodePaths: [monorepoNodeModules],
  });

  console.log(`[bundle-helper] Server bundle created: ${serverOutFile}`);

  // Step 2: Copy native modules to resources/node_modules
  if (existsSync(nodeModulesOut)) {
    rmSync(nodeModulesOut, { recursive: true });
  }
  mkdirSync(nodeModulesOut, { recursive: true });

  for (const mod of NATIVE_MODULES) {
    const srcPath = join(monorepoNodeModules, mod);
    const destPath = join(nodeModulesOut, mod);

    if (existsSync(srcPath)) {
      console.log(`[bundle-helper] Copying native module: ${mod}`);
      cpSync(srcPath, destPath, { recursive: true });
    } else {
      console.warn(`[bundle-helper] WARNING: Native module not found: ${mod}`);
    }
  }

  // Step 3: Also copy bindings (for better-sqlite3)
  const bindingsPath = join(monorepoNodeModules, 'bindings');
  if (existsSync(bindingsPath)) {
    console.log('[bundle-helper] Copying bindings module');
    cpSync(bindingsPath, join(nodeModulesOut, 'bindings'), { recursive: true });
  }

  // Step 4: Copy file-uri-to-path (dependency of bindings)
  const fileUriPath = join(monorepoNodeModules, 'file-uri-to-path');
  if (existsSync(fileUriPath)) {
    console.log('[bundle-helper] Copying file-uri-to-path module');
    cpSync(fileUriPath, join(nodeModulesOut, 'file-uri-to-path'), { recursive: true });
  }

  // Step 5: Stage an exact runtime copy of the server dependency tree.
  stageServerRuntime();

  console.log(`[bundle-helper] SUCCESS: Bundle and native modules ready in ${outDir}`);

  // Clean up temp file
  const { unlinkSync } = await import('fs');
  unlinkSync(tempSource);
} catch (err) {
  console.error('[bundle-helper] FAILED:', err.message);
  process.exit(1);
}
