#!/usr/bin/env node
/**
 * Bundle the DCP desktop helper and server with all JS dependencies.
 * Native addons are kept external and copied separately so their .node
 * binaries continue to work inside the packaged app.
 */

import { build } from 'esbuild';
import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, cpSync, rmSync, readdirSync } from 'fs';
import { dirname, join, relative } from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const outDir = join(__dirname, '..', 'src-tauri', 'resources');
const helperOutFile = join(outDir, 'dcp-helper-bundle.cjs');
const serverOutFile = join(outDir, 'dcp-vault-bundle.cjs');
const nodeModulesOut = join(outDir, 'node_modules');
const serverRuntimeDir = join(outDir, 'dcp-vault-runtime');
const serverRuntimeAppDir = join(serverRuntimeDir, 'app');
const serverRuntimeNodeModulesDir = join(serverRuntimeDir, 'node_modules');
const monorepoRoot = join(__dirname, '..', '..', '..');
const monorepoNodeModules = join(monorepoRoot, 'node_modules');
const serverEntry = join(monorepoRoot, 'packages', 'dcp-vault', 'dist', 'index.js');
const serverPackageDir = join(monorepoRoot, 'packages', 'dcp-vault');
const workspacePackages = {
  '@dcprotocol/core': join(monorepoRoot, 'packages', 'dcp-core', 'dist', 'index.js'),
  '@dcprotocol/client': join(monorepoRoot, 'packages', 'dcp-client', 'dist', 'index.js'),
  '@dcprotocol/relay': join(monorepoRoot, 'packages', 'dcp-relay', 'dist', 'index.js'),
  '@dcprotocol/relay-client': join(monorepoRoot, 'packages', 'dcp-relay-client', 'dist', 'index.js'),
};

const workspacePackagePlugin = {
  name: 'dcp-workspace-packages',
  setup(build) {
    build.onResolve({ filter: /^@dcprotocol\/(core|client|relay|relay-client)$/ }, (args) => ({
      path: workspacePackages[args.path],
    }));
  },
};

// Native modules that can't be bundled - need their .node binaries
const NATIVE_MODULES = [
  'better-sqlite3',
  'sodium-native',
  'keytar',
  // Transitive native deps
  'node-gyp-build',
  'require-addon', // Required by sodium-native to load .node binaries
];

// Native modules that must stay external.
const EXTERNAL_MODULES = [
  ...NATIVE_MODULES,
  'bindings',
  'file-uri-to-path',
  // @hpke packages have UMD builds that require at runtime
  '@hpke/common',
  '@hpke/core',
  '@hpke/chacha20poly1305',
  '@hpke/dhkem-x25519',
  // Pino logger transport
  'pino-pretty',
];

// Root runtime modules for the helper bundle. Their full dependency closure
// must be copied into resources/node_modules because the packaged app no longer
// resolves against the monorepo's node_modules.
const HELPER_RUNTIME_ROOTS = [...EXTERNAL_MODULES];

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
    if (await storage.isProvisioned()) fail('Vault already initialized');

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
    if (!(await storage.isProvisioned())) fail('Vault not initialized');

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
      ['ls', '--omit=dev', '--all', '--parseable', '-w', '@dcprotocol/vault'],
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

function resolvePackageDir(name) {
  let entry;
  try {
    entry = require.resolve(name, {
      paths: [
        monorepoRoot,
        monorepoNodeModules,
        serverPackageDir,
        join(monorepoRoot, 'packages', 'dcp-core'),
        join(monorepoRoot, 'packages', 'dcp-client'),
        join(monorepoRoot, 'packages', 'dcp-relay'),
        join(monorepoRoot, 'packages', 'dcp-relay-client'),
      ],
    });
  } catch {
    // Fallback: search in pnpm's .pnpm directory structure
    const pnpmDir = join(monorepoNodeModules, '.pnpm');
    if (existsSync(pnpmDir)) {
      try {
        const entries = readdirSync(pnpmDir);
        for (const entry of entries) {
          if (entry.startsWith(`${name}@`) || entry.startsWith(`${name.replace('/', '+')}@`)) {
            const candidatePath = join(pnpmDir, entry, 'node_modules', name);
            if (existsSync(candidatePath)) {
              return candidatePath;
            }
          }
        }
      } catch {
        // ignore
      }
    }
    return null;
  }
  let cursor = dirname(entry);

  while (cursor !== dirname(cursor)) {
    const packageJsonPath = join(cursor, 'package.json');
    if (existsSync(packageJsonPath)) {
      const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
      if (pkg.name === name) {
        return cursor;
      }
    }
    cursor = dirname(cursor);
  }

  return null;
}

function collectRuntimeDependencyClosure(rootModules) {
  const queue = [...rootModules];
  const seen = new Set();
  const ordered = [];

  while (queue.length > 0) {
    const name = queue.shift();
    if (!name || seen.has(name)) {
      continue;
    }

    const packageDir = resolvePackageDir(name);
    if (!packageDir) {
      console.warn(`[bundle-helper] WARNING: Runtime dependency not found: ${name}`);
      continue;
    }

    seen.add(name);
    ordered.push({ name, packageDir });

    const packageJson = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));
    const runtimeDeps = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.optionalDependencies || {}),
    };

    for (const depName of Object.keys(runtimeDeps)) {
      if (!seen.has(depName)) {
        queue.push(depName);
      }
    }
  }

  return ordered;
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
    plugins: [workspacePackagePlugin],
  });

  console.log(`[bundle-helper] Helper bundle created: ${helperOutFile}`);

  if (!existsSync(serverEntry)) {
    throw new Error(`Server bundle input not found: ${serverEntry}. Run npm -w @dcprotocol/vault run build first.`);
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
    plugins: [workspacePackagePlugin],
  });

  console.log(`[bundle-helper] Server bundle created: ${serverOutFile}`);

  // Step 2: Copy the full helper runtime dependency tree to resources/node_modules.
  // The onboarding helper uses native modules (sodium-native, better-sqlite3,
  // keytar) plus their transitive JS dependencies. Missing any of those causes
  // packaged desktop startup/create-vault flows to fail at runtime.
  if (existsSync(nodeModulesOut)) {
    rmSync(nodeModulesOut, { recursive: true });
  }
  mkdirSync(nodeModulesOut, { recursive: true });

  for (const { name, packageDir } of collectRuntimeDependencyClosure(HELPER_RUNTIME_ROOTS)) {
    const destPath = join(nodeModulesOut, ...name.split('/'));
    console.log(`[bundle-helper] Copying helper runtime module: ${name}`);
    mkdirSync(dirname(destPath), { recursive: true });
    cpSync(packageDir, destPath, { recursive: true, dereference: true });
  }

  // Step 3: Stage an exact runtime copy of the server dependency tree.
  stageServerRuntime();

  console.log(`[bundle-helper] SUCCESS: Bundle and native modules ready in ${outDir}`);

  // Clean up temp file
  const { unlinkSync } = await import('fs');
  unlinkSync(tempSource);
} catch (err) {
  console.error('[bundle-helper] FAILED:', err.message);
  process.exit(1);
}
