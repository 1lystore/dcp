#!/usr/bin/env node
/**
 * Publish Guard Script
 *
 * This script enforces package publishing rules for DCP Phase 1.
 * It fails if any parked packages are configured for public publishing.
 *
 * Parked packages (must be private or not publishable):
 * - @dcprotocol/gateway
 * - @dcprotocol/mcp
 * - @dcprotocol/proxy
 * - @dcprotocol/server (wrapper only)
 * - @dcprotocol/cli (wrapper only)
 *
 * Publishable packages in Phase 1:
 * - @dcprotocol/core
 * - @dcprotocol/client
 * - @dcprotocol/vault (when created)
 * - @dcprotocol/agent
 * - @dcprotocol/relay
 * - @dcprotocol/relay-client
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'fs';
import { join, dirname, relative, extname, basename } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');
const packagesDir = join(rootDir, 'packages');

// ============================================================================
// Premium-leak guard
// ============================================================================
// This OSS repo must NEVER contain or reference private/premium code. The
// dependency direction is one-way (private -> OSS). If any of these markers
// appear in the tree, a backwards leak has happened and we must NOT publish.
// See docs/open-core-architecture.md.
const PREMIUM_MARKERS = [
  { re: /dcp-premium-cloud/i, label: 'premium cloud host (dcp-premium-cloud)' },
  { re: /\bDCP_PREMIUM[A-Z0-9_]*/, label: 'premium env var (DCP_PREMIUM_*)' },
  { re: /\.dcp\/premium\b/, label: 'premium home path (~/.dcp/premium)' },
  { re: /\bdcp_premium\b/, label: 'private repo reference (dcp_premium)' },
  { re: /MOBILE_CONSENT_RELAY_URL/, label: 'premium mobile-consent relay constant' },
  { re: /startMobileConsentBridge/, label: 'premium mobile-consent bridge symbol' },
  { re: /PremiumDesktopDeviceState/, label: 'premium desktop device-state symbol' },
  { re: /dcp-mobile-consent-bridge/, label: 'premium consent-bridge artifact' },
  { re: /dcp-premium-bridge/, label: 'premium desktop bridge artifact' },
];

// Only scan source-ish text files.
const SCAN_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.cjs',
  '.mjs',
  '.json',
  '.toml',
  '.yml',
  '.yaml',
  '.sh',
  '.md',
  '.rs',
]);

// The push surface = files git actually tracks. Scanning this set (not the working
// tree) ignores gitignored local config/build output and precisely matches what
// would be pushed/published. Falls back to an empty list outside a git checkout.
function listTrackedFiles() {
  try {
    const out = execSync('git ls-files -z', {
      cwd: rootDir,
      encoding: 'utf-8',
      maxBuffer: 64 * 1024 * 1024,
    });
    return out.split('\0').filter(Boolean);
  } catch {
    return [];
  }
}

function scanForPremiumMarkers(hits) {
  for (const rel of listTrackedFiles()) {
    const full = join(rootDir, rel);
    // Never scan the guard itself (it defines the markers) or built bundles.
    if (full === __filename) continue;
    if (basename(full).endsWith('-bundle.cjs')) continue;
    if (!SCAN_EXTENSIONS.has(extname(rel))) continue;
    let content;
    try {
      if (statSync(full).size > 2 * 1024 * 1024) continue; // skip huge files
      content = readFileSync(full, 'utf-8');
    } catch {
      continue;
    }
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const marker of PREMIUM_MARKERS) {
        if (marker.re.test(lines[i])) {
          hits.push({
            file: rel,
            line: i + 1,
            label: marker.label,
            text: lines[i].trim().slice(0, 120),
          });
        }
      }
    }
  }
}

// Packages that must NOT be published in Phase 1
const PARKED_PACKAGES = [
  '@dcprotocol/gateway',
  '@dcprotocol/mcp',
  '@dcprotocol/proxy',
  '@dcprotocol/server',
  '@dcprotocol/cli',
];

// Packages that CAN be published in Phase 1
const PUBLISHABLE_PACKAGES = [
  '@dcprotocol/core',
  '@dcprotocol/client',
  '@dcprotocol/vault',
  '@dcprotocol/agent',
  '@dcprotocol/relay',
  '@dcprotocol/relay-client',
];

// Deployable infrastructure (not npm, deploy via Docker/fly.io)
const DEPLOYABLE_PACKAGES = ['@dcprotocol/telegram'];

// Always private packages (includes deployable infrastructure)
const PRIVATE_PACKAGES = ['@dcprotocol/desktop', '@dcprotocol/telegram'];

function readPackageJson(dir) {
  const pkgPath = join(dir, 'package.json');
  if (!existsSync(pkgPath)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(pkgPath, 'utf-8'));
  } catch {
    return null;
  }
}

function isPublicPackage(pkg) {
  if (pkg.private === true) {
    return false;
  }
  if (pkg.publishConfig?.access === 'public') {
    return true;
  }
  // Scoped packages are private by default unless explicitly public
  if (pkg.name?.startsWith('@')) {
    return pkg.publishConfig?.access === 'public';
  }
  // Non-scoped packages are public by default
  return true;
}

function getDependencyEntries(pkg) {
  return [
    ...Object.entries(pkg.dependencies ?? {}),
    ...Object.entries(pkg.optionalDependencies ?? {}),
    ...Object.entries(pkg.peerDependencies ?? {}),
  ];
}

function main() {
  console.log('DCP Publish Guard - Phase 1\n');
  console.log('Checking package configurations...\n');

  const errors = [];

  // Premium-leak scan: fail hard if any private/premium marker is in tracked files.
  const premiumHits = [];
  scanForPremiumMarkers(premiumHits);
  for (const hit of premiumHits) {
    errors.push(`PREMIUM LEAK: ${hit.file}:${hit.line} — ${hit.label}\n        > ${hit.text}`);
  }
  const warnings = [];
  const publishable = [];
  const parked = [];
  const privatePackages = [];
  const packageNames = new Map();

  const packageDirs = readdirSync(packagesDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);

  for (const dir of packageDirs) {
    const fullPath = join(packagesDir, dir);
    const pkg = readPackageJson(fullPath);

    if (!pkg) {
      warnings.push(`${dir}: No package.json found`);
      continue;
    }

    const name = pkg.name || dir;
    packageNames.set(name, { dir, pkg });
  }

  for (const dir of packageDirs) {
    const fullPath = join(packagesDir, dir);
    const pkg = readPackageJson(fullPath);

    if (!pkg) {
      continue;
    }

    const name = pkg.name || dir;
    const isPublic = isPublicPackage(pkg);

    // Check if this is a parked package that shouldn't be public
    if (PARKED_PACKAGES.includes(name)) {
      if (isPublic) {
        errors.push(
          `${name}: PARKED package is configured as PUBLIC. ` +
            `Set "private": true or remove publishConfig.access`
        );
      } else {
        parked.push(name);
      }
    }
    // Check if this is meant to be private
    else if (PRIVATE_PACKAGES.includes(name)) {
      if (isPublic) {
        errors.push(
          `${name}: PRIVATE package is configured as PUBLIC. ` + `Set "private": true`
        );
      } else {
        privatePackages.push(name);
      }
    }
    // Check publishable packages
    else if (PUBLISHABLE_PACKAGES.includes(name)) {
      if (isPublic) {
        publishable.push(name);
      } else {
        warnings.push(`${name}: Publishable package is marked private`);
        parked.push(name);
      }
    }
    // Unknown package
    else {
      warnings.push(`${name}: Unknown package - not in any category`);
      if (isPublic) {
        warnings.push(`  -> Currently configured as PUBLIC`);
      }
    }

    if (isPublic) {
      for (const [depName, specifier] of getDependencyEntries(pkg)) {
        if (typeof specifier !== 'string') {
          continue;
        }

        if (specifier.startsWith('file:') || specifier.startsWith('link:')) {
          errors.push(`${name}: ${depName} uses local dependency "${specifier}"`);
        }

        if (specifier.startsWith('workspace:')) {
          const dep = packageNames.get(depName);
          if (!dep) {
            errors.push(`${name}: ${depName} uses workspace dependency but no package exists`);
          } else if (!PUBLISHABLE_PACKAGES.includes(depName)) {
            errors.push(
              `${name}: ${depName} uses workspace dependency but is not publishable`
            );
          }
        }
      }
    }
  }

  // Print results
  console.log('=== PUBLISHABLE (Phase 1) ===');
  if (publishable.length === 0) {
    console.log('  (none)');
  } else {
    publishable.forEach((p) => console.log(`  + ${p}`));
  }

  console.log('\n=== PARKED (not publishable) ===');
  if (parked.length === 0) {
    console.log('  (none)');
  } else {
    parked.forEach((p) => console.log(`  - ${p}`));
  }

  console.log('\n=== PRIVATE (never publish) ===');
  if (privatePackages.length === 0) {
    console.log('  (none)');
  } else {
    privatePackages.forEach((p) => console.log(`  x ${p}`));
  }

  if (warnings.length > 0) {
    console.log('\n=== WARNINGS ===');
    warnings.forEach((w) => console.log(`  ! ${w}`));
  }

  if (errors.length > 0) {
    console.log('\n=== ERRORS ===');
    errors.forEach((e) => console.log(`  X ${e}`));
    console.log(
      '\nPublish guard FAILED. Fix the above errors before publishing.'
    );
    process.exit(1);
  }

  console.log('\nPublish guard PASSED.');
  process.exit(0);
}

main();
