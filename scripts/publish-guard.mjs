#!/usr/bin/env node
/**
 * Publish Guard Script
 *
 * This script enforces package publishing rules for DCP Phase 1.
 * It fails if any parked packages are configured for public publishing.
 *
 * Parked packages (must be private or not publishable):
 * - @dcprotocol/gateway
 * - @dcprotocol/client
 * - @dcprotocol/mcp
 * - @dcprotocol/proxy
 * - @dcprotocol/server (wrapper only)
 * - @dcprotocol/cli (wrapper only)
 * - @dcprotocol/relay-client (internal only)
 *
 * Publishable packages in Phase 1:
 * - @dcprotocol/core
 * - @dcprotocol/vault (when created)
 * - @dcprotocol/agent
 * - @dcprotocol/relay
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const packagesDir = join(rootDir, 'packages');

// Packages that must NOT be published in Phase 1
const PARKED_PACKAGES = [
  '@dcprotocol/gateway',
  '@dcprotocol/client',
  '@dcprotocol/mcp',
  '@dcprotocol/proxy',
  '@dcprotocol/server',
  '@dcprotocol/cli',
  '@dcprotocol/relay-client',
];

// Packages that CAN be published in Phase 1
const PUBLISHABLE_PACKAGES = [
  '@dcprotocol/core',
  '@dcprotocol/vault',
  '@dcprotocol/agent',
  '@dcprotocol/relay',
  '@dcprotocol/telegram',
];

// Always private packages
const PRIVATE_PACKAGES = ['@dcprotocol/desktop'];

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

function main() {
  console.log('DCP Publish Guard - Phase 1\n');
  console.log('Checking package configurations...\n');

  const errors = [];
  const warnings = [];
  const publishable = [];
  const parked = [];
  const privatePackages = [];

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
