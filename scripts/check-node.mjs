const major = Number(process.versions.node.split('.')[0]);
const allowed = new Set([18, 20, 22]);

if (!allowed.has(major)) {
  console.error(`\n[DCP] Unsupported Node.js version: ${process.versions.node}`);
  console.error('[DCP] Please use Node.js 18, 20, or 22 (LTS).');
  console.error('[DCP] Recommended: Node 22 LTS.');
  console.error('\nIf you use nvm:');
  console.error('  nvm install 22');
  console.error('  nvm use 22');
  process.exit(1);
}
