import { readFileSync } from 'node:fs';

const requiredVersion = readFileSync(new URL('../.nvmrc', import.meta.url), 'utf8').trim();
const version = process.versions.node;

if (version !== requiredVersion) {
  console.error(`DCP development requires Node ${requiredVersion}.`);
  console.error(`Current Node: ${version}`);
  console.error('Run: nvm use');
  console.error('Then rebuild native modules: pnpm rebuild better-sqlite3 keytar sodium-native');
  process.exit(1);
}
