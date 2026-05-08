import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import https from 'node:https';
import { pipeline } from 'node:stream/promises';
import { spawnSync } from 'node:child_process';

const VERSION = process.env.DCP_NODE_VERSION || '22.22.2';
const platform = process.platform;
const arch = process.arch;

const isWin = platform === 'win32';
const ext = isWin ? 'zip' : 'tar.gz';

function mapPlatform(p) {
  if (p === 'darwin') return 'darwin';
  if (p === 'linux') return 'linux';
  if (p === 'win32') return 'win';
  throw new Error(`Unsupported platform: ${p}`);
}

function mapArch(a) {
  if (a === 'arm64') return 'arm64';
  if (a === 'x64') return 'x64';
  throw new Error(`Unsupported architecture: ${a}`);
}

const plat = mapPlatform(platform);
const archId = mapArch(arch);
const filename = `node-v${VERSION}-${plat}-${archId}.${ext}`;
const url = `https://nodejs.org/dist/v${VERSION}/${filename}`;

const root = path.resolve(process.cwd());
const binDir = path.join(root, 'src-tauri', 'bin');
const outPath = path.join(binDir, isWin ? 'node.exe' : 'node');

if (fs.existsSync(outPath)) {
  const existing = spawnSync(outPath, ['-v'], { encoding: 'utf8' });
  const existingVersion = existing.stdout.trim().replace(/^v/, '');
  if (existing.status === 0 && existingVersion === VERSION) {
    console.log(`[bundle:node] Node ${VERSION} already present at ${outPath}`);
    process.exit(0);
  }
  console.log(`[bundle:node] Replacing Node ${existingVersion || 'unknown'} with ${VERSION}`);
}

fs.mkdirSync(binDir, { recursive: true });

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcp-node-'));
const archivePath = path.join(tmpDir, filename);

console.log(`[bundle:node] Downloading ${url}`);
await new Promise((resolve, reject) => {
  https.get(url, (res) => {
    if (res.statusCode !== 200) {
      reject(new Error(`Download failed: ${res.statusCode}`));
      return;
    }
    const file = fs.createWriteStream(archivePath);
    pipeline(res, file).then(resolve, reject);
  }).on('error', reject);
});

console.log('[bundle:node] Extracting...');
if (ext === 'tar.gz') {
  const tar = spawnSync('tar', ['-xzf', archivePath, '-C', tmpDir]);
  if (tar.status !== 0) {
    throw new Error(`tar failed: ${tar.stderr?.toString() || 'unknown error'}`);
  }
} else {
  // Use PowerShell's Expand-Archive on Windows (no unzip available by default)
  const ps = spawnSync('powershell', [
    '-NoProfile',
    '-Command',
    `Expand-Archive -Path '${archivePath}' -DestinationPath '${tmpDir}' -Force`
  ]);
  if (ps.status !== 0) {
    throw new Error(`PowerShell Expand-Archive failed: ${ps.stderr?.toString() || 'unknown error'}`);
  }
}

const extractedDir = path.join(tmpDir, `node-v${VERSION}-${plat}-${archId}`);
// Windows puts node.exe in root, Unix puts it in bin/
const nodePath = isWin
  ? path.join(extractedDir, 'node.exe')
  : path.join(extractedDir, 'bin', 'node');

if (!fs.existsSync(nodePath)) {
  throw new Error(`Node binary not found after extraction: ${nodePath}`);
}

fs.copyFileSync(nodePath, outPath);
if (!isWin) {
  fs.chmodSync(outPath, 0o755);
}

console.log(`[bundle:node] Node bundled at ${outPath}`);
