#!/usr/bin/env node
/**
 * DCP Vault REST Server
 *
 * REST API for AI agents and browser UIs to interact with the vault.
 * SECURITY: Binds to 127.0.0.1 only - never exposed to network (PRD R1).
 *
 * Endpoints (PRD R2):
 * - GET  /health               - Health check
 * - GET  /scopes               - List available scopes
 * - GET  /address/:chain       - Get wallet address
 * - GET  /budget/check         - Check budget
 * - GET  /agents               - List active sessions
 * - GET  /consent              - List pending consents
 * - POST /consent/:id/approve  - Approve consent
 * - POST /consent/:id/deny     - Deny consent
 * - POST /revoke/:agent        - Revoke agent sessions
 *
 * v1 API Endpoints:
 * - POST /v1/vault/read        - Read data (with consent flow)
 * - POST /v1/vault/write       - Write data (with consent flow)
 * - POST /v1/vault/sign        - Sign transaction (with consent + budget)
 * - POST /v1/vault/sign-message - Sign message (with consent)
 * - POST /v1/vault/sign_message - Sign message (alias)
 * - POST /v1/vault/sign_typed_data - Sign typed data (EIP-712)
 * - POST /v1/vault/sign_x402   - Sign x402 payment (with consent)
 * - GET  /v1/vault/activity    - Get audit events
 * - POST /v1/vault/unlock      - Unlock vault (local only)
 * - POST /v1/vault/lock        - Lock vault (local only)
 * - POST /v1/vault/agents/:id/revoke - Revoke specific session
 */

import Fastify, { FastifyInstance, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import {
  VaultStorage,
  BudgetEngine,
  getStorage,
  getBudgetEngine,
  VaultError,
  Chain,
  ItemType,
  SensitivityLevel,
  AuditEventType,
  envelopeDecrypt,
  signTransaction,
  signSolanaMessage,
  signEvmMessage,
  signEvmTypedData,
  type TrustedService,
  isValidPublicKey,
  listKnownServices,
} from '@dcprotocol/core';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import keytar from 'keytar';
import nacl from 'tweetnacl';
import {
  RelayClient,
  generateKeyPair,
  generateSigningKeyPair,
  type HpkeKeyPair,
  type SigningKeyPair,
} from '@dcprotocol/relay-client';

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_PORT = 8420;
const HOST = '127.0.0.1'; // SECURITY: localhost only
const MCP_UNLOCK_KEYCHAIN_SERVICE = 'dcp-mcp-unlock';
const MCP_UNLOCK_KEYCHAIN_ACCOUNT = 'passphrase';
const MCP_UNLOCK_META_ACCOUNT = 'meta';
const MCP_UNLOCK_SESSION_MINUTES = parseInt(
  process.env.DCP_MCP_SESSION_MINUTES || '30',
  10
);
const PACKAGE_VERSION = getPackageVersion();

// Desktop Owner Trust Model Constants
const OWNER_TOKEN_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const OWNER_TOKEN_MAX_AGE_MS = 4 * 60 * 60 * 1000; // 4 hours
const CHALLENGE_TIMEOUT_MS = 60 * 1000; // 60 seconds
const DEFAULT_RELAY_URL = process.env.DCP_RELAY_URL || '';

// In-memory storage for owner sessions and challenges
interface OwnerToken {
  token: string;
  desktop_id: string;
  created_at: number;
  last_used_at: number;
}

interface Challenge {
  nonce: string;
  desktop_id: string;
  expires_at: number;
}

const ownerTokens: Map<string, OwnerToken> = new Map(); // token -> OwnerToken
const pendingChallenges: Map<string, Challenge> = new Map(); // desktop_id -> Challenge

function getPackageVersion(): string {
  try {
    const entryPath = process.argv[1] ? path.dirname(process.argv[1]) : process.cwd();
    const candidates = [
      path.join(entryPath, '..', 'package.json'),
      path.join(process.cwd(), 'packages', 'dcp-server', 'package.json'),
      path.join(process.cwd(), 'package.json'),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        const raw = fs.readFileSync(p, 'utf8');
        const json = JSON.parse(raw) as { version?: string };
        if (json.version) return json.version;
      }
    }
    return '0.0.0';
  } catch {
    return '0.0.0';
  }
}

// ============================================================================
// Server Setup
// ============================================================================

let storage: VaultStorage;
let budget: BudgetEngine;
let relayClient: RelayClient | null = null;
let relayConnected = false;

function findActiveSessionForScope(agentName: string, scope: string): string | undefined {
  const sessions = storage.listActiveSessionsForAgent(agentName);
  for (const session of sessions) {
    if (session.granted_scopes.includes(scope)) {
      return session.id;
    }
    for (const granted of session.granted_scopes) {
      if (granted.endsWith('.*')) {
        const prefix = granted.slice(0, -2);
        if (scope.startsWith(prefix + '.')) {
          return session.id;
        }
      }
    }
  }
  return undefined;
}

function scopeMatches(pattern: string, scope: string): boolean {
  if (pattern === scope) return true;
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2);
    return scope.startsWith(prefix + '.');
  }
  return false;
}

function isWriteAllowed(agentName: string, scope: string): boolean {
  const config = budget.getConfig();
  const permissions = config.write_permissions || {};
  const allowed = permissions[agentName];
  if (!allowed || allowed.length === 0) {
    return false;
  }
  return allowed.some((pattern) => scopeMatches(pattern, scope));
}

function inferItemType(scope: string): ItemType {
  if (scope.startsWith('identity.')) return 'IDENTITY';
  if (scope.startsWith('address.')) return 'ADDRESS';
  if (scope.startsWith('preferences.')) return 'PREFERENCES';
  if (scope.startsWith('crypto.')) return 'WALLET_KEY';
  if (scope.startsWith('credentials.')) return 'CREDENTIALS';
  if (scope.startsWith('health.')) return 'HEALTH';
  if (scope.startsWith('budget.')) return 'BUDGET';
  return 'PREFERENCES';
}

function inferSensitivity(scope: string): SensitivityLevel {
  if (
    scope.startsWith('identity.passport') ||
    scope.startsWith('identity.drivers_license') ||
    scope.startsWith('crypto.')
  ) {
    return 'critical';
  }
  if (scope.startsWith('credentials.')) {
    return 'sensitive';
  }
  if (scope.startsWith('identity.') || scope.startsWith('address.') || scope.startsWith('health.')) {
    return 'sensitive';
  }
  return 'standard';
}

function ensureSchemaVersion(data: Record<string, unknown>): Record<string, unknown> {
  if ('schema_version' in data) {
    return data;
  }
  return { ...data, schema_version: '1.0' };
}

function normalizeWriteData(scope: string, data: Record<string, unknown>): Record<string, unknown> {
  const base = ensureSchemaVersion(data);
  if (scope.startsWith('credentials.api.')) {
    return validateAndNormalizeCredentialsApi(base);
  }
  return base;
}

function validateAndNormalizeCredentialsApi(data: Record<string, unknown>): Record<string, unknown> {
  const allowedKeys = [
    'schema_version',
    'label',
    'service',
    'key',
    'base_url',
    'auth_type',
    'headers',
  ];

  for (const key of Object.keys(data)) {
    if (!allowedKeys.includes(key)) {
      throw new VaultError('INVALID_SCHEMA', `Unexpected field in credentials.api: ${key}`);
    }
  }

  const normalized: Record<string, unknown> = {
    schema_version: String(data.schema_version || '1.0'),
    label: data.label ?? null,
    service: data.service ?? null,
    key: data.key ?? null,
    base_url: data.base_url ?? null,
    auth_type: data.auth_type ?? null,
    headers: data.headers ?? null,
  };

  if (typeof normalized.schema_version !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'schema_version must be a string');
  }
  if (normalized.label !== null && typeof normalized.label !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'label must be a string or null');
  }
  if (normalized.service !== null && typeof normalized.service !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'service must be a string or null');
  }
  if (normalized.key !== null && typeof normalized.key !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'key must be a string or null');
  }
  if (normalized.base_url !== null && typeof normalized.base_url !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'base_url must be a string or null');
  }
  if (normalized.auth_type !== null && typeof normalized.auth_type !== 'string') {
    throw new VaultError('INVALID_SCHEMA', 'auth_type must be a string or null');
  }
  if (
    normalized.headers !== null &&
    (typeof normalized.headers !== 'object' || Array.isArray(normalized.headers))
  ) {
    throw new VaultError('INVALID_SCHEMA', 'headers must be an object or null');
  }

  return normalized;
}

function normalizeAmount(amount?: string | number): number | undefined {
  if (amount === undefined || amount === null) return undefined;
  if (typeof amount === 'number') return amount;
  if (typeof amount === 'string' && amount.trim().length > 0) {
    const parsed = Number(amount);
    if (!Number.isFinite(parsed)) {
      throw new VaultError('INTERNAL_ERROR', 'Invalid amount');
    }
    return parsed;
  }
  return undefined;
}

// ============================================================================
// Desktop Owner Trust Model Helpers
// ============================================================================

/**
 * Verify Ed25519 signature
 */
function verifyEd25519Signature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return nacl.sign.detached.verify(message, signature, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate a random nonce for challenge-response
 */
function generateChallenge(): string {
  return crypto.randomBytes(32).toString('base64');
}

/**
 * Generate a secure owner token
 */
function generateOwnerToken(): string {
  return crypto.randomBytes(48).toString('base64url');
}

/**
 * Check if request has valid owner token
 * Returns true if the request should bypass consent (owner mode)
 */
function isOwnerRequest(request: FastifyRequest): boolean {
  const token = request.headers['x-dcp-owner-token'] as string | undefined;
  if (!token) return false;

  const ownerToken = ownerTokens.get(token);
  if (!ownerToken) return false;

  const now = Date.now();

  // Check if token is expired (max age)
  if (now - ownerToken.created_at > OWNER_TOKEN_MAX_AGE_MS) {
    ownerTokens.delete(token);
    return false;
  }

  // Check if token is idle expired
  if (now - ownerToken.last_used_at > OWNER_TOKEN_IDLE_TIMEOUT_MS) {
    ownerTokens.delete(token);
    return false;
  }

  // Update last used time
  ownerToken.last_used_at = now;
  return true;
}

/**
 * Clean up expired tokens and challenges
 */
function cleanupOwnerState(): void {
  const now = Date.now();

  // Clean up expired tokens
  for (const [token, data] of ownerTokens.entries()) {
    if (
      now - data.created_at > OWNER_TOKEN_MAX_AGE_MS ||
      now - data.last_used_at > OWNER_TOKEN_IDLE_TIMEOUT_MS
    ) {
      ownerTokens.delete(token);
    }
  }

  // Clean up expired challenges
  for (const [desktopId, challenge] of pendingChallenges.entries()) {
    if (now > challenge.expires_at) {
      pendingChallenges.delete(desktopId);
    }
  }
}

async function buildServer(): Promise<FastifyInstance> {
  const server = Fastify({
    logger: {
      level: 'info',
      transport: {
        target: 'pino-pretty',
        options: {
          translateTime: 'HH:MM:ss',
          ignore: 'pid,hostname',
        },
      },
    },
  });

  // CORS for desktop UI access (restrict to trusted origins)
  const allowedOrigins = new Set([
    'tauri://localhost',
    'https://tauri.localhost',
    'http://localhost:1420',
    'http://127.0.0.1:1420',
  ]);

  await server.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // non-browser clients
      if (allowedOrigins.has(origin)) return cb(null, true);
      try {
        const url = new URL(origin);
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
          return cb(null, true);
        }
      } catch {
        // fall through
      }
      return cb(new Error('Not allowed by CORS'), false);
    },
    methods: ['GET', 'POST', 'DELETE'],
  });

  // Initialize vault storage (respects VAULT_DIR env for testing)
  const vaultDir = process.env.VAULT_DIR;
  storage = getStorage(vaultDir);
  storage.initializeSchema();
  budget = getBudgetEngine(storage, vaultDir);

  // NOTE: Vault is locked by default. Use /v1/vault/unlock to open for this process.

  // Error handler
  server.setErrorHandler((error: Error, request, reply) => {
    if (error instanceof VaultError) {
      reply.status(400).send(error.toJSON());
    } else {
      server.log.error(error);
      reply.status(500).send({
        error: {
          code: 'INTERNAL_ERROR',
          message: error.message,
        },
      });
    }
  });

  // ============================================================================
  // Health Check
  // ============================================================================

  server.get('/health', async () => {
    const initialized = await storage.isProvisioned();
    return {
      status: 'ok',
      initialized,
      unlocked: storage.isUnlocked(),
      version: PACKAGE_VERSION,
    };
  });

  // ============================================================================
  // Local Approval UI
  // ============================================================================

  server.get('/', async (_request, reply) => {
    reply
      .header('Cache-Control', 'no-store')
      .type('text/html')
      .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DCP Vault Approval</title>
    <style>
      :root {
        --bg: #0b0f14;
        --bg-2: #0e131a;
        --panel: #111821;
        --panel-2: #0f1620;
        --text: #e6edf3;
        --muted: #9aa4b2;
        --accent: #8bd3ff;
        --danger: #ff6b6b;
        --ok: #2dd4bf;
        --border: #1f2a37;
      }
      [data-theme="light"] {
        --bg: #f5f7fb;
        --bg-2: #ffffff;
        --panel: #ffffff;
        --panel-2: #f3f5f8;
        --text: #0b0f14;
        --muted: #667085;
        --accent: #2563eb;
        --danger: #dc2626;
        --ok: #059669;
        --border: #e4e7ec;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        background: radial-gradient(1200px 600px at 10% -10%, #18202b, transparent),
          radial-gradient(1200px 600px at 90% -10%, #101720, transparent),
          var(--bg);
        color: var(--text);
      }
      [data-theme="light"] body {
        background: radial-gradient(1200px 600px at 10% -10%, #e9efff, transparent),
          radial-gradient(1200px 600px at 90% -10%, #eef2f7, transparent),
          var(--bg);
      }
      .wrap {
        max-width: 900px;
        margin: 40px auto;
        padding: 0 20px;
      }
      .card {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
      }
      [data-theme="light"] .card {
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
      }
      .row { display: flex; gap: 12px; align-items: center; }
      .row.space { justify-content: space-between; }
      .title { font-size: 20px; font-weight: 700; }
      .subtitle { font-size: 13px; color: var(--muted); }
      .muted { color: var(--muted); }
      .badge {
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 12px;
        border: 1px solid var(--border);
        color: var(--muted);
      }
      .btn {
        padding: 8px 12px;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--panel-2);
        color: var(--text);
        cursor: pointer;
      }
      .btn:hover { border-color: #2c3b4c; }
      [data-theme="light"] .btn:hover { border-color: #cbd5e1; }
      .btn.ok { border-color: #1f766e; color: #bbf7d0; }
      .btn.danger { border-color: #7f1d1d; color: #fecaca; }
      .input {
        width: 100%;
        padding: 8px 10px;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--panel-2);
        color: var(--text);
      }
      .input.compact { width: 220px; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      .consent {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 12px;
        background: var(--panel-2);
      }
      .actions { display: flex; gap: 8px; }
      .small { font-size: 12px; }
      .pill {
        display: inline-flex;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 11px;
        border: 1px solid var(--border);
        color: var(--muted);
      }
      .lock-screen {
        display: none;
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
      }
      .lock-screen.active { display: block; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <div class="row space">
          <div>
            <div class="title">DCP Vault Approval</div>
            <div class="subtitle">Local only — http://127.0.0.1:8420</div>
          </div>
          <div class="row" style="gap:8px;">
            <button class="btn" id="theme-btn">Toggle Theme</button>
            <div class="badge" id="status-badge">checking...</div>
          </div>
        </div>
        <div class="row space" style="margin-top: 8px;">
          <div class="pill" id="mcp-status">MCP: unknown</div>
          <div class="row" style="gap:8px;">
            <input id="passphrase-top" class="input compact" type="password" placeholder="Passphrase for MCP" />
            <button class="btn" id="unlock-mcp-btn-top">Unlock MCP</button>
            <div class="muted small" id="mcp-msg"></div>
          </div>
        </div>
      </div>

      <div class="card" id="unlock-card">
        <div class="row space">
          <div>
            <div class="title">Unlock Vault</div>
            <div class="subtitle">Required once per server process. Passphrase never leaves your machine.</div>
          </div>
        </div>
        <div class="row" style="margin-top: 12px;">
          <input id="passphrase" class="input" type="password" placeholder="Passphrase" />
          <button class="btn ok" id="unlock-btn">Unlock</button>
        </div>
        <div class="muted small" id="unlock-msg" style="margin-top: 8px;"></div>
      </div>

      <div class="lock-screen" id="lock-screen">
        <div class="row space">
          <div>
            <div class="title">Vault Locked</div>
            <div class="subtitle">Unlock to view or approve requests.</div>
          </div>
          <div class="badge">locked</div>
        </div>
      </div>

      <div class="card" id="requests-card">
        <div class="row space">
          <div>
            <div class="title">Pending Requests</div>
            <div class="subtitle">Approve or deny agent requests. Auto-refreshes every 5s.</div>
          </div>
          <button class="btn" id="refresh-btn">Refresh</button>
        </div>
        <div id="consents" style="margin-top: 12px;"></div>
        <div class="muted small" id="empty-msg" style="margin-top: 8px;"></div>
      </div>
    </div>

    <script>
      async function fetchJSON(url, options) {
        const res = await fetch(url, options);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw data;
        return data;
      }

      async function refreshStatus() {
        const status = await fetchJSON('/health');
        const badge = document.getElementById('status-badge');
        const mcpBadge = document.getElementById('mcp-status');
        const unlockCard = document.getElementById('unlock-card');
        const lockScreen = document.getElementById('lock-screen');
        const requestsCard = document.getElementById('requests-card');
        if (status.unlocked) {
          badge.textContent = 'unlocked';
          badge.style.color = '#bbf7d0';
          unlockCard.style.display = 'none';
          lockScreen.classList.remove('active');
          requestsCard.style.display = 'block';
        } else {
          badge.textContent = 'locked';
          badge.style.color = '#fecaca';
          unlockCard.style.display = 'block';
          lockScreen.classList.add('active');
          requestsCard.style.display = 'none';
        }

        try {
          const mcp = await fetchJSON('/v1/vault/mcp-status');
          if (mcp.running) {
            mcpBadge.textContent = mcp.unlocked ? 'MCP: unlocked' : 'MCP: locked';
          } else {
            mcpBadge.textContent = 'MCP: not running';
          }
        } catch {
          mcpBadge.textContent = 'MCP: unknown';
        }
      }

      async function unlockVault() {
        const passphrase = document.getElementById('passphrase').value;
        const msg = document.getElementById('unlock-msg');
        msg.textContent = '';
        try {
          await fetchJSON('/v1/vault/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase }),
          });
          msg.textContent = 'Unlocked.';
          await refreshStatus();
        } catch (err) {
          msg.textContent = err?.error?.message || 'Failed to unlock';
        }
      }

      async function unlockMcp() {
        const passTop = document.getElementById('passphrase-top').value;
        const passMain = document.getElementById('passphrase').value;
        const passphrase = passTop || passMain;
        const msg = document.getElementById('mcp-msg');
        msg.textContent = '';
        if (!passphrase) {
          msg.textContent = 'Passphrase required.';
          return;
        }
        try {
          await fetchJSON('/v1/vault/unlock-mcp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase }),
          });
          msg.textContent = 'MCP unlock queued.';
        } catch (err) {
          msg.textContent = err?.error?.message || 'Failed to unlock MCP';
        }
      }

      async function loadConsents() {
        const container = document.getElementById('consents');
        const emptyMsg = document.getElementById('empty-msg');
        container.innerHTML = '';
        emptyMsg.textContent = '';
        const res = await fetchJSON('/consent');
        const pending = res.pending || [];
        if (pending.length === 0) {
          emptyMsg.textContent = 'No pending requests.';
          return;
        }

        for (const c of pending) {
          const el = document.createElement('div');
          el.className = 'consent';
          const details = c.details || {};
          const amount = details.amount && details.currency ? \`\${details.amount} \${details.currency}\` : null;
          const note = details.description ? details.description : '';
          const chain = details.chain ? details.chain : null;
          const recipient = details.recipient ? details.recipient : null;
          const purpose = details.purpose ? details.purpose : null;
          const network = details.network ? details.network : null;
          el.innerHTML = \`
            <div class="row space">
              <div><strong>\${c.agent_name || 'Agent'}</strong> wants <strong>\${c.action}</strong></div>
              <div class="small muted">\${c.id}</div>
            </div>
            <div class="small muted" style="margin-top: 6px;">
              Scope: \${c.scope || '-'} • Expires: \${new Date(c.expires_at).toLocaleTimeString()}
            </div>
            <div class="small muted" style="margin-top: 6px;">
              \${amount ? '<span class="pill">Amount</span> ' + amount : ''}
              \${chain ? ' <span class="pill">Chain</span> ' + chain : ''}
              \${network ? ' <span class="pill">Network</span> ' + network : ''}
            </div>
            \${recipient ? '<div class="small muted" style="margin-top: 6px;">Recipient: ' + recipient + '</div>' : ''}
            \${purpose ? '<div class="small muted" style="margin-top: 6px;">Purpose: ' + purpose + '</div>' : ''}
            \${note ? '<div class="small muted" style="margin-top: 6px;">Note: ' + note + '</div>' : ''}
            <div class="actions" style="margin-top: 10px;">
              <button class="btn ok" data-id="\${c.id}" data-mode="once">Approve once</button>
              <button class="btn" data-id="\${c.id}" data-mode="session">Session</button>
              <button class="btn danger" data-id="\${c.id}" data-mode="deny">Deny</button>
            </div>
          \`;
          container.appendChild(el);
        }
      }

      async function handleAction(e) {
        const btn = e.target.closest('button');
        if (!btn) return;
        const id = btn.getAttribute('data-id');
        const mode = btn.getAttribute('data-mode');
        if (!id || !mode) return;

        if (mode === 'deny') {
          await fetchJSON(\`/consent/\${id}/deny\`, { method: 'POST' });
        } else {
          await fetchJSON(\`/consent/\${id}/approve\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: mode === 'session' }),
          });
        }
        await loadConsents();
      }

      document.getElementById('unlock-btn').addEventListener('click', unlockVault);
      document.getElementById('unlock-mcp-btn-top').addEventListener('click', unlockMcp);
      document.getElementById('refresh-btn').addEventListener('click', loadConsents);
      document.getElementById('consents').addEventListener('click', handleAction);
      document.getElementById('theme-btn').addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('dcp-theme', next);
      });

      const savedTheme = localStorage.getItem('dcp-theme');
      if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
      }

      refreshStatus().then(loadConsents);
      setInterval(loadConsents, 5000);
    </script>
  </body>
</html>`);
  });

  // ============================================================================
  // Vault Unlock (local only)
  // ============================================================================

  server.post('/v1/vault/unlock', async (request, reply) => {
    const body = request.body as { passphrase?: string };

    if (!body || typeof body.passphrase !== 'string' || body.passphrase.length === 0) {
      throw new VaultError('INTERNAL_ERROR', 'passphrase is required');
    }

    try {
      await storage.unlock(body.passphrase);

      // Start relay client if not already connected (e.g., first unlock after init)
      if (!relayConnected && (await storage.isProvisioned())) {
        startRelayClient(server).catch((err) => {
          server.log.error(err, 'Relay client failed to start after unlock');
        });
      }

      return { unlocked: true };
    } catch (err) {
      if (err instanceof VaultError && err.message.includes('Wrong passphrase')) {
        throw new VaultError('INTERNAL_ERROR', 'Wrong passphrase');
      }
      throw err;
    }
  });

  // ============================================================================
  // MCP Unlock Bridge (local only)
  // ============================================================================

  server.post('/v1/vault/unlock-mcp', async (request) => {
    const body = request.body as { passphrase?: string };
    if (!body || typeof body.passphrase !== 'string' || body.passphrase.length === 0) {
      throw new VaultError('INTERNAL_ERROR', 'passphrase is required');
    }

    // Store passphrase + expiry in OS keychain for MCP to retrieve (no disk writes)
    try {
      const expiresAt = new Date(Date.now() + MCP_UNLOCK_SESSION_MINUTES * 60 * 1000).toISOString();
      await keytar.setPassword(
        MCP_UNLOCK_KEYCHAIN_SERVICE,
        MCP_UNLOCK_KEYCHAIN_ACCOUNT,
        body.passphrase
      );
      await keytar.setPassword(
        MCP_UNLOCK_KEYCHAIN_SERVICE,
        MCP_UNLOCK_META_ACCOUNT,
        JSON.stringify({ expires_at: expiresAt })
      );
    } catch {
      throw new VaultError(
        'INTERNAL_ERROR',
        'Keychain unavailable. Use CLI unlock or vault_unlock instead.'
      );
    }

    // Write a one-time signal file for MCP to pick up (no secrets)
    const dir = vaultDir || path.join(os.homedir(), '.dcp');
    const unlockPath = path.join(dir, 'mcp.unlock');
    const payload = JSON.stringify({ created_at: new Date().toISOString() });
    fs.writeFileSync(unlockPath, payload, { mode: 0o600 });

    return { queued: true };
  });

  // ============================================================================
  // MCP Status (local only)
  // ============================================================================

  server.get('/v1/vault/mcp-status', async () => {
    try {
      const dir = vaultDir || path.join(os.homedir(), '.dcp');
      const statusPath = path.join(dir, 'mcp.status');
      if (!fs.existsSync(statusPath)) {
        return { running: false, unlocked: false };
      }
      const raw = fs.readFileSync(statusPath, 'utf8');
      const data = JSON.parse(raw) as { unlocked?: boolean; updated_at?: string; pid?: number };
      return {
        running: true,
        unlocked: Boolean(data.unlocked),
        updated_at: data.updated_at,
        pid: data.pid,
      };
    } catch {
      return { running: false, unlocked: false };
    }
  });

  // ============================================================================
  // Desktop Owner Trust Model Endpoints
  // ============================================================================

  /**
   * Register desktop public key
   * POST /v1/desktop/register
   */
  server.post<{
    Body: {
      desktop_id: string;
      public_key: string; // base64 encoded Ed25519 public key
    };
  }>('/v1/desktop/register', async (request) => {
    const { desktop_id, public_key } = request.body;

    if (!desktop_id || !public_key) {
      throw new VaultError('INTERNAL_ERROR', 'desktop_id and public_key are required');
    }

    // Validate public key is valid base64 and correct length (32 bytes for Ed25519)
    try {
      const keyBytes = Buffer.from(public_key, 'base64');
      if (keyBytes.length !== 32) {
        throw new VaultError('INTERNAL_ERROR', 'Invalid public key length. Expected 32 bytes.');
      }
    } catch {
      throw new VaultError('INTERNAL_ERROR', 'Invalid public key format');
    }

    // Store in config
    budget.setConfig('desktop_owner', {
      desktop_id,
      public_key,
      registered_at: new Date().toISOString(),
    });

    storage.logAudit('CONFIG', 'success', {
      operation: 'desktop_register',
      details: JSON.stringify({ desktop_id }),
    });

    return { registered: true };
  });

  /**
   * Get challenge nonce for desktop authentication
   * GET /v1/desktop/challenge?desktop_id=<uuid>
   */
  server.get<{
    Querystring: {
      desktop_id: string;
    };
  }>('/v1/desktop/challenge', async (request) => {
    const { desktop_id } = request.query;

    if (!desktop_id) {
      throw new VaultError('INTERNAL_ERROR', 'desktop_id is required');
    }

    // Verify this desktop_id is registered
    const config = budget.getConfig();
    if (!config.desktop_owner || config.desktop_owner.desktop_id !== desktop_id) {
      throw new VaultError('INTERNAL_ERROR', 'Desktop not registered');
    }

    // Clean up expired state
    cleanupOwnerState();

    // Generate challenge
    const nonce = generateChallenge();
    const expires_at = Date.now() + CHALLENGE_TIMEOUT_MS;

    // Store challenge
    pendingChallenges.set(desktop_id, {
      nonce,
      desktop_id,
      expires_at,
    });

    return {
      desktop_id,
      nonce,
      expires_at: new Date(expires_at).toISOString(),
    };
  });

  /**
   * Verify challenge signature and issue owner token
   * POST /v1/desktop/verify
   */
  server.post<{
    Body: {
      desktop_id: string;
      nonce: string;
      signature: string; // base64 encoded Ed25519 signature
    };
  }>('/v1/desktop/verify', async (request) => {
    const { desktop_id, nonce, signature } = request.body;

    if (!desktop_id || !nonce || !signature) {
      throw new VaultError('INTERNAL_ERROR', 'desktop_id, nonce, and signature are required');
    }

    // Clean up expired state
    cleanupOwnerState();

    // Get pending challenge
    const challenge = pendingChallenges.get(desktop_id);
    if (!challenge) {
      throw new VaultError('INTERNAL_ERROR', 'No pending challenge for this desktop');
    }

    // Check if challenge expired
    if (Date.now() > challenge.expires_at) {
      pendingChallenges.delete(desktop_id);
      throw new VaultError('CONSENT_TIMEOUT', 'Challenge expired');
    }

    // Check nonce matches
    if (challenge.nonce !== nonce) {
      throw new VaultError('INTERNAL_ERROR', 'Invalid nonce');
    }

    // Get registered public key
    const config = budget.getConfig();
    if (!config.desktop_owner || config.desktop_owner.desktop_id !== desktop_id) {
      throw new VaultError('INTERNAL_ERROR', 'Desktop not registered');
    }

    // Verify signature
    const publicKeyBytes = Buffer.from(config.desktop_owner.public_key, 'base64');
    const nonceBytes = Buffer.from(nonce, 'base64');
    const signatureBytes = Buffer.from(signature, 'base64');

    const valid = verifyEd25519Signature(
      new Uint8Array(nonceBytes),
      new Uint8Array(signatureBytes),
      new Uint8Array(publicKeyBytes)
    );

    if (!valid) {
      storage.logAudit('DENY', 'denied', {
        operation: 'desktop_verify',
        details: JSON.stringify({ desktop_id, reason: 'invalid_signature' }),
      });
      throw new VaultError('INTERNAL_ERROR', 'Invalid signature');
    }

    // Remove used challenge
    pendingChallenges.delete(desktop_id);

    // Generate owner token
    const token = generateOwnerToken();
    const now = Date.now();

    ownerTokens.set(token, {
      token,
      desktop_id,
      created_at: now,
      last_used_at: now,
    });

    storage.logAudit('GRANT', 'success', {
      operation: 'desktop_verify',
      details: JSON.stringify({ desktop_id }),
    });

    return {
      verified: true,
      token,
      expires_at: new Date(now + OWNER_TOKEN_MAX_AGE_MS).toISOString(),
      idle_timeout_minutes: OWNER_TOKEN_IDLE_TIMEOUT_MS / 60000,
    };
  });

  // ============================================================================
  // Relay Info / Config (owner only)
  // ============================================================================

  server.get('/v1/relay/info', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const identity = await ensureRelayIdentity();
    return {
      vault_id: identity.vaultId,
      relay_url: identity.relayUrl,
      hpke_public_key: identity.hpkeKeyPair.publicKey.toString('base64'),
      pairing_token: identity.pairingToken || null,
      relay_connected: relayConnected,
    };
  });

  server.post<{
    Body: {
      relay_url?: string;
      pairing_token?: string;
    };
  }>('/v1/relay/config', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const { relay_url, pairing_token } = request.body || {};
    if (relay_url !== undefined) {
      budget.setConfig('relay_url', relay_url);
    }
    if (pairing_token !== undefined) {
      budget.setConfig('relay_pairing_token', pairing_token);
    }

    // Restart relay client with new config
    try {
      await startRelayClient(server);
    } catch (err) {
      return reply.status(500).send({
        error: {
          code: 'RELAY_START_FAILED',
          message: err instanceof Error ? err.message : 'Failed to start relay client',
        },
      });
    }

    return {
      updated: true,
    };
  });

  // ============================================================================
  // Pairing Tokens (owner only)
  // ============================================================================

  server.post<{
    Body: {
      service_id: string;
      scopes: string[];
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      ttl_seconds?: number;
    };
  }>('/v1/pairing/start', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const body = request.body || {};
    if (!body.service_id || !body.scopes || body.scopes.length === 0) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: 'service_id and at least one scope are required',
        },
      });
    }

    const budgetConfig = normalizeBudget(body.budget);
    const { token, expires_at } = storage.createPairingToken({
      service_id: body.service_id,
      scopes: body.scopes,
      budget: budgetConfig,
      ttl_seconds: body.ttl_seconds,
    });

    return {
      token,
      expires_at,
      service_id: body.service_id,
      scopes: body.scopes,
      budget: budgetConfig,
    };
  });

  // ============================================================================
  // Vault Lock (local only)
  // ============================================================================

  server.post('/v1/vault/lock', async () => {
    storage.lock();
    return { locked: true };
  });

  // ============================================================================
  // Scopes
  // ============================================================================

  server.get('/scopes', async () => {
    const records = storage.listRecords();

    return {
      scopes: records.map((r) => ({
        scope: r.scope,
        type: r.item_type,
        sensitivity: r.sensitivity,
        chain: r.chain,
        public_address: r.public_address,
      })),
    };
  });

  // ============================================================================
  // Address
  // ============================================================================

  server.get<{ Params: { chain: Chain } }>('/address/:chain', async (request, reply) => {
    const { chain } = request.params;

    const records = storage.listRecords();
    const wallet = records.find((r) => r.item_type === 'WALLET_KEY' && r.chain === chain);

    if (!wallet || !wallet.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    return {
      chain,
      address: wallet.public_address,
    };
  });

  // ============================================================================
  // Budget Check
  // ============================================================================

  server.get<{ Querystring: { amount: string; currency: string; chain?: Chain } }>(
    '/budget/check',
    async (request) => {
      const amount = parseFloat(request.query.amount);
      const currency = request.query.currency;
      const chainParam = request.query.chain;

      if (isNaN(amount) || !currency) {
        throw new VaultError('INTERNAL_ERROR', 'amount and currency are required');
      }

      const limits = budget.getLimits(currency);
      const chain = getChainForCurrency(currency, chainParam);
      const result = budget.checkBudget(amount, currency, chain);

      return {
        allowed: result.allowed,
        limits: {
          per_tx: limits.tx_limit,
          daily: limits.daily_budget,
          approval_threshold: limits.approval_threshold,
        },
        remaining: {
          daily: result.remaining_daily,
          per_tx: result.remaining_tx,
        },
        requires_approval: result.requires_approval,
        reason: result.reason,
      };
    }
  );

  // ============================================================================
  // Budget Config (Owner Only)
  // ============================================================================

  server.get('/v1/vault/budgets', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const config = budget.getConfig();
    return {
      daily_budget: config.daily_budget,
      tx_limit: config.tx_limit,
      approval_threshold: config.approval_threshold,
    };
  });

  server.post<{
    Body: {
      daily_budget?: Record<string, number>;
      tx_limit?: Record<string, number>;
      approval_threshold?: Record<string, number>;
    };
  }>('/v1/vault/budgets', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const { daily_budget, tx_limit, approval_threshold } = request.body || {};

    if (daily_budget) {
      for (const [currency, amount] of Object.entries(daily_budget)) {
        budget.setLimit('daily_budget', currency, Number(amount));
      }
    }
    if (tx_limit) {
      for (const [currency, amount] of Object.entries(tx_limit)) {
        budget.setLimit('tx_limit', currency, Number(amount));
      }
    }
    if (approval_threshold) {
      for (const [currency, amount] of Object.entries(approval_threshold)) {
        budget.setLimit('approval_threshold', currency, Number(amount));
      }
    }

    const config = budget.getConfig();
    return {
      updated: true,
      daily_budget: config.daily_budget,
      tx_limit: config.tx_limit,
      approval_threshold: config.approval_threshold,
    };
  });

  // ============================================================================
  // Agents (Sessions)
  // ============================================================================

  server.get('/agents', async () => {
    const sessions = storage.listActiveSessions();

    return {
      agents: sessions.map((s) => ({
        id: s.id,
        agent_name: s.agent_name,
        granted_scopes: s.granted_scopes,
        consent_mode: s.consent_mode,
        expires_at: s.expires_at,
        created_at: s.created_at,
        last_used_at: s.last_used_at,
      })),
    };
  });

  // ============================================================================
  // Trusted Services (Owner Only)
  // ============================================================================

  server.get('/v1/services', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const services = storage.listTrustedServices();
    return { services };
  });

  server.get('/v1/services/known', async () => {
    return { services: listKnownServices() };
  });

  server.post<{
    Body: {
      service_id?: string;
      name?: string;
      public_key?: string;
      scopes?: string[] | string;
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      enabled?: boolean;
      verified?: boolean;
    };
  }>('/v1/services', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const body = request.body || {};
    const serviceId = body.service_id?.trim();
    if (!serviceId) {
      throw new VaultError('INTERNAL_ERROR', 'service_id is required');
    }

    const publicKey = body.public_key?.trim();
    if (!publicKey || !isValidPublicKey(publicKey)) {
      throw new VaultError('INTERNAL_ERROR', 'Valid public_key is required');
    }

    const scopes = normalizeScopes(body.scopes);
    if (scopes.length === 0) {
      throw new VaultError('INTERNAL_ERROR', 'At least one scope is required');
    }

    const budget = normalizeBudget(body.budget);
    const enabled = body.enabled !== undefined ? Boolean(body.enabled) : true;

    storage.addTrustedService({
      service_id: serviceId,
      name: body.name?.trim() || serviceId,
      public_key: publicKey,
      scopes,
      budget,
      verified: body.verified ?? false,
    });

    if (!enabled) {
      storage.updateTrustedService(serviceId, { enabled: false });
    }

    return { created: true, service: storage.getTrustedService(serviceId) };
  });

  server.patch<{
    Params: { id: string };
    Body: {
      name?: string;
      public_key?: string;
      scopes?: string[] | string;
      budget?: { daily?: number; currency?: string; auto_approve_under?: number };
      enabled?: boolean;
      verified?: boolean;
    };
  }>('/v1/services/:id', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const serviceId = request.params.id;
    const body = request.body || {};
    const updates: Partial<Pick<TrustedService, 'name' | 'public_key' | 'scopes' | 'budget' | 'enabled' | 'verified'>> = {};

    if (body.name !== undefined) {
      updates.name = body.name.trim();
    }
    if (body.public_key !== undefined) {
      const key = body.public_key.trim();
      if (!isValidPublicKey(key)) {
        throw new VaultError('INTERNAL_ERROR', 'Invalid public_key');
      }
      updates.public_key = key;
    }
    if (body.scopes !== undefined) {
      const scopes = normalizeScopes(body.scopes);
      if (scopes.length === 0) {
        throw new VaultError('INTERNAL_ERROR', 'At least one scope is required');
      }
      updates.scopes = scopes;
    }
    if (body.budget !== undefined) {
      updates.budget = normalizeBudget(body.budget);
    }
    if (body.enabled !== undefined) {
      updates.enabled = Boolean(body.enabled);
    }
    if (body.verified !== undefined) {
      updates.verified = Boolean(body.verified);
    }

    storage.updateTrustedService(serviceId, updates);
    return { updated: true, service: storage.getTrustedService(serviceId) };
  });

  server.delete<{ Params: { id: string } }>('/v1/services/:id', async (request, reply) => {
    if (!isOwnerRequest(request)) {
      return reply.status(403).send({
        error: {
          code: 'OWNER_AUTH_REQUIRED',
          message: 'Owner authentication required',
        },
      });
    }

    const serviceId = request.params.id;
    storage.revokeTrustedService(serviceId);
    return { revoked: true };
  });

  // ============================================================================
  // Consent - List Pending
  // ============================================================================

  server.get('/consent', async () => {
    const pending = storage.getPendingConsents();

    return {
      pending: pending.map((c) => {
        let details: Record<string, unknown> = {};
        try {
          if (c.details) {
            details = JSON.parse(c.details);
          }
        } catch {
          // Ignore
        }

        return {
          id: c.id,
          agent_name: c.agent_name,
          action: c.action,
          scope: c.scope,
          details,
          status: c.status,
          created_at: c.created_at,
          expires_at: c.expires_at,
        };
      }),
    };
  });

  // ============================================================================
  // Consent - Approve
  // ============================================================================

  server.post<{ Params: { id: string }; Body: { session?: boolean; mode?: string } }>(
    '/consent/:id/approve',
    async (request) => {
      const { id } = request.params;
      const body = request.body || {};
      const createSession = Boolean(body.session || body.mode === 'session');

      const consent = storage.getPendingConsent(id);

      if (!consent) {
        throw new VaultError('CONSENT_NOT_FOUND', `Consent not found: ${id}`);
      }

      if (consent.status !== 'pending') {
        throw new VaultError('INTERNAL_ERROR', `Consent already ${consent.status}`);
      }

      if (new Date(consent.expires_at) < new Date()) {
        storage.resolveConsent(id, 'expired');
        throw new VaultError('CONSENT_TIMEOUT', 'Consent has expired');
      }

      // Create session first if requested (need ID for resolveConsent)
      let sessionId: string | undefined;
      if (createSession) {
        const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000); // 4 hours max
        const newSession = storage.createSession(
          consent.agent_name,
          [consent.scope],
          'session',
          expiresAt
        );
        sessionId = newSession.id;
      }

      // Approve (with session_id if created)
      storage.resolveConsent(id, 'approved', sessionId);

      // Log to audit
      storage.logAudit('GRANT', 'success', {
        agentName: consent.agent_name,
        scope: consent.scope,
        operation: createSession ? 'session_grant' : 'once_grant',
        details: sessionId ? JSON.stringify({ session_id: sessionId }) : undefined,
      });

      return {
        approved: true,
        session_id: sessionId,
      };
    }
  );

  // ============================================================================
  // Consent - Deny
  // ============================================================================

  server.post<{ Params: { id: string } }>('/consent/:id/deny', async (request) => {
    const { id } = request.params;

    const consent = storage.getPendingConsent(id);

    if (!consent) {
      throw new VaultError('CONSENT_NOT_FOUND', `Consent not found: ${id}`);
    }

    if (consent.status !== 'pending') {
      throw new VaultError('INTERNAL_ERROR', `Consent already ${consent.status}`);
    }

    // Deny
    storage.resolveConsent(id, 'denied');

    // Log to audit
    storage.logAudit('DENY', 'denied', {
      agentName: consent.agent_name,
      scope: consent.scope,
      operation: consent.action,
      details: 'Denied via REST API',
    });

    return {
      denied: true,
    };
  });

  // ============================================================================
  // Revoke Agent Sessions
  // ============================================================================

  server.post<{ Params: { agent: string } }>('/revoke/:agent', async (request) => {
    const { agent } = request.params;

    const count = storage.revokeAgentSessions(agent);

    if (count > 0) {
      storage.logAudit('REVOKE', 'success', {
        agentName: agent,
        operation: 'revoke_agent',
        details: JSON.stringify({ sessions_revoked: count }),
      });
    }

    return {
      revoked: count,
    };
  });

  // ============================================================================
  // V1 API: Vault Read (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/read', async (request) => {
    const { scope, agent_name, session_id, description } = request.body;
    let effectiveSessionId = session_id;

    if (!scope || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope and agent_name are required');
    }

    // Check if vault is unlocked
    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Check if this is an owner request (desktop app with valid token)
    const ownerMode = isOwnerRequest(request);

    // Try to reuse an existing active session by agent + scope
    if (!effectiveSessionId && !ownerMode) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session (skip for owner mode)
    let hasSession = ownerMode; // Owner mode auto-approves
    if (!hasSession && effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(scope) || session.granted_scopes.some(s => scope.startsWith(s.replace('.*', '')))) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session and not owner, create pending consent
    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'read',
        scope,
        description ? JSON.stringify({ description }) : undefined
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    // Get the record
    const record = storage.getRecord(scope);
    if (!record) {
      throw new VaultError('RECORD_NOT_FOUND', `No record found for scope: ${scope}`);
    }

    // Decrypt if it's not a CRITICAL item
    if (record.sensitivity === 'critical') {
      // Don't return critical data - return reference only
      storage.logAudit('READ', 'success', {
        agentName: agent_name,
        scope,
        operation: 'read_reference',
      });

      return {
        scope,
        type: record.item_type,
        sensitivity: record.sensitivity,
        note: 'Critical data cannot be read directly. Use vault_sign_tx for signing operations.',
      };
    }

    // Decrypt and return
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(scope);
    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No encrypted data for scope: ${scope}`);
    }

    const decrypted = envelopeDecrypt(payload, masterKey);
    const data = JSON.parse(decrypted.toString('utf-8'));

    storage.logAudit('READ', 'success', {
      agentName: agent_name,
      scope,
      operation: 'read_data',
    });

    return {
      scope,
      data,
    };
  });

  // ============================================================================
  // V1 API: Vault Write (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      data: Record<string, unknown>;
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/write', async (request) => {
    const { scope, data, agent_name, session_id } = request.body;
    let effectiveSessionId = session_id;

    if (!scope || !data || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope, data, and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Check if this is an owner request (desktop app with valid token)
    const ownerMode = isOwnerRequest(request);

    // Skip write permission check for owner mode
    if (!ownerMode && !isWriteAllowed(agent_name, scope)) {
      throw new VaultError(
        'SCOPE_VIOLATION',
        `Agent ${agent_name} not authorized to write scope: ${scope}`
      );
    }

    if (!effectiveSessionId && !ownerMode) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session (skip for owner mode)
    let hasSession = ownerMode; // Owner mode auto-approves
    if (!hasSession && effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (
          session.granted_scopes.includes(scope) ||
          session.granted_scopes.some((s) => scope.startsWith(s.replace('.*', '')))
        ) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session and not owner, create pending consent
    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'write',
        scope
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const masterKey = storage.getMasterKey();
    const existing = storage.getRecord(scope);
    const payloadData = normalizeWriteData(scope, data);

    if (existing) {
      storage.updateRecord(existing.id, payloadData, masterKey);
    } else {
      storage.createRecord({
        scope,
        item_type: inferItemType(scope),
        sensitivity: inferSensitivity(scope),
        data: payloadData,
      });
    }

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope,
      operation: 'write',
    });

    return {
      scope,
      created: !existing,
      updated: !!existing,
      sensitivity: existing?.sensitivity || inferSensitivity(scope),
    };
  });

  // ============================================================================
  // V1 API: Vault Delete (with consent)
  // ============================================================================

  server.post<{
    Body: {
      scope: string;
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/delete', async (request) => {
    const { scope, agent_name, session_id, description } = request.body;
    let effectiveSessionId = session_id;

    if (!scope || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'scope and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const ownerMode = isOwnerRequest(request);

    if (!ownerMode && !isWriteAllowed(agent_name, scope)) {
      throw new VaultError(
        'SCOPE_VIOLATION',
        `Agent ${agent_name} not authorized to delete scope: ${scope}`
      );
    }

    if (!effectiveSessionId && !ownerMode) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = ownerMode;
    if (!hasSession && effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (
          session.granted_scopes.includes(scope) ||
          session.granted_scopes.some((s) => scope.startsWith(s.replace('.*', '')))
        ) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'delete',
        scope,
        JSON.stringify({ description })
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const existing = storage.listRecords().find((r) => r.scope === scope);
    if (!existing) {
      throw new VaultError('RECORD_NOT_FOUND', `No record found for scope: ${scope}`);
    }

    const deleted = storage.deleteRecord(scope);
    if (deleted) {
      storage.logAudit('EXECUTE', 'success', {
        agentName: agent_name,
        scope,
        operation: 'delete',
      });
    }

    return {
      scope,
      deleted,
    };
  });

  // ============================================================================
  // V1 API: Vault Sign (with consent + budget)
  // ============================================================================

  server.post<{
    Body: {
      chain: Chain;
      unsigned_tx: string;
      amount?: number;
      currency?: string;
      agent_name: string;
      session_id?: string;
      description?: string;
      idempotency_key?: string;
    };
  }>('/v1/vault/sign', async (request) => {
    const { chain, unsigned_tx, amount, currency, agent_name, session_id, description, idempotency_key } = request.body;
    let effectiveSessionId = session_id;

    if (!chain || !unsigned_tx || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'chain, unsigned_tx, and agent_name are required');
    }

    // Check if vault is unlocked
    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    // Determine currency from chain if not provided
    const txCurrency = currency || (chain === 'solana' ? 'SOL' : chain === 'ethereum' ? 'ETH' : 'BASE_ETH');

    // Budget check if amount is provided
    if (amount !== undefined && amount > 0) {
      const budgetResult = budget.checkBudget(amount, txCurrency, chain);

      if (!budgetResult.allowed) {
        storage.logAudit('EXECUTE', 'denied', {
          agentName: agent_name,
          scope: `crypto.wallet.${chain}`,
          operation: 'sign_tx',
          details: JSON.stringify({ reason: budgetResult.reason, amount, currency: txCurrency }),
        });

        const errorCode = budgetResult.reason?.includes('BUDGET_EXCEEDED_TX')
          ? 'BUDGET_EXCEEDED_TX'
          : 'BUDGET_EXCEEDED_DAILY';

        throw new VaultError(errorCode, budgetResult.reason || 'Budget exceeded', {
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
        });
      }

      // If above approval threshold, always require consent
      if (budgetResult.requires_approval) {
        const consent = storage.createPendingConsent(
          agent_name,
          'sign_tx',
          `crypto.wallet.${chain}`,
          JSON.stringify({ description, amount, currency: txCurrency, chain })
        );

        return {
          requires_consent: true,
          consent_id: consent.id,
          expires_at: consent.expires_at,
          reason: 'Amount exceeds approval threshold',
          message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
        };
      }
    }

    // Get wallet scope
    const walletScope = `crypto.wallet.${chain}`;

    // Try to reuse an existing active session by agent + scope
    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session
    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session, create pending consent
    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'sign_tx',
        walletScope,
        JSON.stringify({ description, amount, currency: txCurrency, chain })
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    // Get wallet and sign
    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(walletScope);

    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    // Sign the transaction (signTransaction expects base64 string for Solana, JSON string for EVM)
    const signResult = await signTransaction(payload, masterKey, chain, unsigned_tx);

    // Record spend event if amount provided
    if (amount !== undefined && amount > 0 && effectiveSessionId) {
      storage.recordSpend(effectiveSessionId, amount, txCurrency, chain, 'sign_tx', 'committed', {
        idempotencyKey: idempotency_key,
      });
    }

    // Get updated budget info
    const budgetInfo = budget.checkBudget(0, txCurrency, chain);

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_tx',
      details: JSON.stringify({ chain, amount, currency: txCurrency }),
    });

    return {
      signed_tx: signResult.signed_tx,
      signature: signResult.signature,
      chain,
      remaining_daily: budgetInfo.remaining_daily,
      session_id: effectiveSessionId,
    };
  });

  // ============================================================================
  // V1 API: Vault Sign Message (with consent)
  // ============================================================================

  const handleSignMessage = async (body: {
    chain: Chain;
    message: string;
    encoding?: 'utf8' | 'base64';
    agent_name: string;
    session_id?: string;
    description?: string;
  }) => {
    const { chain, message, encoding, agent_name, session_id, description } = body;
    let effectiveSessionId = session_id;

    if (!chain || !message || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'chain, message, and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const walletScope = `crypto.wallet.${chain}`;

    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'sign_message',
        walletScope,
        JSON.stringify({
          description,
          chain,
          message_length: message.length,
          encoding: encoding || 'utf8',
        })
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const records = storage.listRecords();
    const walletRecord = records.find(
      (r) => r.item_type === 'WALLET_KEY' && r.chain === chain
    );
    if (!walletRecord || !walletRecord.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(walletScope);
    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const resolvedEncoding = encoding || 'utf8';
    let signature: string;
    if (chain === 'solana') {
      signature = signSolanaMessage(payload, masterKey, message, resolvedEncoding);
    } else {
      const messagePayload =
        resolvedEncoding === 'base64' ? Buffer.from(message, 'base64') : message;
      signature = await signEvmMessage(payload, masterKey, messagePayload);
    }

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_message',
      details: JSON.stringify({ chain }),
    });

    return {
      signature,
      public_key: walletRecord.public_address,
      chain,
      session_id: effectiveSessionId,
    };
  };

  server.post<{
    Body: {
      chain: Chain;
      message: string;
      encoding?: 'utf8' | 'base64';
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/sign-message', async (request) => {
    return handleSignMessage(request.body);
  });

  server.post<{
    Body: {
      chain: Chain;
      message: string;
      encoding?: 'utf8' | 'base64';
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/sign_message', async (request) => {
    return handleSignMessage(request.body);
  });

  // ============================================================================
  // V1 API: Vault Sign Typed Data (with consent)
  // ============================================================================

  const handleSignTypedData = async (body: {
    chain: Chain;
    typed_data: Record<string, unknown>;
    agent_name: string;
    session_id?: string;
    description?: string;
  }) => {
    const { chain, typed_data, agent_name, session_id, description } = body;
    let effectiveSessionId = session_id;

    if (!chain || !typed_data || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'chain, typed_data, and agent_name are required');
    }

    if (chain !== 'base' && chain !== 'ethereum') {
      throw new VaultError('INVALID_CHAIN', `Unsupported chain for typed data: ${chain}`);
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const walletScope = `crypto.wallet.${chain}`;

    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'sign_typed_data',
        walletScope,
        JSON.stringify({
          description,
          chain,
        })
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const records = storage.listRecords();
    const walletRecord = records.find(
      (r) => r.item_type === 'WALLET_KEY' && r.chain === chain
    );
    if (!walletRecord || !walletRecord.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const masterKey = storage.getMasterKey();
    const payload = storage.getEncryptedPayload(walletScope);
    if (!payload) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const signature = await signEvmTypedData(payload, masterKey, typed_data);

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_typed_data',
      details: JSON.stringify({ chain }),
    });

    return {
      signature,
      public_key: walletRecord.public_address,
      chain,
      session_id: effectiveSessionId,
    };
  };

  server.post<{
    Body: {
      chain: Chain;
      typed_data: Record<string, unknown>;
      agent_name: string;
      session_id?: string;
      description?: string;
    };
  }>('/v1/vault/sign_typed_data', async (request) => {
    return handleSignTypedData(request.body);
  });

  // ============================================================================
  // V1 API: Vault Sign x402 (with consent)
  // ============================================================================

  server.post<{
    Body: {
      network: 'solana' | 'base';
      payload: string;
      amount?: string | number;
      currency?: string;
      recipient?: string;
      purpose?: string;
      typed_data?: Record<string, unknown>;
      agent_name: string;
      session_id?: string;
    };
  }>('/v1/vault/sign_x402', async (request) => {
    const {
      network,
      payload,
      amount,
      currency,
      recipient,
      purpose,
      typed_data,
      agent_name,
      session_id,
    } = request.body;
    let effectiveSessionId = session_id;

    if (!network || !payload || !agent_name) {
      throw new VaultError('INTERNAL_ERROR', 'network, payload, and agent_name are required');
    }

    if (!storage.isUnlocked()) {
      throw new VaultError('VAULT_LOCKED', 'Vault is locked. Please unlock first.');
    }

    const chain: Chain = network === 'solana' ? 'solana' : 'base';
    const walletScope = `crypto.wallet.${chain}`;

    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, walletScope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(walletScope)) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    const parsedAmount = normalizeAmount(amount);
    if (parsedAmount !== undefined && !currency) {
      throw new VaultError('INTERNAL_ERROR', 'currency is required when amount is provided');
    }
    if (parsedAmount !== undefined && currency) {
      const budgetResult = budget.checkBudget(parsedAmount, currency, chain);

      if (!budgetResult.allowed) {
        const errorCode = budgetResult.reason?.includes('BUDGET_EXCEEDED_TX')
          ? 'BUDGET_EXCEEDED_TX'
          : 'BUDGET_EXCEEDED_DAILY';

        throw new VaultError(errorCode, budgetResult.reason || 'Budget exceeded', {
          remaining_daily: budgetResult.remaining_daily,
          remaining_tx: budgetResult.remaining_tx,
        });
      }

      if (budgetResult.requires_approval) {
        const consent = storage.createPendingConsent(
          agent_name,
          'sign_x402',
          walletScope,
          JSON.stringify({
            amount: parsedAmount,
            currency,
            network,
            recipient,
            purpose,
          })
        );

        return {
          requires_consent: true,
          consent_id: consent.id,
          expires_at: consent.expires_at,
          reason: 'Amount exceeds approval threshold',
          message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
        };
      }
    }

    if (!hasSession) {
      const consent = storage.createPendingConsent(
        agent_name,
        'sign_x402',
        walletScope,
        JSON.stringify({
          amount: parsedAmount,
          currency,
          network,
          recipient,
          purpose,
        })
      );

      return {
        requires_consent: true,
        consent_id: consent.id,
        expires_at: consent.expires_at,
        message: `Consent required. Approve with: POST /consent/${consent.id}/approve`,
      };
    }

    const records = storage.listRecords();
    const walletRecord = records.find(
      (r) => r.item_type === 'WALLET_KEY' && r.chain === chain
    );
    if (!walletRecord || !walletRecord.public_address) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    const masterKey = storage.getMasterKey();
    const encryptedKey = storage.getEncryptedPayload(walletScope);
    if (!encryptedKey) {
      throw new VaultError('RECORD_NOT_FOUND', `No wallet found for chain: ${chain}`);
    }

    let signature: string;
    if (chain === 'solana') {
      signature = signSolanaMessage(encryptedKey, masterKey, payload, 'base64');
    } else if (typed_data) {
      signature = await signEvmTypedData(encryptedKey, masterKey, typed_data);
    } else {
      const payloadBytes = Buffer.from(payload, 'base64');
      signature = await signEvmMessage(encryptedKey, masterKey, payloadBytes);
    }

    if (parsedAmount !== undefined && currency && effectiveSessionId) {
      storage.recordSpend(effectiveSessionId, parsedAmount, currency, chain, 'sign_x402', 'committed', {
        destination: recipient,
      });
    }

    storage.logAudit('EXECUTE', 'success', {
      agentName: agent_name,
      scope: walletScope,
      operation: 'sign_x402',
      details: JSON.stringify({
        amount: parsedAmount,
        currency,
        network,
        recipient,
        purpose,
      }),
    });

    return {
      signature,
      public_key: walletRecord.public_address,
      chain,
      session_id: effectiveSessionId,
    };
  });

  // ============================================================================
  // V1 API: Activity (Audit Events)
  // ============================================================================

  server.get<{
    Querystring: {
      limit?: string;
      agent?: string;
      type?: string;
      since?: string;
    };
  }>('/v1/vault/activity', async (request) => {
    const limit = parseInt(request.query.limit || '100', 10);
    const agentName = request.query.agent;
    const eventType = request.query.type?.toUpperCase() as AuditEventType | undefined;
    const since = request.query.since ? new Date(request.query.since) : undefined;

    // Validate event type
    if (eventType && !['GRANT', 'DENY', 'EXECUTE', 'READ', 'REVOKE', 'CONFIG', 'EXPIRE'].includes(eventType)) {
      throw new VaultError('INTERNAL_ERROR', `Invalid event type: ${request.query.type}`);
    }

    const events = storage.getAuditEvents(limit, {
      eventType,
      agentName,
      since,
    });

    return {
      events: events.map((e) => ({
        id: e.id,
        event_type: e.event_type,
        agent_name: e.agent_name,
        scope: e.scope,
        operation: e.operation,
        outcome: e.outcome,
        created_at: e.created_at,
        details: e.details ? (() => {
          try {
            return JSON.parse(e.details);
          } catch {
            return e.details;
          }
        })() : undefined,
      })),
      count: events.length,
    };
  });

  // ============================================================================
  // V1 API: Revoke Specific Session
  // ============================================================================

  server.post<{ Params: { id: string } }>('/v1/vault/agents/:id/revoke', async (request) => {
    const { id } = request.params;

    const session = storage.getSession(id);
    if (!session) {
      throw new VaultError('INTERNAL_ERROR', `Session not found: ${id}`);
    }

    const success = storage.revokeSession(id);

    if (success) {
      storage.logAudit('REVOKE', 'success', {
        agentName: session.agent_name,
        operation: 'revoke_session',
        details: JSON.stringify({ session_id: id }),
      });
    }

    return {
      revoked: success,
      session_id: id,
      agent_name: session.agent_name,
    };
  });

  return server;
}

// ============================================================================
// Helpers
// ============================================================================

function getChainForCurrency(currency: string, chain?: Chain): Chain {
  if (chain) return chain;
  switch (currency.toUpperCase()) {
    case 'SOL':
      return 'solana';
    case 'ETH':
      return 'ethereum';
    case 'BASE_ETH':
      return 'base';
    case 'USDC':
    case 'USDT':
      throw new VaultError('INTERNAL_ERROR', `chain is required for ${currency}`);
    default:
      throw new VaultError('INTERNAL_ERROR', `Unknown currency: ${currency}`);
  }
}

// ============================================================================
// Service Signature Verification (PRD Section B2)
// ============================================================================

/**
 * Verify a service's Ed25519 signature on a relay request payload
 *
 * The service signs the payload (minus the signature field) to prove identity.
 * The vault verifies this signature using the trusted service's public key.
 *
 * @param payload - Decrypted relay payload
 * @param serviceId - Service identifier
 * @param signature - Base64-encoded Ed25519 signature
 * @param publicKey - Service's Ed25519 public key (base64 or ed25519:xxx format)
 * @returns true if signature is valid
 */
function verifyServiceSignature(
  payload: Record<string, unknown>,
  serviceId: string,
  signature: string,
  publicKey: string
): boolean {
  // Extract the raw public key
  let keyData: string;
  if (publicKey.startsWith('ed25519:')) {
    keyData = publicKey.slice(8);
  } else {
    keyData = publicKey;
  }

  const publicKeyBytes = Buffer.from(keyData, 'base64');
  if (publicKeyBytes.length !== 32) {
    return false;
  }

  // Create the message to verify (payload without signature)
  const payloadWithoutSig = { ...payload };
  delete payloadWithoutSig.service_signature;
  const message = Buffer.from(canonicalJson(payloadWithoutSig), 'utf8');

  // Verify using nacl (canonical JSON)
  const signatureBytes = Buffer.from(signature, 'base64');
  const canonicalOk = nacl.sign.detached.verify(
    new Uint8Array(message),
    new Uint8Array(signatureBytes),
    new Uint8Array(publicKeyBytes)
  );

  if (canonicalOk) return true;

  // Backward compatibility: legacy JSON.stringify ordering
  const legacyMessage = Buffer.from(JSON.stringify(payloadWithoutSig), 'utf8');
  return nacl.sign.detached.verify(
    new Uint8Array(legacyMessage),
    new Uint8Array(signatureBytes),
    new Uint8Array(publicKeyBytes)
  );
}

function canonicalJson(value: unknown): string {
  const normalize = (input: unknown): unknown => {
    if (input === null || input === undefined) return input;
    if (typeof input === 'bigint') return input.toString();
    if (Array.isArray(input)) return input.map(normalize);
    if (typeof input === 'object') {
      const obj = input as Record<string, unknown>;
      const sorted: Record<string, unknown> = {};
      for (const key of Object.keys(obj).sort()) {
        sorted[key] = normalize(obj[key]);
      }
      return sorted;
    }
    return input;
  };

  return JSON.stringify(normalize(value));
}

function normalizeScopes(scopes: string[] | string | undefined): string[] {
  if (!scopes) return [];
  if (Array.isArray(scopes)) {
    return scopes.map((s) => s.trim()).filter((s) => s.length > 0);
  }
  return scopes
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function normalizeBudget(input?: { daily?: number; currency?: string; auto_approve_under?: number }): {
  daily: number;
  currency: string;
  auto_approve_under: number;
} {
  const daily = typeof input?.daily === 'number' && !Number.isNaN(input.daily)
    ? input.daily
    : 10;
  const currency = (input?.currency || 'USDC').toUpperCase();
  const autoApprove = typeof input?.auto_approve_under === 'number' && !Number.isNaN(input.auto_approve_under)
    ? input.auto_approve_under
    : 0;

  return {
    daily,
    currency,
    auto_approve_under: autoApprove,
  };
}

/**
 * Check if a relay request is from a trusted service and has proper authorization
 *
 * @param serviceId - Service identifier from the request
 * @param signature - Service signature
 * @param payload - Decrypted payload for signature verification
 * @param requestedScope - The scope being requested (e.g., 'crypto.wallet.solana')
 * @returns { authorized: true, service } or { authorized: false, reason }
 */
function verifyServiceAuthorization(
  serviceId: string | undefined,
  signature: string | undefined,
  payload: Record<string, unknown>,
  requestedScope: string
): { authorized: boolean; service?: TrustedService; reason?: string } {
  // If no service_id, this might be a local request (no service verification needed)
  if (!serviceId) {
    return { authorized: true };
  }

  // Look up the trusted service
  const service = storage.getTrustedService(serviceId);
  if (!service) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'service_not_trusted' }),
    });
    return { authorized: false, reason: `Service '${serviceId}' is not trusted` };
  }

  if (!service.enabled) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'service_disabled' }),
    });
    return { authorized: false, reason: `Service '${serviceId}' is disabled` };
  }

  // Verify signature
  if (!signature) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'missing_signature' }),
    });
    return { authorized: false, reason: 'Service signature required' };
  }

  const signatureValid = verifyServiceSignature(payload, serviceId, signature, service.public_key);
  if (!signatureValid) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, reason: 'invalid_signature' }),
    });
    return { authorized: false, reason: 'Invalid service signature' };
  }

  // Check scope authorization
  const scopeResult = storage.isServiceAuthorized(serviceId, requestedScope);
  if (!scopeResult.authorized) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ service_id: serviceId, scope: requestedScope, reason: scopeResult.reason }),
    });
    return { authorized: false, service, reason: scopeResult.reason };
  }

  return { authorized: true, service };
}

/**
 * Get the scope for a relay method
 */
function getScopeForRelayMethod(method: string, params: Record<string, unknown>): string {
  switch (method) {
    case 'get_address':
    case 'vault_get_address':
      return `sign:${params.chain || 'solana'}`;
    case 'vault_read':
      return `read:${params.scope || ''}`;
    case 'vault_write':
      return `write:${params.scope || ''}`;
    case 'vault_sign':
      return `sign:${params.chain || 'solana'}`;
    case 'vault_sign_message':
      return `sign:${params.chain || 'solana'}`;
    case 'vault_sign_typed_data':
      return `sign:${params.chain || 'base'}`;
    case 'vault_sign_x402':
      return `sign:${params.network || 'solana'}`;
    case 'vault_pair':
      return 'config:pair';
    case 'budget_check':
      return `budget:check`;
    default:
      return '';
  }
}

// ============================================================================
// Relay Helpers
// ============================================================================

interface RelayIdentity {
  vaultId: string;
  relayUrl: string;
  hpkeKeyPair: HpkeKeyPair;
  signingKeyPair: SigningKeyPair;
  pairingToken?: string;
}

function decodeKey(base64: string | undefined, expectedLength: number): Buffer | null {
  if (!base64) return null;
  try {
    const buf = Buffer.from(base64, 'base64');
    if (buf.length !== expectedLength) return null;
    return buf;
  } catch {
    return null;
  }
}

async function ensureRelayIdentity(): Promise<RelayIdentity> {
  const config = budget.getConfig();
  let vaultId = config.vault_id;
  if (!vaultId) {
    vaultId = `vault_${crypto.randomUUID()}`;
    budget.setConfig('vault_id', vaultId);
  }

  // Relay URL (from env overrides config)
  let relayUrl = config.relay_url || '';
  if (DEFAULT_RELAY_URL && DEFAULT_RELAY_URL !== relayUrl) {
    relayUrl = DEFAULT_RELAY_URL;
    budget.setConfig('relay_url', relayUrl);
  }

  let hpkePublic = decodeKey(config.relay_hpke_public_key, 32);
  let hpkePrivate = decodeKey(config.relay_hpke_private_key, 32);
  if (!hpkePublic || !hpkePrivate) {
    const keyPair = await generateKeyPair();
    hpkePublic = keyPair.publicKey;
    hpkePrivate = keyPair.privateKey;
    budget.setConfig('relay_hpke_public_key', hpkePublic.toString('base64'));
    budget.setConfig('relay_hpke_private_key', hpkePrivate.toString('base64'));
  }

  let signingPublic = decodeKey(config.relay_signing_public_key, 32);
  let signingPrivate = decodeKey(config.relay_signing_private_key, 64);
  if (!signingPublic || !signingPrivate) {
    const signing = generateSigningKeyPair();
    signingPublic = signing.publicKey;
    signingPrivate = signing.privateKey;
    budget.setConfig('relay_signing_public_key', signingPublic.toString('base64'));
    budget.setConfig('relay_signing_private_key', signingPrivate.toString('base64'));
  }

  return {
    vaultId,
    relayUrl,
    hpkeKeyPair: { publicKey: hpkePublic, privateKey: hpkePrivate },
    signingKeyPair: { publicKey: signingPublic, privateKey: signingPrivate },
    pairingToken: config.relay_pairing_token,
  };
}

async function handleRelayRequest(
  server: FastifyInstance,
  decryptedPayload: Buffer,
  meta: { request_id: string; action_type: string; vault_id: string; version: string }
): Promise<{ response: string; replyPublicKey: Buffer }> {
  let parsed: {
    method?: string;
    params?: Record<string, unknown>;
    agent_name?: string;
    session_id?: string;
    reply_public_key?: string;
    service_id?: string;
    service_signature?: string;
    timestamp?: string;
    nonce?: string;
  };

  try {
    parsed = JSON.parse(decryptedPayload.toString());
  } catch {
    throw new Error('Invalid relay payload: not JSON');
  }

  if (!parsed.reply_public_key) {
    throw new Error('Invalid relay payload: missing reply_public_key');
  }

  const replyPublicKey = Buffer.from(parsed.reply_public_key, 'base64');
  const method = parsed.method;
  if (!method) {
    throw new Error('Invalid relay payload: missing method');
  }

  if (method === 'vault_pair') {
    const params = (parsed.params || {}) as {
      pairing_token?: string;
      service_public_key?: string;
      service_name?: string;
    };
    const pairingToken = params.pairing_token;
    const serviceId = parsed.service_id;
    const servicePublicKey = params.service_public_key;

    if (!pairingToken || !serviceId || !servicePublicKey) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'pairing_token, service_id, and service_public_key are required',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    const tokenRecord = storage.getPairingToken(pairingToken);
    if (!tokenRecord) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'Pairing token is invalid or expired',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    if (tokenRecord.service_id !== serviceId) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'Pairing token does not match service_id',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    if (!parsed.service_signature) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'service_signature is required for pairing',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    const signatureValid = verifyServiceSignature(
      parsed as Record<string, unknown>,
      serviceId,
      parsed.service_signature,
      servicePublicKey
    );

    if (!signatureValid) {
      const errorResponse = JSON.stringify({
        ok: false,
        error: {
          code: 'PAIRING_INVALID',
          message: 'Invalid service signature',
        },
      });
      return { response: errorResponse, replyPublicKey };
    }

    const serviceName = params.service_name || serviceId;

    const existing = storage.getTrustedService(serviceId);
    if (existing) {
      storage.updateTrustedService(serviceId, {
        name: serviceName,
        public_key: servicePublicKey,
        scopes: tokenRecord.scopes,
        budget: tokenRecord.budget,
        enabled: true,
      });
    } else {
      storage.addTrustedService({
        service_id: serviceId,
        name: serviceName,
        public_key: servicePublicKey,
        scopes: tokenRecord.scopes,
        budget: tokenRecord.budget,
        verified: false,
      });
    }

    storage.markServiceConnected(serviceId);
    storage.markPairingTokenUsed(pairingToken);

    const okResponse = JSON.stringify({
      ok: true,
      service_id: serviceId,
    });
    return { response: okResponse, replyPublicKey };
  }

  // Get the scope for this method to check authorization
  const requestedScope = getScopeForRelayMethod(method, parsed.params || {});

  // Verify service authorization (PRD Section B2)
  // Relay requests must include service_id + signature
  if (!parsed.service_id) {
    storage.logAudit('DENY', 'denied', {
      operation: 'relay_request',
      details: JSON.stringify({ reason: 'missing_service_id', method }),
    });
    const errorResponse = JSON.stringify({
      ok: false,
      error: {
        code: 'VAULT_UNTRUSTED_SERVICE',
        message: 'service_id is required for relay requests',
        action: 'trust_service',
      },
    });
    return { response: errorResponse, replyPublicKey };
  }

  const authResult = verifyServiceAuthorization(
    parsed.service_id,
    parsed.service_signature,
    parsed as Record<string, unknown>,
    requestedScope
  );

  if (!authResult.authorized) {
    // Return error response
    const errorResponse = JSON.stringify({
      ok: false,
      error: {
        code: 'VAULT_UNTRUSTED_SERVICE',
        message: authResult.reason || 'Service not authorized',
        action: 'trust_service',
      },
    });
    return { response: errorResponse, replyPublicKey };
  }

  // Service is authorized - log successful verification
  storage.logAudit('EXECUTE', 'success', {
    operation: 'service_verify',
    details: JSON.stringify({
      service_id: parsed.service_id,
      method,
      scope: requestedScope,
    }),
  });

  const body: Record<string, unknown> = {
    ...(parsed.params || {}),
  };
  if (parsed.agent_name) body.agent_name = parsed.agent_name;
  if (parsed.session_id) body.session_id = parsed.session_id;

  let url = '';
  let httpMethod: 'POST' | 'GET' = 'POST';

  switch (method) {
    case 'get_address':
    case 'vault_get_address': {
      const chain = (body.chain as string | undefined) || 'solana';
      httpMethod = 'GET';
      url = `/address/${chain}`;
      break;
    }
    case 'vault_read':
      url = '/v1/vault/read';
      break;
    case 'vault_write':
      url = '/v1/vault/write';
      break;
    case 'vault_sign':
      url = '/v1/vault/sign';
      break;
    case 'vault_sign_message':
      url = '/v1/vault/sign_message';
      break;
    case 'vault_sign_typed_data':
      url = '/v1/vault/sign_typed_data';
      break;
    case 'vault_sign_x402':
      url = '/v1/vault/sign_x402';
      break;
    case 'budget_check':
      httpMethod = 'GET';
      url = `/budget/check?amount=${body.amount ?? ''}&currency=${body.currency ?? ''}&chain=${body.chain ?? ''}`;
      break;
    default:
      throw new Error(`Unknown relay method: ${method}`);
  }

  const response = await server.inject({
    method: httpMethod,
    url,
    payload: httpMethod === 'POST' ? JSON.stringify(body) : undefined,
    headers: { 'content-type': 'application/json' },
  });


  return { response: response.payload || '', replyPublicKey };
}

async function startRelayClient(server: FastifyInstance): Promise<void> {
  const identity = await ensureRelayIdentity();

  if (!identity.relayUrl) {
    return;
  }

  if (relayClient) {
    relayClient.destroy();
    relayClient = null;
    relayConnected = false;
  }

  relayClient = new RelayClient({
    relayUrl: identity.relayUrl,
    vaultId: identity.vaultId,
    keyPair: identity.hpkeKeyPair,
    signingKeyPair: identity.signingKeyPair,
    pairingToken: identity.pairingToken,
    autoReconnect: true,
    debug: false,
  });

  relayClient.on('connected', () => {
    relayConnected = true;
  });
  relayClient.on('disconnected', () => {
    relayConnected = false;
  });
  relayClient.on('error', () => {
    // Relay client errors are not always fatal. The websocket can remain open
    // while a request-level or transient transport error is reported. Only mark
    // the relay disconnected when the client is actually no longer connected.
    relayConnected = relayClient?.isConnected() ?? false;
  });

  let pendingEnvelope: { request_id: string; action_type: string; vault_id: string; version: string } | null = null;
  relayClient.on('request', (rawEnvelope: unknown) => {
    const envelope = rawEnvelope as { request_id: string; action_type: string; vault_id: string; version: string };
    pendingEnvelope = {
      request_id: envelope.request_id,
      action_type: envelope.action_type,
      vault_id: envelope.vault_id,
      version: envelope.version,
    };
  });

  relayClient.setRequestHandler(async (action, decryptedPayload) => {
    const meta = pendingEnvelope || {
      request_id: '',
      action_type: action,
      vault_id: identity.vaultId,
      version: '1',
    };
    pendingEnvelope = null;
    const { response, replyPublicKey } = await handleRelayRequest(server, decryptedPayload, {
      request_id: meta.request_id,
      action_type: meta.action_type || action,
      vault_id: meta.vault_id || identity.vaultId,
      version: meta.version || '1',
    });
    return { payload: Buffer.from(response), recipientPublicKey: replyPublicKey };
  });

  await relayClient.connect();
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  const port = parseInt(process.env.VAULT_PORT || String(DEFAULT_PORT), 10);

  const server = await buildServer();

  try {
    await server.listen({ port, host: HOST });
    server.log.info(`DCP Vault REST Server running at http://${HOST}:${port}`);
    server.log.info('SECURITY: Bound to localhost only');
    // Only start relay client if vault is initialized
    if (await storage.isProvisioned()) {
      try {
        await startRelayClient(server);
        if (relayConnected) {
          server.log.info('Relay client connected');
        } else {
          server.log.info('Relay client not connected (no relay_url configured)');
        }
      } catch (err) {
        server.log.error(err);
        server.log.error('Relay client failed to start');
      }
    } else {
      server.log.info('Vault not initialized - relay client will start after vault setup');
    }
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

// Handle shutdown
process.on('SIGINT', () => {
  process.stderr.write('Shutting down...\n');
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.stderr.write('Shutting down...\n');
  process.exit(0);
});

// Export for testing
export { buildServer };

// Start server if run directly (skip during tests)
if (process.env.VITEST !== 'true' && process.env.NODE_ENV !== 'test') {
  main();
}
