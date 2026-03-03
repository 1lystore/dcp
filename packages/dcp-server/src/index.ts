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
 * - POST /v1/vault/sign        - Sign transaction (with consent + budget)
 * - GET  /v1/vault/activity    - Get audit events
 * - POST /v1/vault/unlock      - Unlock vault (local only)
 * - POST /v1/vault/lock        - Lock vault (local only)
 * - POST /v1/vault/agents/:id/revoke - Revoke specific session
 */

import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import {
  VaultStorage,
  BudgetEngine,
  getStorage,
  getBudgetEngine,
  VaultError,
  Chain,
  AuditEventType,
  envelopeDecrypt,
  signTransaction,
} from '@dcprotocol/core';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import keytar from 'keytar';

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

  // CORS for browser UI access
  await server.register(cors, {
    origin: true, // Allow all origins (localhost only anyway)
    methods: ['GET', 'POST', 'DELETE'],
  });

  // Initialize vault storage (respects VAULT_DIR env for testing)
  const vaultDir = process.env.VAULT_DIR;
  storage = getStorage(vaultDir);
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
    return {
      status: 'ok',
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
            </div>
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

    // Try to reuse an existing active session by agent + scope
    if (!effectiveSessionId) {
      const existing = findActiveSessionForScope(agent_name, scope);
      if (existing) {
        effectiveSessionId = existing;
      }
    }

    // Check for valid session
    let hasSession = false;
    if (effectiveSessionId) {
      const session = storage.getSession(effectiveSessionId);
      if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
        if (session.granted_scopes.includes(scope) || session.granted_scopes.some(s => scope.startsWith(s.replace('.*', '')))) {
          hasSession = true;
          storage.touchSession(effectiveSessionId);
        }
      }
    }

    // If no valid session, create pending consent
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
// Main
// ============================================================================

async function main() {
  const port = parseInt(process.env.VAULT_PORT || String(DEFAULT_PORT), 10);

  const server = await buildServer();

  try {
    await server.listen({ port, host: HOST });
    server.log.info(`DCP Vault REST Server running at http://${HOST}:${port}`);
    server.log.info('SECURITY: Bound to localhost only');
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
