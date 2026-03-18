/**
 * Tests for DCP Relay
 *
 * Tests message store, connection store, and relay server functionality
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MessageStore, ConnectionStore, RateLimiter } from '../src/store.js';
import { RelayServer } from '../src/relay.js';
import type { RelayEnvelope, RelayResponseEnvelope } from '../src/types.js';
import { RelayError, RELAY_VERSION } from '../src/types.js';

// ============================================================================
// Test Helpers
// ============================================================================

function createTestEnvelope(overrides: Partial<RelayEnvelope> = {}): RelayEnvelope {
  return {
    version: RELAY_VERSION,
    vault_id: 'vault_test123',
    request_id: `req_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    action_type: 'sign',
    encrypted_payload: 'base64_encrypted_data_here',
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    ...overrides,
  };
}

function createTestResponse(requestId: string): RelayResponseEnvelope {
  return {
    version: RELAY_VERSION,
    request_id: requestId,
    encrypted_payload: 'base64_encrypted_response_here',
    timestamp: new Date().toISOString(),
  };
}

// ============================================================================
// MessageStore Tests
// ============================================================================

describe('MessageStore', () => {
  let store: MessageStore;

  beforeEach(() => {
    store = new MessageStore({ messageTtlMs: 60000, maxPendingMessages: 10 });
  });

  afterEach(() => {
    store.close();
  });

  describe('storeMessage', () => {
    it('should store a message successfully', () => {
      const envelope = createTestEnvelope();
      store.storeMessage(envelope);

      const stored = store.getMessage(envelope.request_id);
      expect(stored).toBeDefined();
      expect(stored?.envelope.request_id).toBe(envelope.request_id);
      expect(stored?.delivered).toBe(false);
    });

    it('should reject duplicate request_id (idempotency)', () => {
      const envelope = createTestEnvelope();
      store.storeMessage(envelope);

      expect(() => store.storeMessage(envelope)).toThrow(RelayError);
      expect(() => store.storeMessage(envelope)).toThrow(/Duplicate request_id/);
    });

    it('should track messages per vault', () => {
      const envelope1 = createTestEnvelope({ vault_id: 'vault_a' });
      const envelope2 = createTestEnvelope({ vault_id: 'vault_a' });
      const envelope3 = createTestEnvelope({ vault_id: 'vault_b' });

      store.storeMessage(envelope1);
      store.storeMessage(envelope2);
      store.storeMessage(envelope3);

      const vaultAMessages = store.getPendingMessages('vault_a');
      const vaultBMessages = store.getPendingMessages('vault_b');

      expect(vaultAMessages.length).toBe(2);
      expect(vaultBMessages.length).toBe(1);
    });

    it('should prune oldest messages when limit reached', () => {
      // Store 10 messages (at limit)
      const envelopes: RelayEnvelope[] = [];
      for (let i = 0; i < 10; i++) {
        const envelope = createTestEnvelope({ vault_id: 'vault_full' });
        store.storeMessage(envelope);
        envelopes.push(envelope);
      }

      // Store one more - should prune oldest
      const newEnvelope = createTestEnvelope({ vault_id: 'vault_full' });
      store.storeMessage(newEnvelope);

      // First envelope should be pruned
      const stored = store.getMessage(envelopes[0].request_id);
      expect(stored).toBeUndefined();

      // New envelope should exist
      const newStored = store.getMessage(newEnvelope.request_id);
      expect(newStored).toBeDefined();
    });
  });

  describe('getPendingMessages', () => {
    it('should return only undelivered messages', () => {
      const envelope1 = createTestEnvelope({ vault_id: 'vault_x' });
      const envelope2 = createTestEnvelope({ vault_id: 'vault_x' });

      store.storeMessage(envelope1);
      store.storeMessage(envelope2);
      store.markDelivered(envelope1.request_id);

      const pending = store.getPendingMessages('vault_x');
      expect(pending.length).toBe(1);
      expect(pending[0].request_id).toBe(envelope2.request_id);
    });

    it('should return empty array for unknown vault', () => {
      const pending = store.getPendingMessages('vault_unknown');
      expect(pending).toEqual([]);
    });

    it('should filter out expired messages', () => {
      const expiredEnvelope = createTestEnvelope({
        vault_id: 'vault_expire',
        expires_at: new Date(Date.now() - 1000).toISOString(), // Already expired
      });

      // Manually add expired message
      const storeAny = store as unknown as {
        messages: Map<string, unknown>;
        requestIdIndex: Map<string, string>;
        vaultMessages: Map<string, Set<string>>;
      };
      const key = `vault_expire:${expiredEnvelope.request_id}`;
      storeAny.messages.set(key, {
        envelope: expiredEnvelope,
        received_at: Date.now() - 10000,
        delivered: false,
      });
      storeAny.requestIdIndex.set(expiredEnvelope.request_id, key);
      storeAny.vaultMessages.set('vault_expire', new Set([key]));

      const pending = store.getPendingMessages('vault_expire');
      expect(pending.length).toBe(0);
    });
  });

  describe('markDelivered', () => {
    it('should mark message as delivered', () => {
      const envelope = createTestEnvelope();
      store.storeMessage(envelope);

      const result = store.markDelivered(envelope.request_id);
      expect(result).toBe(true);

      const stored = store.getMessage(envelope.request_id);
      expect(stored?.delivered).toBe(true);
    });

    it('should return false for unknown request_id', () => {
      const result = store.markDelivered('req_unknown');
      expect(result).toBe(false);
    });
  });

  describe('storeResponse', () => {
    it('should store response for existing request', () => {
      const envelope = createTestEnvelope();
      store.storeMessage(envelope);

      const response = createTestResponse(envelope.request_id);
      const result = store.storeResponse(envelope.request_id, response);
      expect(result).toBe(true);

      const storedResponse = store.getResponse(envelope.request_id);
      expect(storedResponse).toEqual(response);
    });

    it('should return false for unknown request', () => {
      const response = createTestResponse('req_unknown');
      const result = store.storeResponse('req_unknown', response);
      expect(result).toBe(false);
    });
  });

  describe('hasRequest', () => {
    it('should return true for existing request', () => {
      const envelope = createTestEnvelope();
      store.storeMessage(envelope);

      expect(store.hasRequest(envelope.request_id)).toBe(true);
    });

    it('should return false for unknown request', () => {
      expect(store.hasRequest('req_unknown')).toBe(false);
    });
  });

  describe('clearVault', () => {
    it('should remove all messages for a vault', () => {
      const envelope1 = createTestEnvelope({ vault_id: 'vault_clear' });
      const envelope2 = createTestEnvelope({ vault_id: 'vault_clear' });
      const envelope3 = createTestEnvelope({ vault_id: 'vault_keep' });

      store.storeMessage(envelope1);
      store.storeMessage(envelope2);
      store.storeMessage(envelope3);

      store.clearVault('vault_clear');

      expect(store.getMessage(envelope1.request_id)).toBeUndefined();
      expect(store.getMessage(envelope2.request_id)).toBeUndefined();
      expect(store.getMessage(envelope3.request_id)).toBeDefined();
    });
  });

  describe('getStats', () => {
    it('should return correct statistics', () => {
      const envelope1 = createTestEnvelope();
      const envelope2 = createTestEnvelope();

      store.storeMessage(envelope1);
      store.storeMessage(envelope2);
      store.markDelivered(envelope1.request_id);

      const stats = store.getStats();
      expect(stats.totalMessages).toBe(2);
      expect(stats.pendingMessages).toBe(1);
      expect(stats.deliveredMessages).toBe(1);
      expect(stats.vaultCount).toBe(1);
    });
  });
});

// ============================================================================
// ConnectionStore Tests
// ============================================================================

describe('ConnectionStore', () => {
  let store: ConnectionStore;

  beforeEach(() => {
    store = new ConnectionStore();
  });

  describe('register/unregister', () => {
    it('should register a vault connection', () => {
      store.register('vault_1', 'public_key_abc');

      expect(store.isConnected('vault_1')).toBe(true);
      const conn = store.get('vault_1');
      expect(conn?.public_key).toBe('public_key_abc');
    });

    it('should unregister a vault connection', () => {
      store.register('vault_1', 'public_key_abc');
      store.unregister('vault_1');

      expect(store.isConnected('vault_1')).toBe(false);
    });
  });

  describe('updateHeartbeat', () => {
    it('should update heartbeat timestamp', () => {
      store.register('vault_1', 'key');
      const conn1 = store.get('vault_1');
      const initialHeartbeat = conn1?.last_heartbeat;

      // Wait a bit
      const start = Date.now();
      while (Date.now() - start < 10) {
        // busy wait
      }

      store.updateHeartbeat('vault_1');
      const conn2 = store.get('vault_1');

      expect(conn2?.last_heartbeat).toBeGreaterThanOrEqual(initialHeartbeat!);
    });

    it('should return false for unknown vault', () => {
      expect(store.updateHeartbeat('unknown')).toBe(false);
    });
  });

  describe('removeStale', () => {
    it('should remove connections without heartbeat', () => {
      store.register('vault_stale', 'key');

      // Manually set old heartbeat
      const conn = store.get('vault_stale');
      if (conn) {
        conn.last_heartbeat = Date.now() - 100000; // 100 seconds ago
      }

      const removed = store.removeStale(30000); // 30 second interval
      expect(removed).toContain('vault_stale');
      expect(store.isConnected('vault_stale')).toBe(false);
    });

    it('should keep recent connections', () => {
      store.register('vault_recent', 'key');

      const removed = store.removeStale(30000);
      expect(removed).not.toContain('vault_recent');
      expect(store.isConnected('vault_recent')).toBe(true);
    });
  });

  describe('getConnectedVaults', () => {
    it('should return all connected vault IDs', () => {
      store.register('vault_1', 'key1');
      store.register('vault_2', 'key2');
      store.register('vault_3', 'key3');

      const vaults = store.getConnectedVaults();
      expect(vaults.sort()).toEqual(['vault_1', 'vault_2', 'vault_3']);
    });
  });
});

// ============================================================================
// RateLimiter Tests (PRD Section C3)
// ============================================================================

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    // Use small limits for testing: 5 req per 1 second
    limiter = new RateLimiter(5, 1000);
  });

  afterEach(() => {
    limiter.close();
  });

  describe('checkLimit', () => {
    it('should allow requests under limit', () => {
      expect(limiter.checkLimit('vault_a')).toBe(true);
      expect(limiter.checkLimit('vault_a')).toBe(true);
      expect(limiter.checkLimit('vault_a')).toBe(true);
    });

    it('should reject requests over limit', () => {
      // Use all 5 requests
      for (let i = 0; i < 5; i++) {
        expect(limiter.checkLimit('vault_b')).toBe(true);
      }

      // 6th request should be rejected
      expect(limiter.checkLimit('vault_b')).toBe(false);
    });

    it('should track limits per vault independently', () => {
      // Use up vault_c's limit
      for (let i = 0; i < 5; i++) {
        limiter.checkLimit('vault_c');
      }
      expect(limiter.checkLimit('vault_c')).toBe(false);

      // vault_d should still have full quota
      expect(limiter.checkLimit('vault_d')).toBe(true);
      expect(limiter.getCount('vault_d')).toBe(1);
    });

    it('should reset after window expires', async () => {
      // Use up limit
      for (let i = 0; i < 5; i++) {
        limiter.checkLimit('vault_e');
      }
      expect(limiter.checkLimit('vault_e')).toBe(false);

      // Wait for window to expire (1 second + buffer)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Should be allowed again
      expect(limiter.checkLimit('vault_e')).toBe(true);
    });
  });

  describe('getCount', () => {
    it('should return current request count', () => {
      expect(limiter.getCount('vault_f')).toBe(0);

      limiter.checkLimit('vault_f');
      expect(limiter.getCount('vault_f')).toBe(1);

      limiter.checkLimit('vault_f');
      limiter.checkLimit('vault_f');
      expect(limiter.getCount('vault_f')).toBe(3);
    });
  });

  describe('getRemaining', () => {
    it('should return remaining requests', () => {
      expect(limiter.getRemaining('vault_g')).toBe(5);

      limiter.checkLimit('vault_g');
      limiter.checkLimit('vault_g');
      expect(limiter.getRemaining('vault_g')).toBe(3);

      // Use all
      for (let i = 0; i < 3; i++) {
        limiter.checkLimit('vault_g');
      }
      expect(limiter.getRemaining('vault_g')).toBe(0);
    });
  });

  describe('reset', () => {
    it('should reset rate limit for a vault', () => {
      // Use some quota
      for (let i = 0; i < 3; i++) {
        limiter.checkLimit('vault_h');
      }
      expect(limiter.getRemaining('vault_h')).toBe(2);

      limiter.reset('vault_h');
      expect(limiter.getRemaining('vault_h')).toBe(5);
    });
  });

  describe('getStats', () => {
    it('should return limiter statistics', () => {
      limiter.checkLimit('vault_i');
      limiter.checkLimit('vault_j');

      const stats = limiter.getStats();
      expect(stats.trackedVaults).toBe(2);
      expect(stats.maxRequests).toBe(5);
      expect(stats.windowMs).toBe(1000);
    });
  });
});

// ============================================================================
// RelayServer Integration Tests
// ============================================================================

describe('RelayServer', () => {
  let server: RelayServer;
  let testPort: number;

  beforeEach(async () => {
    // Use unique port for each test to avoid EADDRINUSE
    testPort = 18421 + Math.floor(Math.random() * 10000);
    server = new RelayServer({
      port: testPort,
      host: '127.0.0.1',
      debug: false,
      enableLongPoll: true,
    });
    await server.start();
  });

  afterEach(async () => {
    await server.stop();
    // Small delay to ensure port is released
    await new Promise((resolve) => setTimeout(resolve, 50));
  });

  describe('Health endpoint', () => {
    it('should return health status', async () => {
      const response = await fetch(`http://127.0.0.1:${testPort}/health`);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.status).toBe('ok');
      expect(data.version).toBe(RELAY_VERSION);
    });
  });

  describe('Stats endpoint', () => {
    it('should return relay statistics', async () => {
      const response = await fetch(`http://127.0.0.1:${testPort}/stats`);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.totalMessages).toBeDefined();
      expect(data.connectedVaults).toBeDefined();
    });
  });

  describe('Request endpoint', () => {
    it('should reject request for unconnected vault', async () => {
      const envelope = createTestEnvelope({ vault_id: 'vault_not_connected' });

      const response = await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      expect(response.status).toBe(503);
      const data = await response.json();
      expect(data.error.code).toBe('RELAY_VAULT_NOT_CONNECTED');
    });

    it('should reject invalid envelope', async () => {
      const response = await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version: '1' }), // Missing required fields
      });

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data.error.code).toBe('RELAY_INVALID_ENVELOPE');
    });

    it('should reject expired message', async () => {
      // First register a vault via connection store
      server.getConnectionStore().register('vault_expired', 'key');

      const envelope = createTestEnvelope({
        vault_id: 'vault_expired',
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });

      const response = await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data.error.code).toBe('RELAY_MESSAGE_EXPIRED');
    });

    it('should accept valid request for connected vault', async () => {
      // Register vault
      server.getConnectionStore().register('vault_connected', 'key');

      const envelope = createTestEnvelope({ vault_id: 'vault_connected' });

      const response = await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      expect(response.status).toBe(202);
      const data = await response.json();
      expect(data.accepted).toBe(true);
      expect(data.request_id).toBe(envelope.request_id);
    });

    it('should reject request without pairing token when required', async () => {
      const authPort = 18421 + Math.floor(Math.random() * 10000);
      const authServer = new RelayServer({
        port: authPort,
        host: '127.0.0.1',
        debug: false,
        enableLongPoll: true,
        authConfig: { requirePairingToken: true },
      });
      await authServer.start();

      authServer.getConnectionStore().register('vault_auth', 'key');

      const envelope = createTestEnvelope({ vault_id: 'vault_auth' });
      const response = await fetch(`http://127.0.0.1:${authPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.error.code).toBe('RELAY_UNAUTHORIZED');

      await authServer.stop();
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
  });

  describe('Response endpoint', () => {
    it('should return 404 for unknown request', async () => {
      const response = await fetch(
        `http://127.0.0.1:${testPort}/relay/response/req_unknown`
      );

      expect(response.status).toBe(404);
    });

    it('should return pending status for unprocessed request', async () => {
      // Register vault and submit request
      server.getConnectionStore().register('vault_pending', 'key');
      const envelope = createTestEnvelope({ vault_id: 'vault_pending' });

      await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      const response = await fetch(
        `http://127.0.0.1:${testPort}/relay/response/${envelope.request_id}`
      );

      expect(response.status).toBe(202);
      const data = await response.json();
      expect(data.pending).toBe(true);
    });

    it('should return response when available', async () => {
      // Register vault and submit request
      server.getConnectionStore().register('vault_response', 'key');
      const envelope = createTestEnvelope({ vault_id: 'vault_response' });

      await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      // Store response directly
      const responseEnvelope = createTestResponse(envelope.request_id);
      server.getMessageStore().storeResponse(envelope.request_id, responseEnvelope);

      const response = await fetch(
        `http://127.0.0.1:${testPort}/relay/response/${envelope.request_id}`
      );

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.request_id).toBe(envelope.request_id);
      expect(data.encrypted_payload).toBe(responseEnvelope.encrypted_payload);
    });
  });

  describe('Idempotency', () => {
    it('should return cached response for duplicate request', async () => {
      server.getConnectionStore().register('vault_idempotent', 'key');
      const envelope = createTestEnvelope({ vault_id: 'vault_idempotent' });

      // First request
      await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      // Store response
      const responseEnvelope = createTestResponse(envelope.request_id);
      server.getMessageStore().storeResponse(envelope.request_id, responseEnvelope);

      // Duplicate request - should return cached response
      const response = await fetch(`http://127.0.0.1:${testPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.request_id).toBe(envelope.request_id);
    });
  });
});

// ============================================================================
// RelayError Tests
// ============================================================================

describe('Rate Limiting Integration', () => {
  it('should rate limit requests per vault', async () => {
    // Create server with low rate limit for testing
    const rateLimitPort = 18421 + Math.floor(Math.random() * 10000);
    const rateLimitServer = new RelayServer({
      port: rateLimitPort,
      host: '127.0.0.1',
      debug: false,
      enableLongPoll: true,
      rateLimitPerMinute: 3,
      rateLimitWindowMs: 60000,
    });
    await rateLimitServer.start();

    rateLimitServer.getConnectionStore().register('vault_ratelimit', 'key');

    // Send 3 requests (should all succeed)
    for (let i = 0; i < 3; i++) {
      const envelope = createTestEnvelope({ vault_id: 'vault_ratelimit' });
      const response = await fetch(`http://127.0.0.1:${rateLimitPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });
      expect(response.status).toBe(202);
    }

    // 4th request should be rate limited
    const envelope = createTestEnvelope({ vault_id: 'vault_ratelimit' });
    const response = await fetch(`http://127.0.0.1:${rateLimitPort}/relay/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    expect(response.status).toBe(429);
    const data = await response.json();
    expect(data.error.code).toBe('RELAY_RATE_LIMITED');

    // Check rate limit headers
    expect(response.headers.get('X-RateLimit-Limit')).toBe('3');
    expect(response.headers.get('X-RateLimit-Remaining')).toBe('0');
    expect(response.headers.get('Retry-After')).toBeDefined();

    await rateLimitServer.stop();
    await new Promise((resolve) => setTimeout(resolve, 50));
  });

  it('should track rate limits independently per vault', async () => {
    const rateLimitPort = 18421 + Math.floor(Math.random() * 10000);
    const rateLimitServer = new RelayServer({
      port: rateLimitPort,
      host: '127.0.0.1',
      debug: false,
      enableLongPoll: true,
      rateLimitPerMinute: 2,
      rateLimitWindowMs: 60000,
    });
    await rateLimitServer.start();

    rateLimitServer.getConnectionStore().register('vault_a', 'key');
    rateLimitServer.getConnectionStore().register('vault_b', 'key');

    // Exhaust vault_a's limit
    for (let i = 0; i < 2; i++) {
      const envelope = createTestEnvelope({ vault_id: 'vault_a' });
      await fetch(`http://127.0.0.1:${rateLimitPort}/relay/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      });
    }

    // vault_a should be rate limited
    const envelopeA = createTestEnvelope({ vault_id: 'vault_a' });
    const responseA = await fetch(`http://127.0.0.1:${rateLimitPort}/relay/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelopeA),
    });
    expect(responseA.status).toBe(429);

    // vault_b should still work
    const envelopeB = createTestEnvelope({ vault_id: 'vault_b' });
    const responseB = await fetch(`http://127.0.0.1:${rateLimitPort}/relay/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelopeB),
    });
    expect(responseB.status).toBe(202);

    await rateLimitServer.stop();
    await new Promise((resolve) => setTimeout(resolve, 50));
  });
});

describe('Metrics Endpoint', () => {
  let server: RelayServer;
  let testPort: number;

  beforeEach(async () => {
    testPort = 18421 + Math.floor(Math.random() * 10000);
    server = new RelayServer({
      port: testPort,
      host: '127.0.0.1',
      debug: false,
      enableLongPoll: true,
    });
    await server.start();
  });

  afterEach(async () => {
    await server.stop();
    await new Promise((resolve) => setTimeout(resolve, 50));
  });

  it('should return JSON metrics by default', async () => {
    const response = await fetch(`http://127.0.0.1:${testPort}/metrics`);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.messages).toBeDefined();
    expect(data.connections).toBeDefined();
    expect(data.rateLimit).toBeDefined();
    expect(data.websockets).toBeDefined();
    expect(data.config).toBeDefined();
    expect(data.uptime).toBeDefined();
  });

  it('should return Prometheus format when requested', async () => {
    const response = await fetch(`http://127.0.0.1:${testPort}/metrics?format=prometheus`);
    const text = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toContain('text/plain');
    expect(text).toContain('dcp_relay_messages_total');
    expect(text).toContain('dcp_relay_vaults_connected');
    expect(text).toContain('dcp_relay_rate_limit_max');
  });
});

// ============================================================================
// RelayError Tests
// ============================================================================

describe('RelayError', () => {
  it('should create error with correct properties', () => {
    const error = new RelayError('RELAY_TIMEOUT', 'Request timed out', { ms: 5000 });

    expect(error.code).toBe('RELAY_TIMEOUT');
    expect(error.message).toBe('Request timed out');
    expect(error.details?.ms).toBe(5000);
    expect(error.name).toBe('RelayError');
  });

  it('should serialize to JSON correctly', () => {
    const error = new RelayError('RELAY_UNAVAILABLE', 'Service unavailable');
    const json = error.toJSON();

    expect(json.error.code).toBe('RELAY_UNAVAILABLE');
    expect(json.error.message).toBe('Service unavailable');
  });
});
