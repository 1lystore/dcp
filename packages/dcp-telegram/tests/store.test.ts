/**
 * Tests for rate limiting and deduplication stores
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { RateLimiter, DeduplicationStore, NonceStore, TelegramStore } from '../src/store.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter();
  });

  afterEach(() => {
    limiter.close();
  });

  it('should not limit initially', () => {
    expect(limiter.isLimited('chat123', 30)).toBe(false);
  });

  it('should track notifications correctly', () => {
    const chatId = 'chat123';
    const limit = 5;

    for (let i = 0; i < limit; i++) {
      expect(limiter.isLimited(chatId, limit)).toBe(false);
      limiter.record(chatId, limit);
    }

    // Now should be limited
    expect(limiter.isLimited(chatId, limit)).toBe(true);
  });

  it('should track remaining notifications', () => {
    const chatId = 'chat123';
    const limit = 10;

    expect(limiter.getRemaining(chatId, limit)).toBe(10);

    limiter.record(chatId, limit);
    limiter.record(chatId, limit);
    limiter.record(chatId, limit);

    expect(limiter.getRemaining(chatId, limit)).toBe(7);
  });

  it('should track different chats independently', () => {
    const limit = 3;

    // Fill up chat1
    for (let i = 0; i < limit; i++) {
      limiter.record('chat1', limit);
    }

    expect(limiter.isLimited('chat1', limit)).toBe(true);
    expect(limiter.isLimited('chat2', limit)).toBe(false);
  });

  it('should return reset time', () => {
    const chatId = 'chat123';
    limiter.record(chatId, 10);

    const resetTime = limiter.getResetTime(chatId);
    expect(resetTime).toBeGreaterThan(0);
    expect(resetTime).toBeLessThanOrEqual(60 * 60 * 1000); // 1 hour
  });

  it('should provide stats', () => {
    limiter.record('chat1', 1);
    limiter.record('chat2', 10);

    const stats = limiter.getStats();
    expect(stats.totalChats).toBe(2);
    expect(stats.limitedChats).toBe(1); // chat1 is limited (1/1)
  });
});

describe('DeduplicationStore', () => {
  let dedup: DeduplicationStore;

  beforeEach(() => {
    dedup = new DeduplicationStore();
  });

  afterEach(() => {
    dedup.close();
  });

  it('should not mark unseen consent as duplicate', () => {
    expect(dedup.isDuplicate('consent_123')).toBe(false);
  });

  it('should mark seen consent as duplicate', () => {
    const consentId = 'consent_123';
    dedup.markSeen(consentId);
    expect(dedup.isDuplicate(consentId)).toBe(true);
  });

  it('should track different consents independently', () => {
    dedup.markSeen('consent_1');

    expect(dedup.isDuplicate('consent_1')).toBe(true);
    expect(dedup.isDuplicate('consent_2')).toBe(false);
  });

  it('should provide stats', () => {
    dedup.markSeen('consent_1');
    dedup.markSeen('consent_2');
    dedup.markSeen('consent_3');

    const stats = dedup.getStats();
    expect(stats.trackedConsents).toBe(3);
  });
});

describe('NonceStore', () => {
  let nonceStore: NonceStore;

  beforeEach(() => {
    nonceStore = new NonceStore();
  });

  afterEach(() => {
    nonceStore.close();
  });

  it('should accept valid nonce with current timestamp', () => {
    const nonce = 'unique-nonce-123';
    const timestamp = new Date().toISOString();

    expect(nonceStore.checkAndMark(nonce, timestamp)).toBe(true);
  });

  it('should reject duplicate nonce', () => {
    const nonce = 'unique-nonce-123';
    const timestamp = new Date().toISOString();

    expect(nonceStore.checkAndMark(nonce, timestamp)).toBe(true);
    expect(nonceStore.checkAndMark(nonce, timestamp)).toBe(false); // Replay
  });

  it('should reject expired timestamp', () => {
    const nonce = 'unique-nonce-123';
    // 10 minutes ago (beyond 5 minute clock skew)
    const timestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();

    expect(nonceStore.checkAndMark(nonce, timestamp)).toBe(false);
  });

  it('should reject future timestamp beyond clock skew', () => {
    const nonce = 'unique-nonce-123';
    // 10 minutes in future
    const timestamp = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    expect(nonceStore.checkAndMark(nonce, timestamp)).toBe(false);
  });

  it('should accept timestamp within clock skew', () => {
    const nonce = 'unique-nonce-123';
    // 2 minutes ago (within 5 minute skew)
    const timestamp = new Date(Date.now() - 2 * 60 * 1000).toISOString();

    expect(nonceStore.checkAndMark(nonce, timestamp)).toBe(true);
  });
});

describe('TelegramStore', () => {
  let store: TelegramStore;

  beforeEach(() => {
    store = new TelegramStore();
  });

  afterEach(() => {
    store.close();
  });

  it('should combine all stores', () => {
    expect(store.approvals).toBeDefined();
    expect(store.rateLimiter).toBeDefined();
    expect(store.deduplication).toBeDefined();
    expect(store.nonceStore).toBeDefined();
  });

  it('should provide combined stats', () => {
    store.rateLimiter.record('chat1', 10);
    store.deduplication.markSeen('consent_1');

    const stats = store.getStats();
    expect(stats.approvals.pendingApprovals).toBe(0);
    expect(stats.rateLimit.totalChats).toBe(1);
    expect(stats.deduplication.trackedConsents).toBe(1);
  });

  it('should close all stores', () => {
    store.close();
    // Should not throw when closed twice
    store.close();
  });
});

describe('ApprovalCommandStore', () => {
  let dataDir: string;
  let store: TelegramStore;

  beforeEach(() => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dcp-telegram-test-'));
    store = new TelegramStore(dataDir);
  });

  afterEach(() => {
    store.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it('should create and list pending approval commands for a vault', () => {
    const command = store.approvals.createApprovalCommand(
      'vault_123',
      'chat_123',
      'consent_123',
      'approve',
      'vault_123' // pairing_id
    );

    const pending = store.approvals.getPendingApprovals('vault_123');
    expect(pending).toHaveLength(1);
    expect(pending[0].id).toBe(command.id);
    expect(pending[0].consent_id).toBe('consent_123');
    expect(pending[0].action).toBe('approve');
    expect(pending[0].pairing_id).toBe('vault_123');
    expect(pending[0].service_signature).toBeTruthy();
    expect(pending[0].expires_at).toBeTruthy();
  });

  it('should isolate approval commands by vault', () => {
    store.approvals.createApprovalCommand('vault_1', 'chat_1', 'consent_1', 'approve', 'vault_1');
    store.approvals.createApprovalCommand('vault_2', 'chat_2', 'consent_2', 'deny', 'vault_2');

    expect(store.approvals.getPendingApprovals('vault_1')).toHaveLength(1);
    expect(store.approvals.getPendingApprovals('vault_2')).toHaveLength(1);
    expect(store.approvals.getPendingApprovals('vault_missing')).toHaveLength(0);
  });

  it('should mark approval commands as processed', () => {
    const command = store.approvals.createApprovalCommand(
      'vault_123',
      'chat_123',
      'consent_123',
      'deny',
      'vault_123' // pairing_id
    );

    const processed = store.approvals.markApprovalProcessed(command.id, 'success');
    expect(processed?.processed_at).toBeTruthy();
    expect(processed?.result).toBe('success');
    expect(store.approvals.getPendingApprovals('vault_123')).toHaveLength(0);
  });
});

describe('Rate Limit Window Reset', () => {
  it('should reset window after expiration', () => {
    vi.useFakeTimers();

    const limiter = new RateLimiter();
    const chatId = 'chat123';
    const limit = 3;

    // Fill up limit
    for (let i = 0; i < limit; i++) {
      limiter.record(chatId, limit);
    }
    expect(limiter.isLimited(chatId, limit)).toBe(true);

    // Advance time past window (1 hour + 1ms)
    vi.advanceTimersByTime(60 * 60 * 1000 + 1);

    // Should be reset
    expect(limiter.isLimited(chatId, limit)).toBe(false);
    expect(limiter.getRemaining(chatId, limit)).toBe(limit);

    limiter.close();
    vi.useRealTimers();
  });
});
