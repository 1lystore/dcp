/**
 * Tests for NonceStore Replay Protection
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { NonceStore } from '../src/policy/nonce-store.js';

describe('NonceStore', () => {
  let store: NonceStore;

  beforeEach(() => {
    store = new NonceStore();
  });

  afterEach(() => {
    store.destroy();
  });

  describe('add', () => {
    it('should accept new nonces', () => {
      const result = store.add('nonce1', 'agent1', Date.now());
      expect(result).toBe(true);
    });

    it('should reject duplicate nonces', () => {
      const now = Date.now();
      store.add('nonce1', 'agent1', now);
      const result = store.add('nonce1', 'agent1', now);
      expect(result).toBe(false);
    });

    it('should allow same nonce from different requesters', () => {
      const now = Date.now();
      expect(store.add('nonce1', 'agent1', now)).toBe(true);
      expect(store.add('nonce1', 'agent2', now)).toBe(true);
    });
  });

  describe('validateRequest', () => {
    it('should accept valid request', () => {
      expect(() => {
        store.validateRequest('agent1', 'nonce1', Date.now());
      }).not.toThrow();
    });

    it('should reject duplicate nonce', () => {
      const now = Date.now();
      store.validateRequest('agent1', 'nonce1', now);

      expect(() => {
        store.validateRequest('agent1', 'nonce1', now);
      }).toThrow('REPLAY_DETECTED');
    });

    it('should reject old timestamp', () => {
      const oldTimestamp = Date.now() - 60 * 1000; // 1 minute ago

      expect(() => {
        store.validateRequest('agent1', 'nonce1', oldTimestamp);
      }).toThrow('INVALID_TIMESTAMP');
    });

    it('should reject future timestamp', () => {
      const futureTimestamp = Date.now() + 60 * 1000; // 1 minute in future

      expect(() => {
        store.validateRequest('agent1', 'nonce1', futureTimestamp);
      }).toThrow('INVALID_TIMESTAMP');
    });

    it('should accept timestamp within drift tolerance', () => {
      const withinDrift = Date.now() - 25 * 1000; // 25 seconds ago (within 30s)

      expect(() => {
        store.validateRequest('agent1', 'nonce1', withinDrift);
      }).not.toThrow();
    });
  });

  describe('cleanup', () => {
    it('should remove expired nonces', () => {
      // Add a nonce with an already-expired timestamp
      const expiredTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
      store.add('expired-nonce', 'agent1', expiredTimestamp);

      expect(store.size()).toBe(1);
      store.cleanup();
      expect(store.size()).toBe(0);
    });

    it('should keep non-expired nonces', () => {
      store.add('fresh-nonce', 'agent1', Date.now());

      expect(store.size()).toBe(1);
      store.cleanup();
      expect(store.size()).toBe(1);
    });
  });

  describe('destroy', () => {
    it('should clear all nonces', () => {
      store.add('nonce1', 'agent1', Date.now());
      store.add('nonce2', 'agent1', Date.now());

      expect(store.size()).toBe(2);
      store.destroy();
      expect(store.size()).toBe(0);
    });
  });
});
