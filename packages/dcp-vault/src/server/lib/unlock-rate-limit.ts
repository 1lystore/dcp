/**
 * Unlock rate limiting — 5 failed passphrase attempts per minute → 5 minute lockout.
 * Self-contained, in-memory (localhost only). Extracted from the server module.
 */

import type { FastifyRequest } from 'fastify';

const UNLOCK_MAX_ATTEMPTS = 5;
const UNLOCK_WINDOW_MS = 60 * 1000; // 1 minute window
const UNLOCK_LOCKOUT_MS = 5 * 60 * 1000; // 5 minute lockout

interface UnlockAttemptTracker {
  attempts: number[];
  locked_until: number | null;
}

const unlockAttempts: Map<string, UnlockAttemptTracker> = new Map();

export function getUnlockRateLimitKey(request: FastifyRequest): string {
  // For localhost, we track by source port as a basic identifier
  // In production, this is always localhost so we use a single key
  return 'local';
}

export function checkUnlockRateLimit(key: string): { allowed: boolean; retry_after_seconds?: number } {
  const now = Date.now();
  let tracker = unlockAttempts.get(key);

  if (!tracker) {
    tracker = { attempts: [], locked_until: null };
    unlockAttempts.set(key, tracker);
  }

  // Check if currently locked out
  if (tracker.locked_until && now < tracker.locked_until) {
    const retry_after_seconds = Math.ceil((tracker.locked_until - now) / 1000);
    return { allowed: false, retry_after_seconds };
  }

  // Clear lockout if expired
  if (tracker.locked_until && now >= tracker.locked_until) {
    tracker.locked_until = null;
    tracker.attempts = [];
  }

  // Clean up old attempts outside the window
  const windowStart = now - UNLOCK_WINDOW_MS;
  tracker.attempts = tracker.attempts.filter((t) => t > windowStart);

  return { allowed: true };
}

export function recordUnlockFailure(key: string): { locked: boolean; retry_after_seconds?: number } {
  const now = Date.now();
  let tracker = unlockAttempts.get(key);

  if (!tracker) {
    tracker = { attempts: [], locked_until: null };
    unlockAttempts.set(key, tracker);
  }

  // Record this attempt
  tracker.attempts.push(now);

  // Clean up old attempts outside the window
  const windowStart = now - UNLOCK_WINDOW_MS;
  tracker.attempts = tracker.attempts.filter((t) => t > windowStart);

  // Check if we've exceeded the limit
  if (tracker.attempts.length >= UNLOCK_MAX_ATTEMPTS) {
    tracker.locked_until = now + UNLOCK_LOCKOUT_MS;
    const retry_after_seconds = Math.ceil(UNLOCK_LOCKOUT_MS / 1000);
    return { locked: true, retry_after_seconds };
  }

  return { locked: false };
}

export function clearUnlockRateLimit(key: string): void {
  unlockAttempts.delete(key);
}
