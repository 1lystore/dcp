/**
 * Nonce Store for Replay Protection
 *
 * Prevents replay attacks by tracking used nonces.
 * Each nonce is tied to a requester ID and expires after TTL.
 */

const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_TIMESTAMP_DRIFT_MS = 30 * 1000; // 30 seconds
const CLEANUP_INTERVAL_MS = 60 * 1000; // 1 minute

interface NonceEntry {
  expiresAt: number;
  requesterId: string;
}

export class NonceStore {
  private nonces = new Map<string, NonceEntry>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.startCleanup();
  }

  /**
   * Add a nonce to the store
   * @returns true if nonce was added (new), false if duplicate
   */
  add(nonce: string, requesterId: string, timestamp: number): boolean {
    const key = `${requesterId}:${nonce}`;

    if (this.has(key)) {
      return false; // Duplicate - replay detected
    }

    const expiresAt = timestamp + NONCE_TTL_MS;
    this.nonces.set(key, { expiresAt, requesterId });
    return true;
  }

  /**
   * Check if nonce exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.nonces.get(key);
    if (!entry) return false;

    if (Date.now() > entry.expiresAt) {
      this.nonces.delete(key);
      return false;
    }
    return true;
  }

  /**
   * Validate request timestamp and nonce
   * @throws Error if validation fails
   */
  validateRequest(requesterId: string, nonce: string, timestamp: number): void {
    const now = Date.now();

    // Check timestamp freshness
    if (Math.abs(now - timestamp) > MAX_TIMESTAMP_DRIFT_MS) {
      throw new Error('INVALID_TIMESTAMP: Request timestamp too old or too far in future');
    }

    // Check nonce uniqueness
    if (!this.add(nonce, requesterId, timestamp)) {
      throw new Error('REPLAY_DETECTED: Duplicate nonce - request already processed');
    }
  }

  /**
   * Cleanup expired nonces
   */
  cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.nonces) {
      if (now > entry.expiresAt) {
        this.nonces.delete(key);
      }
    }
  }

  /**
   * Get the number of active nonces (for testing/monitoring)
   */
  size(): number {
    return this.nonces.size;
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  /**
   * Stop the cleanup timer and clear all nonces
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.nonces.clear();
  }
}

// Singleton instance for the vault
export const nonceStore = new NonceStore();
