import { TokenValidationResult } from './types';

/**
 * Cache for validated tokens to reduce server calls.
 *
 * Stores validation results with expiration. When a token is accessed,
 * the cache automatically evicts expired entries.
 *
 * Useful for reducing load on the HashGuard server by caching the results
 * of recent token validations.
 */
export class TokenCache {
  private cache: Map<string, CacheEntry> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  /**
   * Creates a new token cache.
   *
   * @param maxEntries - Maximum number of entries to keep (default: 1000).
   * @param ttlMs - Time-to-live for cache entries in milliseconds (default: 300_000 = 5 min).
   * @param autoCleanupMs - Interval for automatic cleanup in milliseconds (default: 60_000 = 1 min).
   *                        Pass null to disable auto-cleanup.
   */
  constructor(
    private readonly maxEntries: number = 1000,
    private readonly ttlMs: number = 300_000,
    autoCleanupMs: number | null = 60_000
  ) {
    if (autoCleanupMs && typeof autoCleanupMs === 'number') {
      this.cleanupInterval = setInterval(() => this.cleanup(), autoCleanupMs);
      // Allow background cleanup not to keep process alive
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref();
      }
    }
  }

  /**
   * Stores a validation result in the cache.
   *
   * @param token - The proof token (used as cache key).
   * @param result - The validation result to cache.
   */
  set(token: string, result: TokenValidationResult): void {
    if (this.cache.size >= this.maxEntries) {
      // Evict oldest entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(token, {
      result,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Retrieves a validation result from the cache.
   *
   * @param token - The proof token to look up.
   * @returns Cached validation result if found and not expired, undefined otherwise.
   */
  get(token: string): TokenValidationResult | undefined {
    const entry = this.cache.get(token);
    if (!entry) {
      return undefined;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(token);
      return undefined;
    }

    return entry.result;
  }

  /**
   * Checks if a token is in the cache.
   *
   * @param token - The proof token.
   * @returns true if the token is cached and not expired.
   */
  has(token: string): boolean {
    return this.get(token) !== undefined;
  }

  /**
   * Removes a token from the cache.
   *
   * @param token - The proof token.
   */
  delete(token: string): void {
    this.cache.delete(token);
  }

  /**
   * Clears all cached entries.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Returns the number of entries currently in the cache.
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Removes expired entries from the cache.
   *
   * @returns Number of entries removed.
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [token, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(token);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Stops the auto-cleanup interval.
   *
   * Call this when disposing of the cache to avoid keeping the process alive.
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.clear();
  }
}

interface CacheEntry {
  result: TokenValidationResult;
  expiresAt: number;
}
