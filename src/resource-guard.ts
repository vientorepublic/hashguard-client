import {
  ResourceAccessOptions,
  ResourceAccessResult,
  TokenValidationResult,
} from './types';
import { TokenValidator } from './token-validator';
import { TokenCache } from './token-cache';

/**
 * Server-side resource access guard using proof tokens.
 *
 * This class provides a high-level API for protecting resources behind
 * proof-of-work verification. It combines token validation, caching,
 * and optional context matching.
 *
 * Typical usage in a server:
 * ```ts
 * const guard = new ResourceGuard(client);
 *
 * // In a request handler:
 * const result = await guard.checkAccess(req.body.proofToken, {
 *   context: 'api_rate_limit',
 *   consume: true,
 * });
 *
 * if (!result.allowed) {
 *   return res.status(403).json({ error: result.reason });
 * }
 * ```
 */
export class ResourceGuard {
  private cache: TokenCache;

  /**
   * Creates a new resource guard.
   *
   * @param client - HashGuard client instance with introspectToken method.
   * @param cacheOptions - Options for token validation caching.
   */
  constructor(
    private readonly client: {
      introspectToken: (
        token: string,
        consume?: boolean
      ) => Promise<TokenValidationResult>;
    },
    cacheOptions?: {
      maxEntries?: number;
      ttlMs?: number;
      autoCleanupMs?: number | null;
    }
  ) {
    this.cache = new TokenCache(
      cacheOptions?.maxEntries,
      cacheOptions?.ttlMs,
      cacheOptions?.autoCleanupMs
    );
  }

  /**
   * Checks if access to a resource is allowed.
   *
   * Steps:
   * 1. Quick local validation: JWT format, expiration.
   * 2. Cache lookup: return cached result if valid (and not consumed).
   * 3. Server verification: call introspectToken if needed.
   * 4. Context matching: verify context matches if specified.
   *
   * @param token - Proof token from the client.
   * @param options - Access control options.
   * @returns Access result indicating whether resource access is allowed.
   */
  async checkAccess(
    token: string,
    options: ResourceAccessOptions
  ): Promise<ResourceAccessResult> {
    const effectiveConsume = options.consume !== false;

    // Step 1: Quick local validation
    const localValidation = TokenValidator.validateLocal(token, {
      consume: effectiveConsume,
      maxAgeMs: options.maxAgeMs,
    });

    if (!localValidation.valid) {
      return {
        allowed: false,
        reason: localValidation.error,
        validationResult: localValidation,
      };
    }

    // Step 2: Check cache (only if not consuming the token)
    if (!effectiveConsume) {
      const cached = this.cache.get(token);
      if (cached) {
        return {
          allowed: cached.valid,
          reason: cached.valid ? undefined : cached.error,
          validationResult: cached,
        };
      }
    }

    // Step 3: Call server for authoritative verification
    try {
      const verification = await this.client.introspectToken(token, effectiveConsume);

      if (!effectiveConsume) {
        this.cache.set(token, verification);
      }

      // Step 4: Context matching if specified
      if (
        options.context &&
        verification.context &&
        verification.context !== options.context
      ) {
        return {
          allowed: false,
          reason: `Context mismatch: expected "${options.context}", got "${verification.context}"`,
          validationResult: verification,
        };
      }

      return {
        allowed: verification.valid,
        reason: verification.valid ? undefined : verification.error,
        validationResult: verification,
      };
    } catch (err) {
      return {
        allowed: false,
        reason: `Server verification failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  /**
   * Checks multiple tokens at once.
   *
   * @param tokens - Array of tokens to verify.
   * @param options - Common access control options (context, consume, etc).
   * @returns Array of access results in the same order as input tokens.
   */
  async checkAccessMultiple(
    tokens: string[],
    options: ResourceAccessOptions
  ): Promise<ResourceAccessResult[]> {
    return Promise.all(
      tokens.map((token) => this.checkAccess(token, { ...options, token }))
    );
  }

  /**
   * Invalidates a cached token entry.
   *
   * Use this when you want to force re-verification from the server.
   *
   * @param token - The token to invalidate.
   */
  invalidateToken(token: string): void {
    this.cache.delete(token);
  }

  /**
   * Clears the entire token cache.
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Returns cache statistics.
   */
  getCacheStats(): {
    size: number;
    maxEntries: number;
  } {
    return {
      size: this.cache.size(),
      maxEntries: 1000, // Consider making this accessible from cache
    };
  }

  /**
   * Cleans up resources (stops background cleanup interval).
   */
  destroy(): void {
    this.cache.destroy();
  }
}
