import { TokenValidationResult, TokenValidationOptions } from './types';

/**
 * Validates proof tokens on the server side.
 *
 * This class provides utilities for verifying token integrity and expiration
 * without requiring network calls to the HashGuard server. It can be used
 * in resource protection middleware to quickly reject expired tokens.
 *
 * For authoritative validation (consuming tokens), use {@link HashGuardClient.introspectToken}.
 */
export class TokenValidator {
  /**
   * Checks if a token string has valid JWT format.
   *
   * A valid JWT has exactly 3 parts separated by dots: header.payload.signature
   *
   * @param token - The token string to validate.
   * @returns true if the token has valid JWT format.
   */
  static isValidJwtFormat(token: string): boolean {
    const parts = token.split('.');
    return parts.length === 3 && parts.every((part) => part.length > 0);
  }

  /**
   * Decodes a JWT payload without verification.
   *
   * WARNING: This does NOT verify the signature. Use this only for local
   * validation (e.g., checking expiration). Always verify tokens with
   * {@link HashGuardClient.introspectToken} before granting access.
   *
   * @param token - The JWT token string.
   * @returns Decoded payload object, or null if token is malformed.
   */
  static decodePayload(token: string): Record<string, unknown> | null {
    if (!this.isValidJwtFormat(token)) {
      return null;
    }

    try {
      const parts = token.split('.');
      const payload = parts[1];
      // JWT payload is base64url encoded
      const decoded = Buffer.from(payload, 'base64url').toString('utf-8');
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }

  /**
   * Checks if a token has expired based on its embedded `exp` claim.
   *
   * @param token - The JWT token string.
   * @param clockSkewSeconds - Allow this many seconds of clock skew (default: 0).
   * @returns true if the token has expired or is malformed.
   */
  static isExpired(token: string, clockSkewSeconds = 0): boolean {
    const payload = this.decodePayload(token);
    if (!payload || typeof payload.exp !== 'number') {
      return true; // Invalid or missing exp claim
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = payload.exp;
    return now > expiresAt + clockSkewSeconds;
  }

  /**
   * Extracts the expiration time from a token.
   *
   * @param token - The JWT token string.
   * @returns ISO 8601 timestamp, or null if not found.
   */
  static getExpiresAt(token: string): string | undefined {
    const payload = this.decodePayload(token);
    if (!payload || typeof payload.exp !== 'number') {
      return undefined;
    }

    const expiresAt = new Date(payload.exp * 1000);
    return expiresAt.toISOString();
  }

  /**
   * Extracts the issued-at time from a token.
   *
   * @param token - The JWT token string.
   * @returns ISO 8601 timestamp, or null if not found.
   */
  static getIssuedAt(token: string): string | undefined {
    const payload = this.decodePayload(token);
    if (!payload || typeof payload.iat !== 'number') {
      return undefined;
    }

    const issuedAt = new Date(payload.iat * 1000);
    return issuedAt.toISOString();
  }

  /**
   * Extracts the subject (subject ID or user identifier) from a token.
   *
   * @param token - The JWT token string.
   * @returns Subject string, or null if not found.
   */
  static getSubject(token: string): string | undefined {
    const payload = this.decodePayload(token);
    if (!payload || typeof payload.sub !== 'string') {
      return undefined;
    }
    return payload.sub;
  }

  /**
   * Extracts custom context from a token.
   *
   * @param token - The JWT token string.
   * @returns Context string, or null if not found.
   */
  static getContext(token: string): string | undefined {
    const payload = this.decodePayload(token);
    if (!payload || typeof payload.context !== 'string') {
      return undefined;
    }
    return payload.context;
  }

  /**
   * Performs local token validation without calling the server.
   *
   * Checks:
   * - JWT format validity
   * - Token expiration (with optional max age)
   * - Presence of required claims
   *
   * WARNING: This does NOT verify the signature. For authoritative
   * validation, use {@link HashGuardClient.introspectToken}.
   *
   * @param token - The JWT token string.
   * @param options - Validation options.
   * @returns Validation result with extracted claims.
   */
  static validateLocal(
    token: string,
    options: TokenValidationOptions = {}
  ): TokenValidationResult {
    if (!token || typeof token !== 'string') {
      return {
        valid: false,
        error: 'Token must be a non-empty string',
      };
    }

    if (!this.isValidJwtFormat(token)) {
      return {
        valid: false,
        error: 'Token has invalid JWT format',
      };
    }

    if (this.isExpired(token)) {
      return {
        valid: false,
        error: 'Token has expired',
      };
    }

    // Check max age if specified
    if (typeof options.maxAgeMs === 'number' && options.maxAgeMs > 0) {
      const issuedAt = this.getIssuedAt(token);
      if (issuedAt) {
        const issuedTime = new Date(issuedAt).getTime();
        const now = Date.now();
        const ageMs = now - issuedTime;
        if (ageMs > options.maxAgeMs) {
          return {
            valid: false,
            error: `Token age (${ageMs}ms) exceeds max age (${options.maxAgeMs}ms)`,
          };
        }
      }
    }

    return {
      valid: true,
      subject: this.getSubject(token),
      context: this.getContext(token),
      issuedAt: this.getIssuedAt(token),
      expiresAt: this.getExpiresAt(token),
    };
  }
}
