import {
  ProofTokenVerificationKey,
  TokenValidationOptions,
  TokenValidationResult,
} from './types';

interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
}

function decodeBase64Url(value: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return Uint8Array.from(Buffer.from(value, 'base64url'));
  }

  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function decodeBase64UrlToString(value: string): string {
  return new TextDecoder().decode(decodeBase64Url(value));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer;
}

function getSubtleCrypto(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API is not available in this runtime');
  }

  return globalThis.crypto.subtle;
}

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
    return parts.length === 3 && parts.every((part) => /^[A-Za-z0-9_-]+$/.test(part));
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
      return JSON.parse(decodeBase64UrlToString(token.split('.')[1]));
    } catch {
      return null;
    }
  }

  /**
   * Decodes a JWT header without verification.
   */
  static decodeHeader(token: string): JwtHeader | null {
    if (!this.isValidJwtFormat(token)) {
      return null;
    }

    try {
      return JSON.parse(decodeBase64UrlToString(token.split('.')[0])) as JwtHeader;
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

  /**
   * Performs stateless validation including ES256 signature verification.
   *
   * This verifies:
   * - JWT structure
   * - ES256 signature using the supplied public JWK
   * - Required claims
   * - Expiration and optional max-age
   *
   * Single-use consumption cannot be checked locally; use server introspection for that.
   */
  static async validateStateless(
    token: string,
    options: TokenValidationOptions = {}
  ): Promise<TokenValidationResult> {
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

    if (!options.verificationKey) {
      return {
        valid: false,
        error: 'verificationKey is required for stateless token validation',
      };
    }

    const header = this.decodeHeader(token);
    if (
      !header ||
      header.alg !== 'ES256' ||
      header.typ !== 'JWT' ||
      header.kid !== options.verificationKey.kid
    ) {
      return {
        valid: false,
        error: 'Token has an unexpected JWT header',
      };
    }

    const signatureValid = await this.verifySignature(token, options.verificationKey);
    if (!signatureValid) {
      return {
        valid: false,
        error: 'Token signature is invalid',
      };
    }

    const payload = this.decodePayload(token);
    if (
      !payload ||
      typeof payload.jti !== 'string' ||
      typeof payload.sub !== 'string' ||
      typeof payload.context !== 'string' ||
      typeof payload.iat !== 'number' ||
      typeof payload.exp !== 'number'
    ) {
      return {
        valid: false,
        error: 'Token payload is malformed',
      };
    }

    if (this.isExpired(token)) {
      return {
        valid: false,
        error: 'Token has expired',
      };
    }

    if (typeof options.maxAgeMs === 'number' && options.maxAgeMs > 0) {
      const ageMs = Date.now() - payload.iat * 1000;
      if (ageMs > options.maxAgeMs) {
        return {
          valid: false,
          error: `Token age (${ageMs}ms) exceeds max age (${options.maxAgeMs}ms)`,
        };
      }
    }

    return {
      valid: true,
      subject: payload.sub,
      context: payload.context,
      issuedAt: new Date(payload.iat * 1000).toISOString(),
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    };
  }

  private static async verifySignature(
    token: string,
    verificationKey: ProofTokenVerificationKey
  ): Promise<boolean> {
    try {
      const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
      const subtle = getSubtleCrypto();
      const key = await subtle.importKey(
        'jwk',
        {
          ...verificationKey,
          ext: true,
          key_ops: ['verify'],
        },
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        false,
        ['verify']
      );

      return await subtle.verify(
        {
          name: 'ECDSA',
          hash: 'SHA-256',
        },
        key,
        toArrayBuffer(decodeBase64Url(encodedSignature)),
        toArrayBuffer(new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`))
      );
    } catch {
      return false;
    }
  }
}
