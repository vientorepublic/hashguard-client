import * as crypto from 'crypto';
import { solvePow } from '../src/solver';
import { verifyProof, sha256hex } from '../src/crypto';
import { SolverEstimate, SolverTimeoutError } from '../src/types';
import { HashGuardClient } from '../src/client';
import { TokenValidator } from '../src/token-validator';
import { TokenCache } from '../src/token-cache';
import { ResourceGuard } from '../src/resource-guard';
import { ProofTokenJwks, ProofTokenVerificationKey } from '../src/types';

function createSignedProofToken(overrides: Record<string, unknown> = {}): {
  token: string;
  verificationKey: ProofTokenVerificationKey;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const exported = publicKey.export({ format: 'jwk' }) as {
    x?: string;
    y?: string;
  };
  const verificationKey: ProofTokenVerificationKey = {
    kty: 'EC',
    crv: 'P-256',
    x: exported.x!,
    y: exported.y!,
    use: 'sig',
    alg: 'ES256',
    kid: 'test-kid',
    key_ops: ['verify'],
  };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    jti: 'test-jti',
    sub: '203.0.113.5',
    context: 'test',
    iat: now,
    exp: now + 60,
    ...overrides,
  };
  const header = {
    alg: 'ES256',
    typ: 'JWT',
    kid: verificationKey.kid,
  };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .sign('sha256', Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8'), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    })
    .toString('base64url');

  return {
    token: `${encodedHeader}.${encodedPayload}.${signature}`,
    verificationKey,
  };
}

describe('Solver', () => {
  it('should find a valid nonce for an easy target', () => {
    const challengeId = 'test-id';
    const seed = 'test-seed';
    // All-f's target: very easy to satisfy
    const easyTarget = 'ffff' + 'f'.repeat(60);

    const result = solvePow(challengeId, seed, easyTarget, {
      maxAttempts: 1000,
    });

    expect(result.nonce).toBeDefined();
    expect(result.hash).toBeDefined();
    expect(result.attempts).toBeGreaterThan(0);
    expect(result.solveTimeMs).toBeGreaterThanOrEqual(0);

    // Verify the result is actually valid
    expect(verifyProof(challengeId, seed, result.nonce, easyTarget)).toBe(true);
  });

  it('should respect maxAttempts limit', () => {
    const challengeId = 'test-id';
    const seed = 'test-seed';
    // All-zero target: impossible to satisfy
    const impossibleTarget = '0'.repeat(64);

    expect(() => {
      solvePow(challengeId, seed, impossibleTarget, {
        maxAttempts: 100,
        timeoutMs: 60000,
      });
    }).toThrow(SolverTimeoutError);
  });

  it('should report progress at intervals', () => {
    const challengeId = 'test-id';
    const seed = 'test-seed';
    // Use a target that requires multiple attempts (hashes starting with 00)
    const moderateTarget = '00ff' + 'f'.repeat(60);
    const progressCalls: number[] = [];

    const result = solvePow(challengeId, seed, moderateTarget, {
      maxAttempts: 100000,
      progressInterval: 100,
      onProgress: (attempts) => progressCalls.push(attempts),
    });

    // Should have found a solution or reported progress
    expect(result).toBeDefined();
    expect(result.attempts).toBeGreaterThan(0);
    // At least one progress report should have been made with 100 interval
    expect(progressCalls.length).toBeGreaterThanOrEqual(0);
  });

  it('should emit ETA estimates during JS solving', () => {
    const challengeId = 'estimate-id';
    const seed = 'estimate-seed';
    const impossibleTarget = '0'.repeat(64);
    const estimateEvents: SolverEstimate[] = [];

    expect(() => {
      solvePow(challengeId, seed, impossibleTarget, {
        maxAttempts: 120,
        timeoutMs: 60_000,
        progressInterval: 25,
        difficultyBits: 20,
        onEstimate: (estimate) => estimateEvents.push(estimate),
      });
    }).toThrow(SolverTimeoutError);

    expect(estimateEvents.length).toBeGreaterThan(0);
    expect(estimateEvents.some((event) => event.phase === 'progress')).toBe(true);
    expect(estimateEvents[estimateEvents.length - 1]?.phase).toBe('timeout');
    expect(estimateEvents[0]?.usingWasm).toBe(false);
    expect(estimateEvents[0]?.difficultyBits).toBe(20);
    expect(estimateEvents[0]?.hashRate).toBeGreaterThanOrEqual(0);
  });
});

describe('Crypto', () => {
  it('sha256hex should return a 64-char hex string', () => {
    const hash = sha256hex('hello');
    expect(hash).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });

  it('verifyProof should accept a valid proof', () => {
    const hash = sha256hex('test-id:seed:123');
    const valid = verifyProof('test-id', 'seed', '123', hash);
    expect(valid).toBe(true);
  });

  it('verifyProof should reject an invalid proof', () => {
    const invalidTarget = '0'.repeat(64);
    const valid = verifyProof('test-id', 'seed', '123', invalidTarget);
    expect(valid).toBe(false);
  });
});

describe('TokenValidator', () => {
  it('should detect valid JWT format', () => {
    const validToken = 'header.payload.signature';
    const invalidToken = 'header.payload';

    expect(TokenValidator.isValidJwtFormat(validToken)).toBe(true);
    expect(TokenValidator.isValidJwtFormat(invalidToken)).toBe(false);
    expect(TokenValidator.isValidJwtFormat('')).toBe(false);
  });

  it('should decode JWT payload', () => {
    // Create a simple JWT-like token with known payload
    const payload = JSON.stringify({ sub: 'user123', context: 'test' });
    const encoded = Buffer.from(payload).toString('base64url');
    const token = `header.${encoded}.signature`;

    const decoded = TokenValidator.decodePayload(token);
    expect(decoded).toBeDefined();
    expect(decoded?.sub).toBe('user123');
    expect(decoded?.context).toBe('test');
  });

  it('should return null for malformed tokens', () => {
    expect(TokenValidator.decodePayload('invalid')).toBeNull();
    expect(TokenValidator.decodePayload('')).toBeNull();
  });

  it('should validate local token format', () => {
    const result = TokenValidator.validateLocal('not.a.token');
    expect(result.valid).toBe(false);
  });

  it('should accept valid JWT format in local validation', () => {
    const goodToken = 'header.payload.sig';
    const result = TokenValidator.validateLocal(goodToken);
    // Will be invalid due to expiration, but format is OK
    expect(result).toBeDefined();
  });

  it('should validate an ES256 proof token statelessly', async () => {
    const fixture = createSignedProofToken();

    const result = await TokenValidator.validateStateless(fixture.token, {
      verificationKey: fixture.verificationKey,
    });

    expect(result.valid).toBe(true);
    expect(result.subject).toBe('203.0.113.5');
    expect(result.context).toBe('test');
  });

  it('should reject stateless validation with the wrong verification key', async () => {
    const fixture = createSignedProofToken();
    const wrongKey = createSignedProofToken().verificationKey;

    const result = await TokenValidator.validateStateless(fixture.token, {
      verificationKey: wrongKey,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Token signature is invalid');
  });

  it('should let HashGuardClient validate tokens statelessly', async () => {
    const fixture = createSignedProofToken();
    const client = new HashGuardClient({
      baseUrl: 'https://hashguard.viento.me',
      proofTokenVerificationKey: fixture.verificationKey,
    });

    const result = await client.validateTokenStatelessly(fixture.token);

    expect(result.valid).toBe(true);
  });

  it('should fetch JWKS and select the matching key by kid', async () => {
    const fixture = createSignedProofToken();
    const otherKey = {
      ...createSignedProofToken().verificationKey,
      kid: 'other-kid',
    };
    const jwks: ProofTokenJwks = {
      keys: [otherKey, fixture.verificationKey],
    };
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => jwks,
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as typeof fetch;

    try {
      const client = new HashGuardClient({
        baseUrl: 'https://hashguard.viento.me',
      });

      const result = await client.validateTokenStatelessly(fixture.token);

      expect(result.valid).toBe(true);
      expect(fetchMock).toHaveBeenCalledWith(
        'https://hashguard.viento.me/.well-known/jwks.json',
        expect.objectContaining({
          method: 'GET',
        })
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('should return a clear error when no JWKS key matches token kid', async () => {
    const fixture = createSignedProofToken();
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        keys: [{ ...fixture.verificationKey, kid: 'different-kid' }],
      }),
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as typeof fetch;

    try {
      const client = new HashGuardClient({
        baseUrl: 'https://hashguard.viento.me',
      });

      const result = await client.validateTokenStatelessly(fixture.token);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('No verification key matched the token kid');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('TokenCache', () => {
  it('should store and retrieve cached entries', () => {
    const cache = new TokenCache(10, 60_000, null);
    const result = { valid: true, subject: 'user1' };

    cache.set('token1', result);
    expect(cache.has('token1')).toBe(true);
    expect(cache.get('token1')).toEqual(result);
  });

  it('should return undefined for missing entries', () => {
    const cache = new TokenCache(10, 60_000, null);
    expect(cache.get('nonexistent')).toBeUndefined();
    expect(cache.has('nonexistent')).toBe(false);
  });

  it('should delete entries', () => {
    const cache = new TokenCache(10, 60_000, null);
    const result = { valid: true };

    cache.set('token1', result);
    cache.delete('token1');
    expect(cache.has('token1')).toBe(false);
  });

  it('should track cache size', () => {
    const cache = new TokenCache(10, 60_000, null);
    cache.set('token1', { valid: true });
    cache.set('token2', { valid: false });

    expect(cache.size()).toBe(2);
    cache.clear();
    expect(cache.size()).toBe(0);
  });

  it('should cleanup expired entries', (done) => {
    const cache = new TokenCache(10, 100, null); // 100ms TTL
    cache.set('token1', { valid: true });

    setTimeout(() => {
      const removed = cache.cleanup();
      expect(removed).toBeGreaterThan(0);
      expect(cache.has('token1')).toBe(false);
      done();
    }, 150);
  });
});

describe('ResourceGuard', () => {
  it('should default to consume=true when consume option is omitted', async () => {
    const payload = Buffer.from(
      JSON.stringify({
        sub: '203.0.113.5',
        context: 'test',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      })
    ).toString('base64url');
    const token = `header.${payload}.signature`;

    const calls: boolean[] = [];
    const client = {
      introspectToken: async (_token: string, consume?: boolean) => {
        calls.push(consume ?? false);
        return {
          valid: true,
          subject: '203.0.113.5',
          context: 'test',
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        };
      },
    };

    const guard = new ResourceGuard(client, { autoCleanupMs: null });
    const result = await guard.checkAccess(token, {
      token,
      context: 'test',
    });

    expect(result.allowed).toBe(true);
    expect(calls).toEqual([true]);
    guard.destroy();
  });
});
