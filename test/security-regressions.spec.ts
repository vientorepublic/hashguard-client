import { HashGuardClient } from '../src/client';
import { ResourceGuard } from '../src/resource-guard';
import { TokenValidator } from '../src/token-validator';
import { ProofTokenVerificationKey } from '../src/types';

function token(kid = 'unknown', overrides: Record<string, unknown> = {}) {
  const header = Buffer.from(
    JSON.stringify({ alg: 'ES256', typ: 'JWT', kid })
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      jti: 'id',
      sub: '203.0.113.1',
      context: 'search',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      ...overrides,
    })
  ).toString('base64url');
  return `${header}.${payload}.signature`;
}
const key: ProofTokenVerificationKey = {
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  use: 'sig',
  kid: 'known',
  x: 'x',
  y: 'y',
};

describe('Security review regressions', () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.useRealTimers();
  });

  it('bounds unknown-kid refreshes and deduplicates concurrent HTTP requests', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({ keys: [key] }) });
    globalThis.fetch = fetchMock as typeof fetch;
    const client = new HashGuardClient({
      baseUrl: 'https://issuer.test',
      proofTokenJwks: { keys: [key] },
    });
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        client.validateTokenStatelessly(token(`kid-${i}`))
      )
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect((await client.validateTokenStatelessly(token('another-kid'))).valid).toBe(
      false
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not repeatedly fetch when the cold JWKS lookup fails', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new TypeError('offline'));
    globalThis.fetch = fetchMock as typeof fetch;
    const client = new HashGuardClient({ baseUrl: 'https://issuer.test' });
    await expect(client.validateTokenStatelessly(token())).rejects.toThrow('offline');
    expect((await client.validateTokenStatelessly(token('other'))).valid).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects expired tokens exactly at exp, including local cache paths', async () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-11-15T00:00:00Z'));
    const assertion = token('known', { exp: Math.floor(Date.now() / 1000) });
    expect(TokenValidator.isExpired(assertion)).toBe(true);
    expect(TokenValidator.validateLocal(assertion).valid).toBe(false);
  });

  it('returns denied when stateless validation or key lookup throws', async () => {
    const guard = new ResourceGuard(
      {
        introspectToken: jest.fn(),
        validateTokenStatelessly: async () => {
          throw new Error('offline');
        },
      },
      { autoCleanupMs: null }
    );
    try {
      await expect(
        guard.checkAccess(token(), { token: token() })
      ).resolves.toMatchObject({ allowed: false });
    } finally {
      guard.destroy();
    }
  });

  it('checks subject/context on cached assertions and forwards constraints to introspection', async () => {
    const assertion = token();
    const introspectToken = jest
      .fn()
      .mockResolvedValue({ valid: true, subject: '203.0.113.1', context: 'search' });
    const guard = new ResourceGuard({ introspectToken }, { autoCleanupMs: null });
    try {
      const options = {
        token: assertion,
        context: 'search',
        subject: '203.0.113.1',
        consume: false,
      };
      expect((await guard.checkAccess(assertion, options)).allowed).toBe(true);
      expect(
        (await guard.checkAccess(assertion, { ...options, subject: '203.0.113.2' }))
          .allowed
      ).toBe(false);
      expect(
        (await guard.checkAccess(assertion, { ...options, context: 'export' })).allowed
      ).toBe(false);
      expect(introspectToken).toHaveBeenCalledTimes(1);
      expect(introspectToken).toHaveBeenCalledWith(assertion, false, {
        expectedContext: 'search',
        expectedSubject: '203.0.113.1',
      });
    } finally {
      guard.destroy();
    }
  });

  it('rejects out-of-range timestamps without throwing', () => {
    expect(TokenValidator.validateLocal(token('known', { exp: 1e308 })).valid).toBe(
      false
    );
    expect(TokenValidator.getIssuedAt(token('known', { iat: -1e308 }))).toBeUndefined();
  });
});
