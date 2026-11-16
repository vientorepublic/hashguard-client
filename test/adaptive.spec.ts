import { HashGuardClient } from '../src/client';
import { sha256hex } from '../src/crypto';

describe('Adaptive SDK', () => {
  const originalFetch = globalThis.fetch;
  const fetchMock = jest.fn();
  const client = new HashGuardClient({ baseUrl: 'https://hashguard.test' });
  beforeEach(() => {
    fetchMock.mockReset();
    globalThis.fetch = fetchMock as typeof fetch;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });
  const respond = (body: unknown) => ({ ok: true, json: async () => body });

  it('returns a low-risk assertion without solving, progress callbacks or verification HTTP', async () => {
    fetchMock.mockResolvedValue(
      respond({
        action: 'allow',
        riskScore: 0,
        verification: { proofToken: 'signed', expiresAt: 'later' },
      })
    );
    const onProgress = jest.fn();
    expect(
      await client.execute('search', { onProgress, maxAttempts: 0 })
    ).toMatchObject({
      challengeRequired: false,
      challenge: null,
      solveResult: null,
      verification: { proofToken: 'signed' },
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://hashguard.test/v1/pow/assessments'
    );
    expect(onProgress).not.toHaveBeenCalled();
  });

  it('solves and verifies only a server-issued challenge', async () => {
    fetchMock
      .mockResolvedValueOnce(
        respond({
          action: 'challenge',
          riskScore: 25,
          challenge: {
            challengeId: 'id',
            seed: 'seed',
            target: 'f'.repeat(64),
            difficultyBits: 1,
          },
        })
      )
      .mockResolvedValueOnce(respond({ proofToken: 'solved', expiresAt: 'later' }));
    const result = await client.execute('search');
    expect(result.challengeRequired).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const payload = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(sha256hex(`id:seed:${payload.nonce}`) <= 'f'.repeat(64)).toBe(true);
    expect(result.verification.proofToken).toBe('solved');
  });

  it('propagates hard limits without issuing a fallback challenge', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 429,
      json: async () => ({ code: 'POW_ADAPTIVE_RATE_LIMITED', message: 'limited' }),
    });
    await expect(client.execute()).rejects.toMatchObject({
      code: 'POW_ADAPTIVE_RATE_LIMITED',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects unknown server decisions', async () => {
    fetchMock.mockResolvedValue(respond({ action: 'unknown' }));
    await expect(client.execute()).rejects.toMatchObject({
      code: 'INVALID_ASSESSMENT',
    });
  });
});
