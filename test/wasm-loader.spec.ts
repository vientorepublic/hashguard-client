import * as nodeCrypto from 'crypto';

const mockWasmInit = jest.fn<Promise<void>, [ArrayBuffer]>();
const mockWasmSha256hex = jest.fn<string, [string]>();
const mockWasmVerifyProof = jest.fn<boolean, [string, string, string, string]>();
const mockWasmSolve = jest.fn<
  number,
  [string, string, string, number, number, number, number]
>();
const mockWasmSolveBatch = jest.fn<
  number,
  [string, string, string, number, number, number, number, number]
>();

jest.mock('../src/wasm-pkg/wasm_binary.js', () => ({
  __esModule: true,
  WASM_BASE64: Buffer.from([0x00, 0x61, 0x73, 0x6d]).toString('base64'),
}));

jest.mock('../src/wasm-pkg/hashguard_wasm.js', () => ({
  __esModule: true,
  default: (buffer: ArrayBuffer) => mockWasmInit(buffer),
  sha256hex: (input: string) => mockWasmSha256hex(input),
  verify_proof: (challengeId: string, seed: string, nonce: string, targetHex: string) =>
    mockWasmVerifyProof(challengeId, seed, nonce, targetHex),
  solve: (
    challengeId: string,
    seed: string,
    targetHex: string,
    maxAttempts: number,
    startMs: number,
    timeoutMs: number,
    progressInterval: number
  ) =>
    mockWasmSolve(
      challengeId,
      seed,
      targetHex,
      maxAttempts,
      startMs,
      timeoutMs,
      progressInterval
    ),
  solve_batch: (
    challengeId: string,
    seed: string,
    targetHex: string,
    startNonce: number,
    batchAttempts: number,
    startMs: number,
    timeoutMs: number,
    progressInterval: number
  ) =>
    mockWasmSolveBatch(
      challengeId,
      seed,
      targetHex,
      startNonce,
      batchAttempts,
      startMs,
      timeoutMs,
      progressInterval
    ),
}));

describe('WASM loader fallback behavior', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  it('falls back to the JS SHA-256 implementation when WASM initialization fails', async () => {
    mockWasmInit.mockRejectedValueOnce(new Error('simulated wasm init failure'));

    const loader = await import('../src/wasm-loader');
    const crypto = await import('../src/crypto');

    const initialized = await loader.initHashGuardWasm();

    expect(initialized).toBe(false);
    expect(loader.isWasmReady()).toBe(false);

    const input = 'fallback-check';
    const expected = nodeCrypto
      .createHash('sha256')
      .update(input, 'utf8')
      .digest('hex');

    expect(crypto.sha256hex(input)).toBe(expected);
    expect(mockWasmSha256hex).not.toHaveBeenCalled();
  });

  it('allows a later retry to initialize WASM after an earlier failure', async () => {
    mockWasmInit
      .mockRejectedValueOnce(new Error('transient wasm init failure'))
      .mockResolvedValueOnce(undefined);
    mockWasmSha256hex.mockReturnValue('e'.repeat(64));

    const loader = await import('../src/wasm-loader');
    const crypto = await import('../src/crypto');

    expect(await loader.initHashGuardWasm()).toBe(false);
    expect(loader.isWasmReady()).toBe(false);

    expect(await loader.initHashGuardWasm()).toBe(true);
    expect(loader.isWasmReady()).toBe(true);
    expect(mockWasmInit).toHaveBeenCalledTimes(2);

    expect(crypto.sha256hex('retry-check')).toBe('e'.repeat(64));
    expect(mockWasmSha256hex).toHaveBeenCalledWith('retry-check');
  });
});
