import { getWasmModule } from '../src/wasm-loader';

jest.mock('../src/wasm-loader', () => ({
  getWasmModule: jest.fn(),
}));

import { sha256hex, verifyProof } from '../src/crypto';
import { solvePow } from '../src/solver';
import { SolverTimeoutError } from '../src/types';

type WasmMock = {
  sha256hex: jest.Mock<string, [string]>;
  verify_proof: jest.Mock<boolean, [string, string, string, string]>;
  solve: jest.Mock<number, [string, string, string, number, number, number, number]>;
};

const mockedGetWasmModule = getWasmModule as jest.MockedFunction<typeof getWasmModule>;

function createWasmMock(): WasmMock {
  return {
    sha256hex: jest.fn<string, [string]>().mockReturnValue('a'.repeat(64)),
    verify_proof: jest
      .fn<boolean, [string, string, string, string]>()
      .mockReturnValue(true),
    solve: jest
      .fn<number, [string, string, string, number, number, number, number]>()
      .mockReturnValue(7),
  };
}

describe('WASM acceleration path', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('sha256hex should delegate to WASM when module is ready', () => {
    const wasm = createWasmMock();
    wasm.sha256hex.mockReturnValue('b'.repeat(64));
    mockedGetWasmModule.mockReturnValue(wasm);

    const out = sha256hex('hello-wasm');

    expect(out).toBe('b'.repeat(64));
    expect(wasm.sha256hex).toHaveBeenCalledWith('hello-wasm');
  });

  it('verifyProof should delegate to WASM when module is ready', () => {
    const wasm = createWasmMock();
    wasm.verify_proof.mockReturnValue(false);
    mockedGetWasmModule.mockReturnValue(wasm);

    const ok = verifyProof('cid', 'seed', '3', 'f'.repeat(64));

    expect(ok).toBe(false);
    expect(wasm.verify_proof).toHaveBeenCalledWith('cid', 'seed', '3', 'f'.repeat(64));
  });

  it('solvePow should use WASM solve loop and hash reporting', () => {
    const wasm = createWasmMock();
    wasm.solve.mockReturnValue(42);
    wasm.sha256hex.mockReturnValue('c'.repeat(64));
    mockedGetWasmModule.mockReturnValue(wasm);

    const result = solvePow('challenge', 'seed', 'f'.repeat(64), {
      maxAttempts: 1000,
      timeoutMs: 10_000,
      progressInterval: 50,
    });

    expect(wasm.solve).toHaveBeenCalled();
    expect(wasm.sha256hex).toHaveBeenCalledWith('challenge:seed:42');
    expect(result.nonce).toBe('42');
    expect(result.hash).toBe('c'.repeat(64));
    expect(result.attempts).toBe(43);
    expect(result.solveTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('solvePow should raise timeout error when WASM solver returns timeout', () => {
    const wasm = createWasmMock();
    wasm.solve.mockReturnValue(-2);
    mockedGetWasmModule.mockReturnValue(wasm);

    expect(() => {
      solvePow('challenge', 'seed', 'f'.repeat(64), {
        maxAttempts: 100,
        timeoutMs: 1,
      });
    }).toThrow(SolverTimeoutError);
  });
});
