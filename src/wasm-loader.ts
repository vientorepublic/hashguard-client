/**
 * Lazy loader for the WASM-accelerated hashguard core.
 *
 * Call {@link initHashGuardWasm} once at application start-up.  After a
 * successful init all calls to `sha256hex`, `verifyProof`, and `solvePow`
 * automatically use the WASM implementation instead of the pure-JS fallback.
 * If the WASM artefacts are not present (e.g. fresh checkout before
 * `npm run build:wasm`) initialization silently returns `false` and the SDK
 * continues to work with the JS implementation.
 */

interface WasmFunctions {
  sha256hex(input: string): string;
  verify_proof(
    challengeId: string,
    seed: string,
    nonce: string,
    targetHex: string
  ): boolean;
  solve(
    challengeId: string,
    seed: string,
    targetHex: string,
    maxAttempts: number,
    startMs: number,
    timeoutMs: number,
    progressInterval: number
  ): number;
}

let _wasm: WasmFunctions | null = null;

/** Returns `true` if the WASM module has been successfully initialised. */
export function isWasmReady(): boolean {
  return _wasm !== null;
}

/**
 * Initialises the WASM acceleration module.
 *
 * - Safe to call multiple times — subsequent calls are no-ops and return `true`.
 * - Returns `false` when the WASM artefacts are unavailable (e.g. before
 *   running `npm run build:wasm`).  The SDK falls back to the pure-JS
 *   implementation automatically.
 */
export async function initHashGuardWasm(): Promise<boolean> {
  if (_wasm !== null) return true;

  try {
    const [binaryMod, glueMod] = await Promise.all([
      import('./wasm-pkg/wasm_binary.js') as Promise<{ WASM_BASE64: string }>,
      import('./wasm-pkg/hashguard_wasm.js'),
    ]);

    const buffer = _decodeBase64(binaryMod.WASM_BASE64);
    await glueMod.default(buffer);
    _wasm = glueMod as unknown as WasmFunctions;
    return true;
  } catch {
    // WASM artefacts not built yet, or WebAssembly not supported — silently fall back.
    return false;
  }
}

/** Returns the loaded WASM module, or `null` if not yet initialised. */
export function getWasmModule(): WasmFunctions | null {
  return _wasm;
}

// ── internal ──────────────────────────────────────────────────────────────────

function _decodeBase64(b64: string): ArrayBuffer {
  // Access Node.js Buffer via globalThis to avoid needing both DOM + @types/node in the same lib.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const NodeBuffer = (globalThis as any).Buffer as
    | {
        from(
          s: string,
          enc: string
        ): { buffer: ArrayBuffer; byteOffset: number; byteLength: number };
      }
    | undefined;
  if (NodeBuffer) {
    // Node.js path — Buffer.from is faster and handles non-padded base64 robustly.
    const buf = NodeBuffer.from(b64, 'base64');
    // buf.buffer may be a larger pooled ArrayBuffer; slice to exact size.
    return buf.buffer.slice(
      buf.byteOffset,
      buf.byteOffset + buf.byteLength
    ) as ArrayBuffer;
  }
  // Browser path — atob is available in all modern environments.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _atob: (s: string) => string = (globalThis as any).atob;
  const bin = _atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
