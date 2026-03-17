/**
 * Lazy loader for the WASM-accelerated hashguard core.
 *
 * Call {@link initHashGuardWasm} explicitly once at application start-up.
 * After a successful init all calls to `sha256hex`, `verifyProof`, and
 * `solvePow` use the WASM implementation instead of the pure-JS fallback.
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
let _initPromise: Promise<boolean> | null = null;

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
  if (_wasm !== null) {
    console.log('[WASM Loader] WASM already initialized');
    return true;
  }
  if (_initPromise) {
    console.log('[WASM Loader] WASM initialization in progress...');
    return _initPromise;
  }

  console.log('[WASM Loader] Starting WASM initialization');
  _initPromise = (async () => {
    try {
      console.log('[WASM Loader] Loading WASM binary and glue modules');
      const [binaryMod, glueMod] = await Promise.all([
        import('./wasm-pkg/wasm_binary.js') as Promise<{ WASM_BASE64: string }>,
        import('./wasm-pkg/hashguard_wasm.js'),
      ]);

      console.log(
        '[WASM Loader] Decoding base64 binary, size:',
        binaryMod.WASM_BASE64.length
      );
      const buffer = _decodeBase64(binaryMod.WASM_BASE64);
      console.log(
        '[WASM Loader] Initializing WebAssembly instance, buffer size:',
        buffer.byteLength
      );

      await glueMod.default(buffer);
      _wasm = glueMod as unknown as WasmFunctions;

      console.log('[WASM Loader] ✓ WASM initialization successful');
      return true;
    } catch (err) {
      // WASM artefacts not built yet, or WebAssembly not supported — silently fall back.
      console.warn(
        '[WASM Loader] ✗ WASM initialization failed, falling back to JS:',
        err
      );
      return false;
    }
  })();

  return _initPromise;
}

/** Returns the loaded WASM module, or `null` if not yet initialised. */
export function getWasmModule(): WasmFunctions | null {
  // Explicit initialization model: caller must invoke initHashGuardWasm().
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
