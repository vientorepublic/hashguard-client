import { SolveResult, SolverOptions, SolverTimeoutError } from './types';
import { verifyProof, sha256hex } from './crypto';
import { getWasmModule } from './wasm-loader';

/**
 * Solves a PoW challenge by trying nonce candidates until one satisfies
 * `SHA-256(challengeId:seed:nonce) <= target`.
 *
 * @throws {@link SolverTimeoutError} if `maxAttempts` or `timeoutMs` is exceeded.
 */
export function solvePow(
  challengeId: string,
  seed: string,
  targetHex: string,
  options: SolverOptions = {}
): SolveResult {
  const maxAttempts = options.maxAttempts ?? 50_000_000;
  const timeoutMs = options.timeoutMs ?? 120_000;
  const progressInterval = options.progressInterval ?? 100_000;

  // ── Validate targetHex format ─────────────────────────────────────────────
  if (!targetHex || typeof targetHex !== 'string') {
    throw new Error(`Invalid targetHex: expected string, got ${typeof targetHex}`);
  }
  if (targetHex.length !== 64) {
    throw new Error(
      `Invalid targetHex: expected 64 hex characters, got ${targetHex.length}`
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(targetHex)) {
    throw new Error(`Invalid targetHex: contains non-hex characters: ${targetHex}`);
  }

  // Use Date.now() for absolute time (not performance.now() which is relative).
  // This ensures WASM's Date::now() comparison works correctly.
  const startMs = Date.now();

  // ── WASM fast path ────────────────────────────────────────────────────────
  // The entire nonce-search loop runs inside WASM, crossing the JS boundary
  // only once.  Progress callbacks are not forwarded in WASM mode.
  const wasm = getWasmModule();
  if (wasm) {
    console.log('[PoW Solver] WASM active, solving challenge', {
      challengeId,
      seed,
      targetHex: `${targetHex.substring(0, 16)}...${targetHex.substring(48)}`,
      targetHexLen: targetHex.length,
      maxAttempts,
      timeoutMs,
    });

    const rawNonce = wasm.solve(
      challengeId,
      seed,
      targetHex,
      maxAttempts,
      startMs,
      timeoutMs,
      progressInterval
    );
    const solveTimeMs = Math.round(Date.now() - startMs);

    console.log('[PoW Solver] WASM solve returned', { rawNonce, solveTimeMs });

    if (rawNonce === -2) {
      // Wall-clock timeout inside WASM loop.
      console.error('[PoW Solver] WASM timeout after', solveTimeMs, 'ms');
      throw new SolverTimeoutError(maxAttempts, solveTimeMs);
    }
    if (rawNonce === -3) {
      // Invalid target hex
      console.error('[PoW Solver] Invalid target hex format:', targetHex);
      throw new Error(
        `Invalid target hex: expected 64 hex chars, got ${targetHex.length} chars`
      );
    }
    if (rawNonce === -1) {
      // Max attempts exhausted
      console.error('[PoW Solver] Max attempts exhausted after', solveTimeMs, 'ms');
      throw new SolverTimeoutError(maxAttempts, solveTimeMs);
    }
    if (rawNonce < 0) {
      // Unexpected error code
      console.error('[PoW Solver] Unexpected error code:', rawNonce);
      throw new Error(`Unexpected WASM error code: ${rawNonce}`);
    }

    const preimage = `${challengeId}:${seed}:${rawNonce}`;
    const hash = sha256hex(preimage); // also uses WASM
    return {
      nonce: String(rawNonce),
      hash,
      attempts: rawNonce + 1,
      solveTimeMs,
    };
  }

  // ── JS fallback ───────────────────────────────────────────────────────────
  console.log('[PoW Solver] Using JS fallback (WASM not available)', {
    challengeId,
    seed,
    targetHex: `${targetHex.substring(0, 16)}...${targetHex.substring(48)}`,
    targetHexLen: targetHex.length,
    maxAttempts,
    timeoutMs,
  });

  for (let nonce = 0; nonce < maxAttempts; nonce++) {
    if (verifyProof(challengeId, seed, String(nonce), targetHex)) {
      const solveTimeMs = Math.round(Date.now() - startMs);
      // Compute the hash for reporting
      const preimage = `${challengeId}:${seed}:${nonce}`;
      const hash = sha256hex(preimage);
      console.log(
        '[PoW Solver] Found solution at nonce',
        nonce,
        'in',
        solveTimeMs,
        'ms'
      );
      return {
        nonce: String(nonce),
        hash,
        attempts: nonce + 1,
        solveTimeMs,
      };
    }

    // Check wall-clock timeout
    if (nonce % progressInterval === 0) {
      const elapsedMs = Date.now() - startMs;
      if (elapsedMs > timeoutMs) {
        console.error(
          '[PoW Solver] JS timeout after',
          Math.round(elapsedMs),
          'ms at nonce',
          nonce
        );
        throw new SolverTimeoutError(nonce, Math.round(elapsedMs));
      }
      if (options.onProgress) {
        options.onProgress(nonce);
      }
    }
  }

  const elapsedMs = Math.round(Date.now() - startMs);
  console.error('[PoW Solver] Max attempts exhausted after', elapsedMs, 'ms');
  throw new SolverTimeoutError(maxAttempts, elapsedMs);
}
