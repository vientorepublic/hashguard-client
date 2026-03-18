import {
  SolveResult,
  SolverEstimate,
  SolverOptions,
  SolverTimeoutError,
} from './types';
import { verifyProof, sha256hex } from './crypto';
import { getWasmModule } from './wasm-loader';

type WasmModule = NonNullable<ReturnType<typeof getWasmModule>>;

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
  const maxAttempts = Math.max(1, options.maxAttempts ?? 50_000_000);
  const timeoutMs = Math.max(1, options.timeoutMs ?? 120_000);
  const progressInterval = Math.max(1, options.progressInterval ?? 100_000);

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
  const difficultyBits = resolveDifficultyBits(options.difficultyBits, targetHex);
  const emitEstimate = createEstimateEmitter({
    options,
    startMs,
    maxAttempts,
    timeoutMs,
    difficultyBits,
  });

  // ── WASM fast path ────────────────────────────────────────────────────────
  // The entire nonce-search loop can run inside WASM when no incremental
  // callbacks are required. If progress/ETA callbacks are requested we switch
  // to batched WASM execution so JS can emit events between batches.
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

    if (options.onProgress || options.onEstimate) {
      return solvePowWithWasmBatches(
        wasm,
        challengeId,
        seed,
        targetHex,
        {
          ...options,
          maxAttempts,
          timeoutMs,
          progressInterval,
        },
        startMs,
        emitEstimate
      );
    }

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
      emitEstimate('timeout', maxAttempts, solveTimeMs, true);
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
      emitEstimate('timeout', maxAttempts, solveTimeMs, true);
      throw new SolverTimeoutError(maxAttempts, solveTimeMs);
    }
    if (rawNonce < 0) {
      // Unexpected error code
      console.error('[PoW Solver] Unexpected error code:', rawNonce);
      throw new Error(`Unexpected WASM error code: ${rawNonce}`);
    }

    const preimage = `${challengeId}:${seed}:${rawNonce}`;
    const hash = sha256hex(preimage); // also uses WASM
    emitEstimate('complete', rawNonce + 1, solveTimeMs, true);
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
      emitEstimate('complete', nonce + 1, solveTimeMs, false);
      return {
        nonce: String(nonce),
        hash,
        attempts: nonce + 1,
        solveTimeMs,
      };
    }

    // Check wall-clock timeout
    const attempts = nonce + 1;
    if (attempts % progressInterval === 0) {
      const elapsedMs = Date.now() - startMs;
      if (elapsedMs > timeoutMs) {
        console.error(
          '[PoW Solver] JS timeout after',
          Math.round(elapsedMs),
          'ms at nonce',
          nonce
        );
        emitEstimate('timeout', attempts, Math.round(elapsedMs), false);
        throw new SolverTimeoutError(attempts, Math.round(elapsedMs));
      }
      if (options.onProgress) {
        options.onProgress(attempts);
      }
      emitEstimate('progress', attempts, Math.round(elapsedMs), false);
    }
  }

  const elapsedMs = Math.round(Date.now() - startMs);
  console.error('[PoW Solver] Max attempts exhausted after', elapsedMs, 'ms');
  emitEstimate('timeout', maxAttempts, elapsedMs, false);
  throw new SolverTimeoutError(maxAttempts, elapsedMs);
}

function solvePowWithWasmBatches(
  wasm: WasmModule,
  challengeId: string,
  seed: string,
  targetHex: string,
  options: SolverOptions & {
    maxAttempts: number;
    timeoutMs: number;
    progressInterval: number;
  },
  startMs: number,
  emitEstimate: (
    phase: SolverEstimate['phase'],
    attempts: number,
    elapsedMs: number,
    usingWasm: boolean
  ) => void
): SolveResult {
  let attemptsCompleted = 0;

  while (attemptsCompleted < options.maxAttempts) {
    const batchAttempts = Math.min(
      options.progressInterval,
      options.maxAttempts - attemptsCompleted
    );
    const rawNonce = wasm.solve_batch(
      challengeId,
      seed,
      targetHex,
      attemptsCompleted,
      batchAttempts,
      startMs,
      options.timeoutMs,
      options.progressInterval
    );
    const elapsedMs = Math.round(Date.now() - startMs);

    if (rawNonce >= 0) {
      const preimage = `${challengeId}:${seed}:${rawNonce}`;
      const hash = sha256hex(preimage);
      emitEstimate('complete', rawNonce + 1, elapsedMs, true);
      return {
        nonce: String(rawNonce),
        hash,
        attempts: rawNonce + 1,
        solveTimeMs: elapsedMs,
      };
    }

    if (rawNonce === -3) {
      console.error('[PoW Solver] Invalid target hex format:', targetHex);
      throw new Error(
        `Invalid target hex: expected 64 hex chars, got ${targetHex.length} chars`
      );
    }

    attemptsCompleted += batchAttempts;

    if (rawNonce === -2) {
      console.error('[PoW Solver] WASM timeout after', elapsedMs, 'ms');
      emitEstimate('timeout', attemptsCompleted, elapsedMs, true);
      throw new SolverTimeoutError(attemptsCompleted, elapsedMs);
    }

    if (options.onProgress) {
      options.onProgress(attemptsCompleted);
    }
    emitEstimate('progress', attemptsCompleted, elapsedMs, true);
  }

  const elapsedMs = Math.round(Date.now() - startMs);
  console.error('[PoW Solver] Max attempts exhausted after', elapsedMs, 'ms');
  emitEstimate('timeout', options.maxAttempts, elapsedMs, true);
  throw new SolverTimeoutError(options.maxAttempts, elapsedMs);
}

function resolveDifficultyBits(
  difficultyBits: number | undefined,
  targetHex: string
): number | null {
  if (
    typeof difficultyBits === 'number' &&
    Number.isFinite(difficultyBits) &&
    difficultyBits >= 0
  ) {
    return Math.floor(difficultyBits);
  }

  return inferDifficultyBitsFromTarget(targetHex);
}

function inferDifficultyBitsFromTarget(targetHex: string): number | null {
  if (!/^[0-9a-fA-F]{64}$/.test(targetHex)) {
    return null;
  }

  let bits = 0;
  for (const char of targetHex.toLowerCase()) {
    const nibble = Number.parseInt(char, 16);
    if (nibble === 0) {
      bits += 4;
      continue;
    }
    if (nibble < 2) return bits + 3;
    if (nibble < 4) return bits + 2;
    if (nibble < 8) return bits + 1;
    return bits;
  }

  return 256;
}

function createEstimateEmitter({
  options,
  startMs,
  maxAttempts,
  timeoutMs,
  difficultyBits,
}: {
  options: SolverOptions;
  startMs: number;
  maxAttempts: number;
  timeoutMs: number;
  difficultyBits: number | null;
}) {
  return (
    phase: SolverEstimate['phase'],
    attempts: number,
    elapsedMs: number,
    usingWasm: boolean
  ) => {
    if (!options.onEstimate) {
      return;
    }

    const hashRate = elapsedMs > 0 ? attempts / (elapsedMs / 1000) : 0;
    const expectedTotalAttempts =
      difficultyBits !== null && difficultyBits <= 52 ? 2 ** difficultyBits : null;

    let estimatedRemainingAttempts: number | null = null;
    let estimatedRemainingMs: number | null = null;
    let estimatedTotalMs: number | null = null;
    let estimatedCompletionAt: number | null = null;

    if (phase === 'complete') {
      estimatedRemainingAttempts = 0;
      estimatedRemainingMs = 0;
      estimatedTotalMs = elapsedMs;
      estimatedCompletionAt = startMs + elapsedMs;
    } else if (expectedTotalAttempts !== null && hashRate > 0) {
      estimatedRemainingAttempts = Math.max(expectedTotalAttempts - attempts, 0);
      estimatedRemainingMs = Math.round((estimatedRemainingAttempts / hashRate) * 1000);
      estimatedTotalMs = elapsedMs + estimatedRemainingMs;
      estimatedCompletionAt = startMs + elapsedMs + estimatedRemainingMs;
    }

    options.onEstimate({
      phase,
      usingWasm,
      difficultyBits,
      attempts,
      elapsedMs,
      hashRate,
      expectedTotalAttempts,
      estimatedRemainingAttempts,
      estimatedRemainingMs,
      estimatedTotalMs,
      estimatedCompletionAt,
      attemptProgress: Math.min(attempts / maxAttempts, 1),
      timeProgress: Math.min(elapsedMs / timeoutMs, 1),
    });
  };
}
