import { SolveResult, SolverOptions, SolverTimeoutError } from './types';
import { verifyProof, sha256hex } from './crypto';

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

  const startMs = performance.now();

  for (let nonce = 0; nonce < maxAttempts; nonce++) {
    if (verifyProof(challengeId, seed, String(nonce), targetHex)) {
      const solveTimeMs = Math.round(performance.now() - startMs);
      // Compute the hash for reporting
      const preimage = `${challengeId}:${seed}:${nonce}`;
      const hash = sha256hex(preimage);
      return {
        nonce: String(nonce),
        hash,
        attempts: nonce + 1,
        solveTimeMs,
      };
    }

    // Check wall-clock timeout
    if (nonce % progressInterval === 0) {
      const elapsedMs = performance.now() - startMs;
      if (elapsedMs > timeoutMs) {
        throw new SolverTimeoutError(nonce, Math.round(elapsedMs));
      }
      if (options.onProgress) {
        options.onProgress(nonce);
      }
    }
  }

  const elapsedMs = Math.round(performance.now() - startMs);
  throw new SolverTimeoutError(maxAttempts, elapsedMs);
}
