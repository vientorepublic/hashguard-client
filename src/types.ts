// ── Server response shapes ────────────────────────────────────────────────────

/** Response from POST /v1/pow/challenges */
export interface Challenge {
  challengeId: string;
  algorithm: 'sha256';
  seed: string;
  difficultyBits: number;
  target: string; // 64-char lowercase hex (256-bit target)
  issuedAt: string; // ISO 8601
  expiresAt: string; // ISO 8601
}

/** Response from POST /v1/pow/verifications */
export interface VerificationResult {
  proofToken: string;
  expiresAt: string; // ISO 8601
}

/** Public JWK exposed by the HashGuard server for stateless proof-token verification. */
export interface ProofTokenVerificationKey {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  use: 'sig';
  alg: 'ES256';
  kid: string;
  key_ops?: ['verify'];
}

/** Standard JWKS document exposed by the HashGuard server. */
export interface ProofTokenJwks {
  keys: ProofTokenVerificationKey[];
}

/** Response from POST /v1/pow/assertions/introspect */
export interface IntrospectResult {
  valid: boolean;
  subject?: string;
  context?: string;
  issuedAt?: string;
  expiresAt?: string;
}

// ── Local results ─────────────────────────────────────────────────────────────

/** Statistics returned after the local nonce-search completes. */
export interface SolveResult {
  /** The nonce string that satisfies SHA-256(challengeId:seed:nonce) ≤ target */
  nonce: string;
  /** The winning SHA-256 hash as lowercase hex */
  hash: string;
  /** Total number of nonce candidates tried (including the winning one) */
  attempts: number;
  /** Wall-clock time spent solving in milliseconds */
  solveTimeMs: number;
}

/** Progress/ETA snapshot emitted by the local solver. */
export interface SolverEstimate {
  /** Emission phase. */
  phase: 'progress' | 'complete' | 'timeout';
  /** Whether the active solver path is WASM-backed. */
  usingWasm: boolean;
  /** Difficulty bits used for the estimate, if known. */
  difficultyBits: number | null;
  /** Attempts completed so far. */
  attempts: number;
  /** Wall-clock time elapsed in milliseconds. */
  elapsedMs: number;
  /** Current throughput in hashes per second. */
  hashRate: number;
  /** Heuristic expected total attempts for the current difficulty. */
  expectedTotalAttempts: number | null;
  /** Heuristic remaining attempts until completion. */
  estimatedRemainingAttempts: number | null;
  /** Heuristic remaining time in milliseconds. */
  estimatedRemainingMs: number | null;
  /** Heuristic total solve time in milliseconds. */
  estimatedTotalMs: number | null;
  /** Estimated completion timestamp in epoch milliseconds. */
  estimatedCompletionAt: number | null;
  /** Fraction of the attempt budget already consumed, clamped to [0, 1]. */
  attemptProgress: number;
  /** Fraction of the time budget already consumed, clamped to [0, 1]. */
  timeProgress: number;
}

/** Return value of {@link HashGuardClient.execute} – combines all three steps. */
export interface PowFlowResult {
  challenge: Challenge;
  solveResult: SolveResult;
  verification: VerificationResult;
}

// ── Configuration ─────────────────────────────────────────────────────────────

/** Constructor options for {@link HashGuardClient}. */
export interface HashGuardClientOptions {
  /**
   * Base URL of the HashGuard server.
   * @example "https://hashguard.viento.me"
   */
  baseUrl: string;
  /**
   * Global route prefix used by the server (default: `"v1"`).
   * Change this only if the server was configured with a different prefix.
   */
  routePrefix?: string;
  /** HTTP request timeout in milliseconds (default: `10_000`). */
  timeout?: number;
  /** Extra headers appended to every request (e.g. `Authorization`). */
  headers?: Record<string, string>;
  /** Optional public JWK used for stateless proof-token validation. */
  proofTokenVerificationKey?: ProofTokenVerificationKey;
  /** Optional JWKS document used for stateless proof-token validation. */
  proofTokenJwks?: ProofTokenJwks;
}

/** Options controlling the local PoW solver. */
export interface SolverOptions {
  /**
   * Maximum number of nonce candidates to try before giving up
   * (default: `200_000_000`).
   *
   * At 26-bit difficulty the expected nonce count is ~67 M; 200 M covers the
   * ~95th-percentile worst case. `timeoutMs` acts as an additional safety net.
   */
  maxAttempts?: number;
  /**
   * Wall-clock time budget in milliseconds (default: `300_000`).
   * The solver throws {@link SolverTimeoutError} if this is exceeded.
   *
   * Matches the server-side `POW_CHALLENGE_TTL_SECONDS` default of 300 s so
   * the solver never gives up before the challenge itself expires.
   */
  timeoutMs?: number;
  /**
   * Optional explicit difficulty bits used for ETA estimation.
   * If omitted, the solver infers an estimate from `targetHex`.
   */
  difficultyBits?: number;
  /**
   * Called every `progressInterval` attempts so the caller can
   * update a progress bar or cancel early.
   */
  onProgress?: (attempts: number) => void;
  /**
   * Called with heuristic ETA/progress snapshots during solving and again when
   * the solver completes or times out.
   */
  onEstimate?: (estimate: SolverEstimate) => void;
  /**
   * How often to invoke `onProgress`, measured in attempts
   * (default: `100_000`).
   */
  progressInterval?: number;
}

// ── Errors ────────────────────────────────────────────────────────────────────

/**
 * Thrown by the solver when it exhausts `maxAttempts` or `timeoutMs`
 * without finding a valid nonce.
 */
export class SolverTimeoutError extends Error {
  constructor(
    /** Number of nonce candidates tried before giving up. */
    public readonly attempts: number,
    /** Wall-clock time elapsed in milliseconds. */
    public readonly elapsedMs: number
  ) {
    super(`PoW solver gave up after ${attempts} attempts (${elapsedMs}ms)`);
    this.name = 'SolverTimeoutError';
    // Restore prototype chain for instanceof checks when targeting ES5.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the HashGuard server returns a non-2xx response.
 */
export class HashGuardError extends Error {
  constructor(
    /** HTTP status code (0 = network / timeout error). */
    public readonly status: number,
    /** Server-side error code, e.g. `"POW_INVALID_PROOF"`. */
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = 'HashGuardError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── Token Validation ──────────────────────────────────────────────────────────

/** Result of token validation on the server side. */
export interface TokenValidationResult {
  /** Whether the token is valid and can be used. */
  valid: boolean;
  /** The subject/context of the token (if valid). */
  subject?: string;
  /** Additional context provided when the token was issued. */
  context?: string;
  /** Token issued time (ISO 8601). */
  issuedAt?: string;
  /** Token expiration time (ISO 8601). */
  expiresAt?: string;
  /** Error message if validation failed. */
  error?: string;
}

/** Options for token validation. */
export interface TokenValidationOptions {
  /** Whether to consume the token after validation (single-use). */
  consume?: boolean;
  /** Max allowed age in milliseconds; if exceeded, token is invalid. */
  maxAgeMs?: number;
  /** Public JWK used for stateless JWT signature verification. */
  verificationKey?: ProofTokenVerificationKey;
}

/** Options for resource access control. */
export interface ResourceAccessOptions {
  /** Proof token from the client. */
  token: string;
  /** Optional context to match against (must match what was in challenge). */
  context?: string;
  /** Whether to consume the token (default: true). */
  consume?: boolean;
  /** Max allowed age in milliseconds. */
  maxAgeMs?: number;
}

/** Result of resource access check. */
export interface ResourceAccessResult {
  /** Whether access is granted. */
  allowed: boolean;
  /** Reason if access was denied. */
  reason?: string;
  /** Token validation details. */
  validationResult?: TokenValidationResult;
}
