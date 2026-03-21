import {
  Challenge,
  VerificationResult,
  IntrospectResult,
  PowFlowResult,
  SolverOptions,
  HashGuardClientOptions,
  HashGuardError,
  ProofTokenVerificationKey,
  TokenValidationResult,
  ResourceAccessResult,
  ResourceAccessOptions,
} from './types';
import { solvePow } from './solver';
import { TokenValidator } from './token-validator';
import { ResourceGuard } from './resource-guard';

/**
 * Official client for the HashGuard Proof-of-Work CAPTCHA service.
 *
 * Typical usage:
 * ```ts
 * const client = new HashGuardClient({ baseUrl: 'https://pow.example.com' });
 * const result = await client.execute({ context: 'login' });
 * console.log('Proof token:', result.verification.proofToken);
 * ```
 */
export class HashGuardClient {
  private readonly baseUrl: string;
  private readonly routePrefix: string;
  private readonly timeout: number;
  private readonly headers: Record<string, string>;
  private proofTokenVerificationKey?: ProofTokenVerificationKey;

  constructor(options: HashGuardClientOptions) {
    if (!options.baseUrl) {
      throw new Error('baseUrl is required');
    }
    this.baseUrl = options.baseUrl.replace(/\/$/, ''); // strip trailing slash
    this.routePrefix = options.routePrefix ?? 'v1';
    this.timeout = options.timeout ?? 10_000;
    this.headers = options.headers ?? {};
    this.proofTokenVerificationKey = options.proofTokenVerificationKey;
  }

  /**
   * Complete PoW workflow: issue → solve → verify.
   *
   * Steps:
   * 1. Request a new challenge from the server.
   * 2. Solve it locally using the PoW solver.
   * 3. Submit the solution and receive a proof token.
   *
   * @param context - Arbitrary string to categorize the challenge (e.g. "login").
   * @param solverOptions - Options for controlling the local solver (timeouts, progress).
   */
  async execute(
    context?: string,
    solverOptions?: SolverOptions
  ): Promise<PowFlowResult> {
    const challenge = await this.issueChallenge(context);
    const solveResult = solvePow(
      challenge.challengeId,
      challenge.seed,
      challenge.target,
      {
        ...solverOptions,
        difficultyBits: solverOptions?.difficultyBits ?? challenge.difficultyBits,
      }
    );
    const verification = await this.verifyChallenge(
      challenge.challengeId,
      solveResult.nonce,
      solveResult.solveTimeMs
    );

    return { challenge, solveResult, verification };
  }

  /**
   * Issues a new PoW challenge.
   *
   * The returned challenge contains:
   * - A unique `challengeId` (UUID)
   * - A random `seed` (32-byte hex)
   * - A difficulty level (`difficultyBits`, typically 20–26)
   * - A target value (`target`, 64-char hex)
   *
   * Challenges expire after a server-configured TTL (default: 10 minutes).
   */
  async issueChallenge(context?: string): Promise<Challenge> {
    const url = `${this.baseUrl}/${this.routePrefix}/pow/challenges`;
    const payload = context ? { context } : {};

    const response = await this.request<Challenge>(url, {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    return response;
  }

  /**
   * Verifies a solved challenge and returns a proof token.
   *
   * The proof token is a signed JWT that is single-use (consumed on first verification).
   * It can be sent to your application backend which calls {@link introspectToken}
   * to verify that the client has indeed solved the PoW.
   *
   * @param challengeId - The challenge ID returned by {@link issueChallenge}.
   * @param nonce - The winning nonce found by the solver.
   * @param solveTimeMs - Optional: time spent solving, for metrics.
   */
  async verifyChallenge(
    challengeId: string,
    nonce: string,
    solveTimeMs?: number
  ): Promise<VerificationResult> {
    const url = `${this.baseUrl}/${this.routePrefix}/pow/verifications`;
    const payload: Record<string, unknown> = { challengeId, nonce };
    if (typeof solveTimeMs === 'number') {
      payload.clientMetrics = { solveTimeMs };
    }

    const response = await this.request<VerificationResult>(url, {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    return response;
  }

  /**
   * Introspects a proof token on the server side.
   *
   * Your application backend should call this endpoint after receiving a proof token
   * from the client. The token is consumed (single-use policy) by default; pass
   * `consume: false` to inspect without consuming.
   *
   * @param proofToken - The token returned by {@link verifyChallenge}.
   * @param consume - Whether to consume the token (default: `true`).
   */
  async introspectToken(proofToken: string, consume = true): Promise<IntrospectResult> {
    const url = `${this.baseUrl}/${this.routePrefix}/pow/assertions/introspect`;

    const response = await this.request<IntrospectResult>(url, {
      method: 'POST',
      body: JSON.stringify({ proofToken, consume }),
    });

    return response;
  }

  /**
   * Fetches and caches the public JWK used for stateless proof-token verification.
   */
  async getProofTokenVerificationKey(
    forceRefresh = false
  ): Promise<ProofTokenVerificationKey> {
    if (this.proofTokenVerificationKey && !forceRefresh) {
      return this.proofTokenVerificationKey;
    }

    const url = `${this.baseUrl}/${this.routePrefix}/pow/assertions/verification-key`;
    const response = await this.request<ProofTokenVerificationKey>(url, {
      method: 'GET',
    });

    this.proofTokenVerificationKey = response;
    return response;
  }

  /**
   * Low-level HTTP helper.
   */
  private async request<T>(url: string, options: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'content-type': 'application/json',
          ...this.headers,
          ...((options.headers as Record<string, string>) || {}),
        },
      });

      const data = (await response.json()) as Record<string, unknown>;

      if (!response.ok) {
        const errorCode = (data.code as string) || 'UNKNOWN_ERROR';
        const errorMessage = (data.message as string) || `HTTP ${response.status}`;
        throw new HashGuardError(response.status, errorCode, errorMessage);
      }

      return data as T;
    } catch (error) {
      if (error instanceof HashGuardError) {
        throw error;
      }
      if (error instanceof TypeError) {
        // Network error (including abort timeout)
        throw new HashGuardError(0, 'NETWORK_ERROR', error.message);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Validates a proof token locally without calling the server.
   *
   * WARNING: This does NOT verify the JWT signature. Use this only for quick validation
   * (e.g., checking if a token is expired). For authoritative validation,
   * use {@link introspectToken}.
   *
   * @param proofToken - The proof token to validate.
   * @param maxAgeMs - Max allowed age in milliseconds.
   */
  validateTokenLocally(proofToken: string, maxAgeMs?: number): TokenValidationResult {
    return TokenValidator.validateLocal(proofToken, { maxAgeMs });
  }

  /**
   * Validates a proof token statelessly using the server's public verification key.
   *
   * This verifies JWT signature and claims locally, but cannot detect whether the
   * token has already been consumed. Use {@link introspectToken} for single-use checks.
   */
  async validateTokenStatelessly(
    proofToken: string,
    maxAgeMs?: number
  ): Promise<TokenValidationResult> {
    const verificationKey = await this.getProofTokenVerificationKey();
    return TokenValidator.validateStateless(proofToken, {
      maxAgeMs,
      verificationKey,
    });
  }

  /**
   * Creates a ResourceGuard instance for protecting resources.
   *
   * @param cacheOptions - Optional token cache configuration.
   * @returns A ResourceGuard instance bound to this client.
   */
  createResourceGuard(cacheOptions?: {
    maxEntries?: number;
    ttlMs?: number;
    autoCleanupMs?: number | null;
  }): ResourceGuard {
    return new ResourceGuard(this, cacheOptions);
  }

  /**
   * Checks if a token can be used to access a resource.
   *
   * Higher-level convenience method that wraps ResourceGuard functionality.
   *
   * @param token - The proof token.
   * @param options - Access control options (context, consume, maxAge).
   */
  async checkResourceAccess(
    token: string,
    options: ResourceAccessOptions
  ): Promise<ResourceAccessResult> {
    const guard = this.createResourceGuard();
    try {
      return await guard.checkAccess(token, options);
    } finally {
      guard.destroy();
    }
  }
}
