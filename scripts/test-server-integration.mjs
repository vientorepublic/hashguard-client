#!/usr/bin/env node
/**
 * Integration test: Issue a challenge from localhost:3000, solve it, and verify.
 * This tests the actual WASM solver against real server-generated targets.
 */

import { HashGuardClient } from '../dist/index.mjs';

const client = new HashGuardClient({
  baseUrl: 'http://localhost:3000',
  routePrefix: 'v1',
  timeout: 30_000,
});

async function runTest() {
  try {
    console.log('🚀 Starting server integration test...\n');

    // Step 1: Issue a challenge
    console.log('📝 Requesting challenge from server...');
    const challenge = await client.issueChallenge('integration-test');
    console.log('✓ Challenge received:', {
      challengeId: challenge.challengeId,
      seed: challenge.seed.substring(0, 16) + '...',
      difficultyBits: challenge.difficultyBits,
      targetHex: challenge.target.substring(0, 20) + '...',
      targetHexLen: challenge.target.length,
    });
    console.log();

    // Step 2: Solve the challenge
    console.log('⚙️  Solving challenge...');
    console.log('   Input: challengeId=' + challenge.challengeId);
    console.log('   Input: seed=' + challenge.seed.substring(0, 16) + '...');
    console.log(
      '   Input: targetHex=' +
        challenge.target.substring(0, 20) +
        '... (len=' +
        challenge.target.length +
        ')'
    );
    console.log();

    const solveResult = await Promise.race([
      client.execute('integration-test'),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Solver timeout (30s)')), 30_000)
      ),
    ]);

    console.log('✓ Challenge solved:', {
      nonce: solveResult.solveResult.nonce,
      hash: solveResult.solveResult.hash.substring(0, 20) + '...',
      attempts: solveResult.solveResult.attempts,
      solveTimeMs: solveResult.solveResult.solveTimeMs,
    });
    console.log();

    // Step 3: Verify proof token validity
    console.log('📋 Proof token verification:');
    console.log(
      '   Token:',
      solveResult.verification.proofToken.substring(0, 30) + '...'
    );
    console.log('   Expires:', solveResult.verification.expiresAt);
    console.log();

    console.log('✅ Server integration test PASSED\n');
    process.exit(0);
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

runTest();
