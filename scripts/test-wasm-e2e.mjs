#!/usr/bin/env node
import assert from 'node:assert/strict';

import {
  initHashGuardWasm,
  isWasmReady,
  sha256hex,
  solvePow,
  verifyProof,
} from '../dist/index.mjs';

async function run() {
  const ok = await initHashGuardWasm();
  assert.equal(ok, true, 'initHashGuardWasm() should return true');
  assert.equal(isWasmReady(), true, 'isWasmReady() should be true after init');

  // SHA-256("abc") official vector
  const expectedSha256 =
    'ba7816bf8f01cfea414140de5dae2223' + 'b00361a396177a9cb410ff61f20015ad';
  assert.equal(sha256hex('abc'), expectedSha256, 'SHA-256 test vector mismatch');

  const challengeId = 'e2e-challenge';
  const seed = 'e2e-seed';
  const easyTarget = 'ffff' + 'f'.repeat(60);

  const solved = solvePow(challengeId, seed, easyTarget, {
    maxAttempts: 10_000,
    timeoutMs: 10_000,
    progressInterval: 100,
  });

  assert.equal(
    verifyProof(challengeId, seed, solved.nonce, easyTarget),
    true,
    'Solved nonce must satisfy target'
  );

  const boundNonce = '123';
  const boundaryHash = sha256hex(`${challengeId}:${seed}:${boundNonce}`);
  assert.equal(
    verifyProof(challengeId, seed, boundNonce, boundaryHash),
    true,
    'Hash == target boundary condition must pass'
  );

  console.log('WASM e2e passed');
}

run().catch((err) => {
  console.error('WASM e2e failed');
  console.error(err);
  process.exit(1);
});
