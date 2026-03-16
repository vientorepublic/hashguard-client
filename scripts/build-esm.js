#!/usr/bin/env node
/**
 * Convert CommonJS dist/index.js to ESM dist/index.mjs
 * using esbuild with format: esm
 */
import esbuild from 'esbuild';

async function buildESM() {
  try {
    await esbuild.build({
      entryPoints: ['src/index.ts'],
      outfile: 'dist/index.mjs',
      format: 'esm',
      target: 'es2020',
      sourcemap: true,
    });
    console.log('✓ Built dist/index.mjs (ESM)');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('✗ Failed to build ESM:', message);
    process.exit(1);
  }
}

buildESM();
