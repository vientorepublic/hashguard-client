#!/usr/bin/env node
/**
 * Dual build: ESM (dist/index.mjs) + CJS (dist/index.cjs)
 */
import esbuild from 'esbuild';

const sharedOptions = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  target: 'es2020',
  sourcemap: true,
  platform: 'node',
};

async function build() {
  try {
    await esbuild.build({
      ...sharedOptions,
      outfile: 'dist/index.mjs',
      format: 'esm',
    });
    console.log('✓ Built dist/index.mjs (ESM)');

    await esbuild.build({
      ...sharedOptions,
      outfile: 'dist/index.cjs',
      format: 'cjs',
    });
    console.log('✓ Built dist/index.cjs (CJS)');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('✗ Build failed:', message);
    process.exit(1);
  }
}

build();
