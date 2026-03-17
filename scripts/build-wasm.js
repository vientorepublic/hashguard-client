#!/usr/bin/env node
/**
 * Builds the Rust WASM crate and generates `src/wasm-pkg/wasm_binary.ts`
 * with the WASM binary embedded as a base64 string.
 *
 * Usage: node scripts/build-wasm.js
 *
 * Prerequisites:
 *   rustup target add wasm32-unknown-unknown
 *   cargo install wasm-pack
 */
import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

function run(cmd) {
  console.log(`$ ${cmd}`);
  execSync(cmd, { stdio: 'inherit', cwd: root });
}

// ── 0. Preflight checks ──────────────────────────────────────────────────────

try {
  execSync('wasm-pack --version', { stdio: 'pipe' });
} catch {
  console.error('\n❌  wasm-pack not found. Install it with:');
  console.error('      cargo install wasm-pack');
  console.error('   Or via the official installer:');
  console.error(
    '      curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh\n'
  );
  process.exit(1);
}

// Ensure the wasm32 target is available.
try {
  const targets = execSync('rustup target list --installed', { encoding: 'utf-8' });
  if (!targets.includes('wasm32-unknown-unknown')) {
    console.log('ℹ  Adding wasm32-unknown-unknown target...');
    run('rustup target add wasm32-unknown-unknown');
  }
} catch {
  // rustup might not be in PATH in some CI setups — proceed and let wasm-pack fail if needed.
}

// ── 1. Compile Rust → WASM ───────────────────────────────────────────────────

console.log('\n▶  Compiling Rust crate to WASM...\n');
run('wasm-pack build crate --target web --out-dir ../src/wasm-pkg --release');

// ── 2. Embed the binary as base64 ───────────────────────────────────────────

const wasmPath = join(root, 'src/wasm-pkg/hashguard_wasm_bg.wasm');
const wasmBytes = readFileSync(wasmPath);
const base64 = wasmBytes.toString('base64');
const sizeKb = (wasmBytes.length / 1024).toFixed(1);

const binaryTs =
  `// AUTO-GENERATED — do not edit manually.\n` +
  `// Regenerate by running: npm run build:wasm\n` +
  `export const WASM_BASE64 = '${base64}';\n`;
const binaryJs =
  `// AUTO-GENERATED — do not edit manually.\n` +
  `// Regenerate by running: npm run build:wasm\n` +
  `export const WASM_BASE64 = '${base64}';\n`;

writeFileSync(join(root, 'src/wasm-pkg/wasm_binary.ts'), binaryTs, 'utf-8');
writeFileSync(join(root, 'src/wasm-pkg/wasm_binary.js'), binaryJs, 'utf-8');

// ── 3. Patch the generated glue ──────────────────────────────────────────────
//
// wasm-pack --target web injects a `new URL('./hashguard_wasm_bg.wasm', import.meta.url)`
// fallback so browsers can fetch the .wasm file if init() is called without arguments.
// We always pass an explicit ArrayBuffer, so the URL is dead code.  Replacing it
// prevents esbuild from treating the .wasm file as a file-URL asset.

const gluePath = join(root, 'src/wasm-pkg/hashguard_wasm.js');
let glue = readFileSync(gluePath, 'utf-8');
const urlPattern =
  /module_or_path\s*=\s*new URL\(\s*['"]hashguard_wasm_bg\.wasm['"]\s*,\s*import\.meta\.url\s*\)\s*;/;

if (urlPattern.test(glue)) {
  glue = glue.replace(
    urlPattern,
    `throw new Error('[hashguard-wasm] init() requires an explicit ArrayBuffer — call initHashGuardWasm() instead of the raw init().');`
  );
  writeFileSync(gluePath, glue, 'utf-8');
  console.log(
    '\n✓  Patched   src/wasm-pkg/hashguard_wasm.js  (removed default URL fallback)'
  );
} else {
  console.log(
    '\nℹ  Glue already patched or URL pattern not found — no changes needed.'
  );
}

console.log(`✓  WASM binary  — ${sizeKb} KB`);
console.log(`✓  Generated    src/wasm-pkg/wasm_binary.ts`);
console.log(`✓  Generated    src/wasm-pkg/wasm_binary.js\n`);
