#!/usr/bin/env node
/**
 * payfetch — `.mcpb` (Claude Desktop MCP Bundle) build helper.
 *
 * Produces a SELF-CONTAINED desktop extension at `dist-mcpb/payfetch.mcpb`
 * (a zip with `manifest.json` at its root + a single bundled server file) that
 * Claude Desktop one-click-installs with NO `npm install`.
 *
 * STRATEGY — esbuild single-file bundle (chosen over a full node_modules stage):
 *   The prod-only dependency tree is ~130MB / ~176 packages; esbuild tree-shakes
 *   the reachable graph of the 5 runtime deps (@coinbase/cdp-sdk,
 *   @modelcontextprotocol/sdk, @x402/core, undici, viem) into ONE ~4MB ESM file.
 *   Verified empirically that both watch-items bundle cleanly:
 *     - undici inlines its llhttp WASM as base64 (no runtime `.wasm` file read),
 *       so the parser survives bundling.
 *     - @coinbase/cdp-sdk (the wallet SIGNING SDK) bundles fully; its transitive
 *       CJS deps (form-data → combined-stream) call `require('util')` at load
 *       time, which under `--format=esm` needs a real `require`. The banner below
 *       injects one via `createRequire` (builtins resolve with no node_modules).
 *
 * Pipeline (fully reproducible from `npm run build:mcpb`):
 *   1. tsc build            → dist/ (plain JS, resolvable `.js` specifiers)
 *   2. esbuild bundle       → dist-mcpb/stage/server/payfetch-mcp.mjs
 *   3. copy manifest        → dist-mcpb/stage/manifest.json  (single source of
 *                              truth: mcpb/manifest.json, entry = server/…mjs)
 *   4. mcpb validate + pack → dist-mcpb/payfetch.mcpb
 *
 * BUILD/PACKAGING ONLY — this file touches no money-path/guard/tool logic.
 */

import { build as esbuild } from "esbuild";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, ".."); // products/p3_payfetch
const DIST_ENTRY = join(ROOT, "dist", "bin", "payfetch-mcp.js");
const OUT_DIR = join(ROOT, "dist-mcpb");
const STAGE_DIR = join(OUT_DIR, "stage");
const SERVER_DIR = join(STAGE_DIR, "server");
// Bundle entry inside the .mcpb. `.mjs` so `node <file>` runs it as ESM with NO
// package.json "type" marker in the bundle. Must match mcpb/manifest.json.
const BUNDLE_ENTRY = join(SERVER_DIR, "payfetch-mcp.mjs");
const MANIFEST_SRC = join(ROOT, "mcpb", "manifest.json");
const MANIFEST_STAGE = join(STAGE_DIR, "manifest.json");
const MCPB_OUT = join(OUT_DIR, "payfetch.mcpb");
const MCPB_BIN = join(ROOT, "node_modules", ".bin", "mcpb");

// createRequire/dirname shim: makes externalized node builtins required by CJS
// deps resolve under `--format=esm`, with no node_modules alongside the bundle.
const BANNER = [
  "import { createRequire as __pfCreateRequire } from 'node:module';",
  "import { fileURLToPath as __pfFileURLToPath } from 'node:url';",
  "import { dirname as __pfDirname } from 'node:path';",
  "const require = __pfCreateRequire(import.meta.url);",
  "const __filename = __pfFileURLToPath(import.meta.url);",
  "const __dirname = __pfDirname(__filename);",
].join("\n");

function step(msg) {
  process.stderr.write(`[build:mcpb] ${msg}\n`);
}

function run(cmd, args) {
  execFileSync(cmd, args, { cwd: ROOT, stdio: "inherit" });
}

async function main() {
  // 1. tsc build → dist/ (reuses the canonical `npm run build`).
  step("tsc build → dist/");
  run("npm", ["run", "build"]);
  if (!existsSync(DIST_ENTRY)) {
    throw new Error(`expected built entry missing: ${DIST_ENTRY}`);
  }

  // Clean the staging tree (dist-mcpb/ is gitignored).
  rmSync(STAGE_DIR, { recursive: true, force: true });
  rmSync(MCPB_OUT, { force: true });
  mkdirSync(SERVER_DIR, { recursive: true });

  // 2. esbuild single-file bundle from the BUILT entry (plain JS specifiers).
  step("esbuild bundle → stage/server/payfetch-mcp.mjs");
  const result = await esbuild({
    entryPoints: [DIST_ENTRY],
    outfile: BUNDLE_ENTRY,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    banner: { js: BANNER },
    logLevel: "warning",
  });
  if (result.errors.length > 0) {
    throw new Error(`esbuild reported ${result.errors.length} error(s)`);
  }
  step(`esbuild warnings: ${result.warnings.length}`);

  // 3. Stage the manifest verbatim (single source of truth). Its entry_point +
  //    mcp_config.args already name server/payfetch-mcp.mjs.
  step("stage manifest.json");
  cpSync(MANIFEST_SRC, MANIFEST_STAGE);

  // 4. Validate the manifest, then pack the stage → dist-mcpb/payfetch.mcpb.
  step("mcpb validate");
  run(MCPB_BIN, ["validate", MANIFEST_STAGE]);
  step("mcpb pack → dist-mcpb/payfetch.mcpb");
  run(MCPB_BIN, ["pack", STAGE_DIR, MCPB_OUT]);

  const sizeMb = (statSync(MCPB_OUT).size / (1024 * 1024)).toFixed(2);
  step(`DONE → ${MCPB_OUT} (${sizeMb} MB)`);
}

main().catch((err) => {
  process.stderr.write(`[build:mcpb] FAILED: ${err?.message ?? err}\n`);
  process.exit(1);
});
