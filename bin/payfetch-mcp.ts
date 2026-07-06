#!/usr/bin/env node
/**
 * payfetch-mcp — stdio MCP server entrypoint (SPEC §9). Loads the env config,
 * builds the engine, and serves the five tools over stdio. Thin: all wiring is
 * in src/mcp/server.ts. Run via `npx tsx bin/payfetch-mcp.ts` (the package runs
 * on tsx — Node cannot resolve the .js→.ts import specifiers natively).
 */

import { scrubSecrets } from "../src/config.js";
import { runStdioServer } from "../src/mcp/server.js";

runStdioServer().catch((err: unknown) => {
  // Config refusals already self-identify ("payfetch: ..."); avoid double-prefix.
  const message = scrubSecrets(String((err as Error)?.message ?? err), []);
  const line = message.startsWith("payfetch") ? message : `payfetch-mcp: fatal: ${message}`;
  process.stderr.write(`${line}\n`);
  process.exit(1);
});
