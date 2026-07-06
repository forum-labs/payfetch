#!/usr/bin/env node
/**
 * payfetch — operator CLI (SPEC §5.4, §8, §9). Three subcommands:
 *
 *   payfetch clear-autodeny <host>   Reset a host's auto-deny circuit breaker
 *                                    (SPEC §5.4 operator clear — NOT an MCP tool;
 *                                    the agent may never un-deny a host).
 *   payfetch status                  Print today's spend_status as JSON.
 *   payfetch verify                  Verify the ledger tamper-evidence sidecar
 *                                    (SPEC §8/§14, fix L14); exits non-zero if any
 *                                    month fails integrity.
 *
 * Unknown subcommands print usage and exit non-zero. The CLI reads the SAME
 * environment as the MCP server (config.ts). Run via `npx tsx bin/payfetch.ts`.
 */

import {
  buildFromEnv,
  resolveDataDir,
  scrubSecrets,
  ConfigError,
} from "../src/config.js";
import { SCAFFOLD_BASE_URL } from "../src/core/constants.js";
import { realFs } from "../src/core/fs.js";
import { Ledger, LedgerLockedError } from "../src/core/ledger.js";
import { clearAutoDeny, createPayfetch } from "../src/index.js";
import { runReport } from "../src/report/report.js";

function usage(message?: string): never {
  if (message) process.stderr.write(`payfetch: ${message}\n`);
  process.stderr.write(
    "usage:\n" +
      "  payfetch clear-autodeny <host>   reset a host's auto-deny (SPEC §5.4)\n" +
      "  payfetch status                  print today's spend status (JSON)\n" +
      "  payfetch verify                  verify the ledger integrity sidecar (SPEC §8/§14)\n" +
      "  payfetch report <receiptId>      report a paid outcome (opt-in; --yes skips prompt)\n",
  );
  process.exit(message ? 1 : 0);
}

/** Read one line from stdin and resolve true iff it is y/yes (default: no). */
function promptYesNo(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    process.stdin.resume();
    process.stdin.once("data", (buf: Buffer) => {
      process.stdin.pause();
      const answer = buf.toString().trim().toLowerCase();
      resolve(answer === "y" || answer === "yes");
    });
  });
}

async function cmdClearAutoDeny(host: string | undefined): Promise<void> {
  if (!host) usage("clear-autodeny requires a <host> argument");
  const dataDir = resolveDataDir(process.env);
  const cleared = clearAutoDeny(dataDir, host!);
  process.stdout.write(`${JSON.stringify({ host, cleared }, null, 2)}\n`);
}

async function cmdStatus(): Promise<void> {
  let pf;
  try {
    pf = createPayfetch(buildFromEnv(process.env));
  } catch (err) {
    if (err instanceof LedgerLockedError) {
      process.stderr.write(
        "payfetch: the MCP server appears to be running (ledger is locked). " +
          "Use the spend_status tool, or stop the server first.\n",
      );
      process.exit(1);
    }
    throw err;
  }
  try {
    const status = await pf.status();
    process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
  } finally {
    pf.close();
  }
}

async function cmdVerify(): Promise<void> {
  const dataDir = resolveDataDir(process.env);
  // Read-only, but acquire the single-writer lock like `status` so we never race a
  // running server mid-append (which could look like a spurious sidecar gap). A
  // directly-constructed Ledger is used because verifyIntegrity is not on the
  // public Payfetch surface (SPEC §8/§14).
  const ledger = new Ledger(realFs, dataDir, () => Date.now());
  try {
    ledger.acquireLock();
  } catch (err) {
    if (err instanceof LedgerLockedError) {
      process.stderr.write(
        "payfetch: the MCP server appears to be running (ledger is locked). " +
          "Stop the server first to verify the ledger.\n",
      );
      process.exit(1);
    }
    throw err;
  }
  let ok: boolean;
  try {
    const report = ledger.verifyIntegrity();
    ok = report.ok;
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } finally {
    ledger.releaseLock();
  }
  if (!ok) process.exit(1);
}

async function cmdReport(rest: string[]): Promise<void> {
  const receiptId = rest.find((a) => !a.startsWith("-"));
  if (!receiptId) usage("report requires a <receiptId> argument");
  const autoYes = rest.includes("--yes") || rest.includes("-y");

  // Resolve the wallet signer the SAME way the MCP server does (refuses without a
  // configured signer). Reporting is signed by the payment wallet (Option C).
  const signer = buildFromEnv(process.env).deps.signer;
  const dataDir = resolveDataDir(process.env);
  // Read-only over the ledger files (no lock: we never write; a running server is
  // fine to read alongside — the JSONL is append-only).
  const receipts = new Ledger(realFs, dataDir, () => Date.now()).readAllReceipts();

  const outcome = await runReport({
    readReceipts: () => receipts,
    receiptId: receiptId!,
    signer,
    fetchImpl: (input, init) => fetch(input, init),
    baseUrl: SCAFFOLD_BASE_URL,
    confirm: async () =>
      autoYes ? true : await promptYesNo("Submit this report? [y/N] "),
    out: (line) => process.stdout.write(`${line}\n`),
    err: (line) => process.stderr.write(`${line}\n`),
  });

  if (
    outcome.kind === "not_found" ||
    outcome.kind === "not_reportable" ||
    outcome.kind === "submit_failed"
  ) {
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "clear-autodeny":
      return cmdClearAutoDeny(rest[0]);
    case "status":
      return cmdStatus();
    case "verify":
      return cmdVerify();
    case "report":
      return cmdReport(rest);
    default:
      usage(cmd ? `unknown subcommand: ${cmd}` : "no subcommand given");
  }
}

main().catch((err: unknown) => {
  // ConfigError messages already self-identify ("payfetch: ..."); don't double-prefix.
  const raw = scrubSecrets(String((err as Error)?.message ?? err), []);
  process.stderr.write(err instanceof ConfigError ? `${raw}\n` : `payfetch: ${raw}\n`);
  process.exit(1);
});
