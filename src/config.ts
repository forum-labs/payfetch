/**
 * P3′ payfetch — environment → engine configuration (SPEC §12). The composition
 * root's env reader: it resolves EXACTLY ONE wallet signer source, the data dir,
 * the test/approver/via flags, and assembles the `createPayfetch` options.
 *
 * `buildFromEnv` takes an env RECORD (never `process.env` directly) plus an
 * injectable IO seam, so signer selection and refusals are unit-testable with no
 * process/disk coupling.
 *
 * Invariants (SPEC §12):
 *  - EXACTLY ONE signer source among PAYFETCH_PRIVATE_KEY | PAYFETCH_KEY_FILE |
 *    PAYFETCH_CDP_* . Zero or ambiguous → refuse to start with a clear error that
 *    NAMES the three options (payfetch never guesses which wallet to spend from).
 *  - PAYFETCH_KEY_FILE: refuse to start if the file is group/world-readable
 *    (POSIX mode check) — sloppy key handling is not normalized.
 *  - Key material NEVER appears in an error message or log: signer-construction
 *    errors are wrapped by `scrubSecrets`, which redacts the provided secret
 *    literals AND any key-shaped substring. The refusal errors themselves name
 *    only ENV VAR NAMES, never values.
 *  - `deps.log` writes to STDERR only (stdout is the MCP protocol channel) and is
 *    never handed key material (SPEC §1/§12).
 */

import { randomBytes } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { homedir as osHomedir } from "node:os";
import { join } from "node:path";

import { NONCE_BYTES } from "./core/constants.js";
import { CdpServerWalletSigner } from "./payer/signer_cdp.js";
import { LocalKeySigner } from "./payer/signer_local.js";
import type { PayfetchDeps, WalletSigner } from "./payer/types.js";
import type { CreatePayfetchOpts } from "./index.js";

// ---------------------------------------------------------------------------
// Environment variable names (SPEC §12) — one place, never inlined
// ---------------------------------------------------------------------------

/** The SPEC §12 environment variable names payfetch reads. */
export const ENV = {
  PRIVATE_KEY: "PAYFETCH_PRIVATE_KEY",
  KEY_FILE: "PAYFETCH_KEY_FILE",
  CDP_API_KEY_ID: "PAYFETCH_CDP_API_KEY_ID",
  CDP_API_KEY_SECRET: "PAYFETCH_CDP_API_KEY_SECRET",
  CDP_WALLET_SECRET: "PAYFETCH_CDP_WALLET_SECRET",
  CDP_ACCOUNT_NAME: "PAYFETCH_CDP_ACCOUNT_NAME",
  DATA_DIR: "PAYFETCH_DATA_DIR",
  TEST_MODE: "PAYFETCH_TEST_MODE",
  APPROVER: "PAYFETCH_APPROVER",
  VIA: "PAYFETCH_VIA",
} as const;

/** Default data-dir directory name under the operator's home (SPEC §12). */
export const DEFAULT_DATA_DIR_NAME = ".payfetch";
/** PAYFETCH_APPROVER must equal this exact value to enable T5 approve/deny (SPEC §9). */
export const APPROVER_ENABLED_VALUE = "1";
/** POSIX group+world permission bits; a key file with ANY set is refused (SPEC §12). */
const GROUP_WORLD_PERMS_MASK = 0o077;
/** Minimum secret length the literal scrub will redact (avoids nuking short words). */
const MIN_SCRUB_SECRET_LEN = 6;

export type EnvRecord = Record<string, string | undefined>;

// ---------------------------------------------------------------------------
// IO seam — the effectful bits, injectable for tests
// ---------------------------------------------------------------------------

/** Effectful dependencies of `buildFromEnv` (real impl below; fakeable in tests). */
export type ConfigIo = {
  /** Read a UTF-8 file's contents. Throws (caller wraps) if unreadable. */
  readText: (path: string) => string;
  /** POSIX `st_mode` bits for a path, or null if the path is absent. */
  statMode: (path: string) => number | null;
  /** The operator's home directory (for the default data dir). */
  homedir: () => string;
  /** Runtime `fetch` (guard egress; the paying-fetch transport is DNS-pinned in index). */
  fetch: typeof fetch;
  /** Epoch-ms clock. */
  now: () => number;
  /** 32-byte CSPRNG source (nonces + install id; SPEC §2/§12). */
  random: () => Uint8Array;
  /** Structured log sink → STDERR only (never stdout, never key material). */
  log: PayfetchDeps["log"];
};

/** The production IO seam: node:fs / node:os / global fetch / node:crypto / stderr. */
export function realConfigIo(): ConfigIo {
  return {
    readText: (path) => readFileSync(path, "utf8"),
    statMode: (path) => {
      try {
        return statSync(path).mode;
      } catch (err) {
        if ((err as { code?: string }).code === "ENOENT") return null;
        throw err;
      }
    },
    homedir: () => osHomedir(),
    fetch: (...args: Parameters<typeof fetch>) => fetch(...args),
    now: () => Date.now(),
    random: () => Uint8Array.from(randomBytes(NONCE_BYTES)),
    log: (msg, fields) => {
      // STDERR only: stdout carries the MCP JSON-RPC stream (SPEC §9).
      process.stderr.write(`${JSON.stringify({ ts: Date.now(), msg, ...(fields ?? {}) })}\n`);
    },
  };
}

// ---------------------------------------------------------------------------
// Errors & scrubbing (SPEC §12 key hygiene)
// ---------------------------------------------------------------------------

/** A startup-refusal error (SPEC §12). Its message NEVER contains key material. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * Redact key material from a string bound for an error/log (SPEC §12). First the
 * exact provided secret literals, then any key-shaped substring (long 0x-hex,
 * long bare hex runs, long base64url tokens). Defense-in-depth: even if an
 * upstream library echoes a secret we did not anticipate, the shape catches it.
 */
export function scrubSecrets(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (s && s.length >= MIN_SCRUB_SECRET_LEN) out = out.split(s).join("[redacted]");
  }
  out = out.replace(/0x[0-9a-fA-F]{16,}/g, "0x[redacted]");
  out = out.replace(/\b[0-9a-fA-F]{32,}\b/g, "[redacted]");
  out = out.replace(/\b[A-Za-z0-9_-]{40,}\b/g, "[redacted]");
  return out;
}

// ---------------------------------------------------------------------------
// Signer source selection (pure — no IO, unit-testable)
// ---------------------------------------------------------------------------

export type SignerSource = "private_key" | "key_file" | "cdp";

function nonEmpty(v: string | undefined): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

const NO_SIGNER_MSG =
  "payfetch: no wallet signer configured. Set EXACTLY ONE of: " +
  "(1) PAYFETCH_PRIVATE_KEY (0x-hex private key), " +
  "(2) PAYFETCH_KEY_FILE (path to a mode-600 key file), or " +
  "(3) PAYFETCH_CDP_API_KEY_ID + PAYFETCH_CDP_API_KEY_SECRET + PAYFETCH_CDP_WALLET_SECRET " +
  "(Coinbase CDP server wallet). (SPEC §12)";

/**
 * Determine which single signer source is configured (SPEC §12). Throws a
 * `ConfigError` on zero sources, ambiguity (more than one), or an incomplete CDP
 * source. CDP "presence" is ANY of the three required CDP vars — so a partial CDP
 * config is a hard refusal, never a silent fallthrough (never guess the wallet).
 */
export function selectSignerSource(env: EnvRecord): SignerSource {
  const hasPk = nonEmpty(env[ENV.PRIVATE_KEY]);
  const hasKf = nonEmpty(env[ENV.KEY_FILE]);
  const cdpParts: Array<[string, boolean]> = [
    [ENV.CDP_API_KEY_ID, nonEmpty(env[ENV.CDP_API_KEY_ID])],
    [ENV.CDP_API_KEY_SECRET, nonEmpty(env[ENV.CDP_API_KEY_SECRET])],
    [ENV.CDP_WALLET_SECRET, nonEmpty(env[ENV.CDP_WALLET_SECRET])],
  ];
  const cdpAny = cdpParts.some(([, present]) => present);
  const cdpAll = cdpParts.every(([, present]) => present);

  const present: SignerSource[] = [];
  if (hasPk) present.push("private_key");
  if (hasKf) present.push("key_file");
  if (cdpAny) present.push("cdp");

  if (present.length === 0) throw new ConfigError(NO_SIGNER_MSG);
  if (present.length > 1) {
    throw new ConfigError(
      `payfetch: multiple wallet signer sources set (${present.join(", ")}). ` +
        "Set EXACTLY ONE — payfetch never guesses which wallet to spend from. " +
        "Options: PAYFETCH_PRIVATE_KEY | PAYFETCH_KEY_FILE | PAYFETCH_CDP_* . (SPEC §12)",
    );
  }
  if (present[0] === "cdp" && !cdpAll) {
    const missing = cdpParts.filter(([, p]) => !p).map(([name]) => name);
    throw new ConfigError(
      `payfetch: CDP signer selected but incomplete — missing ${missing.join(", ")}. ` +
        "All of PAYFETCH_CDP_API_KEY_ID, PAYFETCH_CDP_API_KEY_SECRET, " +
        "PAYFETCH_CDP_WALLET_SECRET are required. (SPEC §12)",
    );
  }
  return present[0];
}

// ---------------------------------------------------------------------------
// Signer construction (effectful — key-file perms check, viem/CDP wiring)
// ---------------------------------------------------------------------------

/** Build a LocalKeySigner from a 0x-hex key; scrub any viem validation error. */
function newLocalSigner(key: string, secrets: string[]): WalletSigner {
  try {
    return new LocalKeySigner(key as `0x${string}`);
  } catch (err) {
    const scrubbed = scrubSecrets(`${(err as Error).message}`, secrets);
    throw new ConfigError(`payfetch: invalid private key — ${scrubbed} (SPEC §12)`);
  }
}

function buildSigner(source: SignerSource, env: EnvRecord, io: ConfigIo): WalletSigner {
  if (source === "private_key") {
    const key = env[ENV.PRIVATE_KEY]!.trim();
    return newLocalSigner(key, [key]);
  }
  if (source === "key_file") {
    const path = env[ENV.KEY_FILE]!;
    const mode = io.statMode(path);
    if (mode === null) {
      throw new ConfigError(`payfetch: PAYFETCH_KEY_FILE not found at "${path}". (SPEC §12)`);
    }
    if ((mode & GROUP_WORLD_PERMS_MASK) !== 0) {
      throw new ConfigError(
        `payfetch: refusing to start — PAYFETCH_KEY_FILE "${path}" is group/world-readable ` +
          `(mode ${(mode & 0o777).toString(8).padStart(3, "0")}). ` +
          "Run: chmod 600 <file>. (SPEC §12)",
      );
    }
    let contents: string;
    try {
      contents = io.readText(path);
    } catch (err) {
      throw new ConfigError(
        `payfetch: could not read PAYFETCH_KEY_FILE "${path}": ${(err as Error).message}. (SPEC §12)`,
      );
    }
    const key = contents.trim();
    return newLocalSigner(key, [key, contents]);
  }
  // source === "cdp" — the constructor is lazy (no network, no throw; SPEC §12).
  return new CdpServerWalletSigner({
    apiKeyId: env[ENV.CDP_API_KEY_ID]!,
    apiKeySecret: env[ENV.CDP_API_KEY_SECRET]!,
    walletSecret: env[ENV.CDP_WALLET_SECRET]!,
    accountName: nonEmpty(env[ENV.CDP_ACCOUNT_NAME]) ? env[ENV.CDP_ACCOUNT_NAME]!.trim() : undefined,
  });
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/** Resolve the data dir: PAYFETCH_DATA_DIR, else `~/.payfetch` (SPEC §12). */
export function resolveDataDir(env: EnvRecord, homedir: () => string = osHomedir): string {
  const d = env[ENV.DATA_DIR];
  return nonEmpty(d) ? d.trim() : join(homedir(), DEFAULT_DATA_DIR_NAME);
}

/**
 * Assemble the `createPayfetch` options from the environment (SPEC §12). Pure
 * with respect to `env`; effectful only through the injected `io`. The returned
 * `deps.elicit` is `null` — the MCP server (SPEC §6/§9) wires the elicitation
 * bridge into this mutable DI record after it knows the connected client's
 * capabilities.
 *
 * @throws ConfigError on a missing/ambiguous/incomplete signer or an unsafe key file.
 */
export function buildFromEnv(env: EnvRecord, io: ConfigIo = realConfigIo()): CreatePayfetchOpts {
  const source = selectSignerSource(env);
  const signer = buildSigner(source, env, io);
  const dataDir = resolveDataDir(env, io.homedir);

  const viaRaw = env[ENV.VIA];
  const via = nonEmpty(viaRaw) ? viaRaw.trim() : null;

  const deps: PayfetchDeps = {
    fetch: io.fetch,
    signer,
    now: io.now,
    random: io.random,
    dataDir,
    log: io.log,
    elicit: null, // server wires the elicitation bridge (SPEC §6)
  };

  return {
    deps,
    // `!= null` matches createPayfetch's own PAYFETCH_TEST_MODE fallback: presence
    // (any value) enables test mode (SPEC §12).
    testMode: env[ENV.TEST_MODE] != null,
    approver: env[ENV.APPROVER] === APPROVER_ENABLED_VALUE,
    via,
  };
}
