/**
 * P3′ payfetch — shared hermetic test harness (SPEC §14). NO network, ever.
 *
 * Purpose: the composable, builder-style fakes that stages 2/3 reuse. All wire
 * fixtures are real-SHAPE x402 bodies; the settlement builder uses the SAME base64
 * JSON encoding the pinned `@x402/core@2.17.0` package emits (via `safeBase64Encode`,
 * @x402/core/utils) so decode round-trips against `decodePaymentResponseHeader`.
 *
 * WIRE-PARITY WAVE (§3.1a): v2 fixtures added alongside the v1 ones —
 * `acceptsEntryV2`/`challenge402V2` (CAIP-2 network, `amount` field, x402Version:2)
 * and `challengeHeaderResponse` (challenge delivered in the PAYMENT-REQUIRED header,
 * the v2-canonical channel). `settlementResponse` defaults to the PAYMENT-RESPONSE
 * channel (v2-canonical), with an opt-in legacy `x-payment-response`.
 *
 * Components:
 *  - `FakeFetch`          — routes (method,url) → scripted responses; supports a
 *                            SEQUENCE per route (retry/second-402 flows: the last
 *                            entry repeats); records every call.
 *  - `acceptsEntry` /
 *    `challenge402`       — v1 wire-format 402 fixture builders (defaults + overrides,
 *                            incl. multi-accepts and malformed variants).
 *  - `acceptsEntryV2` /
 *    `challenge402V2`     — v2 (§3.1a) fixture builders; live-scaffold `hello` facts.
 *  - `scriptedResponse` /
 *    `settlementResponse` — response builders (the latter sets the settlement header).
 *  - `FakeSigner`         — counts signTypedData calls; deterministic signature;
 *                            captures the last typed data.
 *  - `fakeClock`          — settable/advanceable `now()`.
 *  - `seededRandom` /
 *    `fixedRandom`        — deterministic 32-byte sources that RECORD what they
 *                            emit (so tests can assert nonce == emitted bytes).
 *  - `fakeDeps`           — PayfetchDeps filled with the above.
 */

import { safeBase64Encode } from "@x402/core/utils";

import {
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  X_PAYMENT_RESPONSE_HEADER,
} from "../src/core/constants.js";
import type { PayfetchFs } from "../src/core/fs.js";
import type { Receipt } from "../src/core/ledger.js";
import type {
  GuardInput,
  GuardResult,
  PrePayGuard,
} from "../src/guards/types.js";
import { X402Payer } from "../src/payer/x402.js";
import type {
  Eip712TypedData,
  ElicitFn,
  ParsedChallenge,
  PayfetchDeps,
  PaymentPayer,
  PaymentProof,
  PaymentQuote,
  WalletSigner,
} from "../src/payer/types.js";

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

export type FakeClock = {
  now: () => number;
  set: (ms: number) => void;
  advance: (ms: number) => void;
};

/** Settable epoch-ms clock. SPEC §14 fake clock. */
export function fakeClock(startMs = 0): FakeClock {
  let t = startMs;
  return {
    now: () => t,
    set: (ms) => {
      t = ms;
    },
    advance: (ms) => {
      t += ms;
    },
  };
}

// ---------------------------------------------------------------------------
// Deterministic 32-byte random sources (recorded for assertions)
// ---------------------------------------------------------------------------

export type RandomSource = { random: () => Uint8Array; emitted: Uint8Array[] };

/** Deterministic 32-byte sequence (LCG). Records every emitted chunk. */
export function seededRandom(seed = 1): RandomSource {
  const emitted: Uint8Array[] = [];
  let counter = 0;
  const random = (): Uint8Array => {
    const out = new Uint8Array(32);
    let state = (seed * 2654435761 + counter * 40503 + 1) >>> 0;
    for (let i = 0; i < 32; i++) {
      state = (state * 1664525 + 1013904223) >>> 0;
      out[i] = state & 0xff;
    }
    counter += 1;
    emitted.push(out);
    return out;
  };
  return { random, emitted };
}

/** Always returns a copy of the same 32 bytes. Records each emission. */
export function fixedRandom(bytes: Uint8Array): RandomSource {
  if (bytes.length !== 32) throw new Error("fixedRandom requires exactly 32 bytes");
  const emitted: Uint8Array[] = [];
  const random = (): Uint8Array => {
    const out = Uint8Array.from(bytes);
    emitted.push(out);
    return out;
  };
  return { random, emitted };
}

// ---------------------------------------------------------------------------
// FakeSigner
// ---------------------------------------------------------------------------

/** Deterministic 65-byte signature (never a real signature; value is irrelevant). */
const DETERMINISTIC_SIG = ("0x" + "ab".repeat(65)) as `0x${string}`;

export class FakeSigner implements WalletSigner {
  readonly kind: "local_key" | "cdp_server_wallet";
  readonly #address: string;
  /** Count of signTypedData invocations (SPEC §14 count-assertions). */
  signCount = 0;
  /** Typed data from the most recent signTypedData call. */
  lastTypedData: Eip712TypedData | null = null;

  constructor(opts: { address?: string; kind?: "local_key" | "cdp_server_wallet" } = {}) {
    this.#address = (
      opts.address ?? "0x00000000000000000000000000000000000000A1"
    ).toLowerCase();
    this.kind = opts.kind ?? "local_key";
  }

  async address(): Promise<string> {
    return this.#address;
  }

  async signTypedData(td: Eip712TypedData): Promise<`0x${string}`> {
    this.signCount += 1;
    this.lastTypedData = td;
    return DETERMINISTIC_SIG;
  }
}

// ---------------------------------------------------------------------------
// Wire-format 402 fixture builders
// ---------------------------------------------------------------------------

/**
 * A single x402 `accepts` entry with sensible defaults (Base mainnet USDC,
 * $0.01). Any key set to `undefined` in `over` is OMITTED (for malformed
 * variants, e.g. `acceptsEntry({ payTo: undefined })`); other keys replace.
 */
export function acceptsEntry(over: Record<string, unknown> = {}): Record<string, unknown> {
  const base: Record<string, unknown> = {
    scheme: "exact",
    network: "base",
    maxAmountRequired: "10000", // 0.01 USDC (6 decimals)
    resource: "https://api.example.com/data",
    description: "Example paid resource",
    mimeType: "application/json",
    payTo: "0x000000000000000000000000000000000000bEEF",
    maxTimeoutSeconds: 60,
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
    extra: { name: "USD Coin", version: "2" },
  };
  const out = { ...base, ...over };
  for (const k of Object.keys(out)) {
    if (out[k] === undefined) delete out[k];
  }
  return out;
}

/** A full x402 402 challenge body (JSON object). */
export function challenge402(
  opts: { x402Version?: number; accepts?: Record<string, unknown>[]; error?: string } = {},
): Record<string, unknown> {
  return {
    x402Version: opts.x402Version ?? 1,
    error: opts.error ?? "X-PAYMENT header is required",
    accepts: opts.accepts ?? [acceptsEntry()],
  };
}

/**
 * A single x402 **v2** `accepts` entry (§3.1a, WIRE-PARITY WAVE). Defaults match
 * the LIVE scaffold `hello` facts (RESULTS.md): CAIP-2 `eip155:84532`, Base
 * Sepolia USDC, `amount` field, `extra` = the scaffold's `{name:"USDC",version:"2"}`.
 * Same `undefined`-omit override semantics as `acceptsEntry`. NOTE: v2 entries
 * carry NO `resource`/`mimeType`/`outputSchema` — those move to the challenge-level
 * `resource` object (see `challenge402V2`).
 */
export function acceptsEntryV2(over: Record<string, unknown> = {}): Record<string, unknown> {
  const base: Record<string, unknown> = {
    scheme: "exact",
    network: "eip155:84532", // CAIP-2 Base Sepolia
    amount: "1000", // v2 amount field ($0.001, 6 decimals)
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Base Sepolia USDC
    payTo: "0xffa3e5fa7AE5F0DD1fd196Cbd41d40325E4Aa831",
    maxTimeoutSeconds: 60,
    extra: { name: "USDC", version: "2" },
  };
  const out = { ...base, ...over };
  for (const k of Object.keys(out)) {
    if (out[k] === undefined) delete out[k];
  }
  return out;
}

/**
 * A full x402 **v2** 402 challenge body (`x402Version:2`, challenge-level
 * `resource` object, CAIP-2 accepts). The v2-canonical delivery is the
 * PAYMENT-REQUIRED header — use `challengeHeaderResponse` to emit it on the wire.
 */
export function challenge402V2(
  opts: {
    accepts?: Record<string, unknown>[];
    error?: string;
    resource?: Record<string, unknown> | null;
  } = {},
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    x402Version: 2,
    error: opts.error ?? "payment required",
    accepts: opts.accepts ?? [acceptsEntryV2()],
  };
  // Challenge-level resource object (v2); pass `resource: null` to omit.
  if (opts.resource !== null) {
    body.resource = opts.resource ?? { url: "https://api.example.com/v1/hello" };
  }
  return body;
}

// ---------------------------------------------------------------------------
// FakeFetch
// ---------------------------------------------------------------------------

export type Settlement = {
  success: boolean;
  transaction?: string;
  network?: string;
  payer?: string;
};

export type ScriptedResponse = {
  status?: number; // default 200
  headers?: Record<string, string>;
  jsonBody?: unknown; // serialized to JSON (sets content-type: application/json)
  textBody?: string; // raw text (e.g. non-JSON body)
  settlement?: Settlement; // sets the settlement header via safeBase64Encode
  /**
   * Which settlement header to emit (§3.1a rule 5). Default "payment-response"
   * (v2-canonical, what the deployed scaffold emits); "x-payment-response" is the
   * legacy channel (the pipeline reads PAYMENT-RESPONSE first, else this).
   */
  settlementChannel?: "payment-response" | "x-payment-response";
};

/** Convenience: a scripted response (thin passthrough for readability). */
export function scriptedResponse(over: ScriptedResponse = {}): ScriptedResponse {
  return over;
}

/**
 * A 200 carrying a settlement header + optional JSON body. Emits PAYMENT-RESPONSE
 * by default (v2-canonical); pass `settlementChannel: "x-payment-response"` for the
 * legacy channel (§3.1a rule 5).
 */
export function settlementResponse(
  settlement: Settlement,
  over: ScriptedResponse = {},
): ScriptedResponse {
  return { status: 200, settlement, ...over };
}

/** A 402 challenge response from a challenge body (body channel, v1 style). */
export function challengeResponse(
  body: unknown,
  over: ScriptedResponse = {},
): ScriptedResponse {
  return { status: 402, jsonBody: body, ...over };
}

/**
 * A 402 whose challenge lives in the base64 **PAYMENT-REQUIRED header** (the
 * v2-canonical challenge channel, §3.1a rule 1). The body defaults to empty; pass
 * `over.jsonBody`/`over.textBody` to simulate a seller that ALSO ships a v1-style
 * body (the header must win). Extra headers in `over.headers` are merged.
 */
export function challengeHeaderResponse(
  challenge: unknown,
  over: ScriptedResponse = {},
): ScriptedResponse {
  return {
    status: 402,
    ...over,
    headers: {
      [PAYMENT_REQUIRED_HEADER]: safeBase64Encode(JSON.stringify(challenge)),
      ...(over.headers ?? {}),
    },
  };
}

export type RecordedCall = {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
};

function routeKey(method: string, url: string): string {
  return `${method.toUpperCase()} ${url}`;
}

function toResponse(sr: ScriptedResponse): Response {
  const headers = new Headers(sr.headers ?? {});
  if (sr.settlement) {
    const name =
      sr.settlementChannel === "x-payment-response"
        ? X_PAYMENT_RESPONSE_HEADER
        : PAYMENT_RESPONSE_HEADER; // v2-canonical default
    headers.set(name, safeBase64Encode(JSON.stringify(sr.settlement)));
  }
  let body: string | null = null;
  if (sr.textBody !== undefined) {
    body = sr.textBody;
  } else if (sr.jsonBody !== undefined) {
    body = JSON.stringify(sr.jsonBody);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }
  return new Response(body, { status: sr.status ?? 200, headers });
}

/**
 * Routes (method,url) → a scripted response SEQUENCE. Each fetch advances the
 * route's cursor; once exhausted, the LAST entry repeats (steady state). An
 * unrouted request throws (a test never means to hit the network).
 */
export class FakeFetch {
  readonly #routes = new Map<string, ScriptedResponse[]>();
  readonly #cursor = new Map<string, number>();
  /** Every call, in order (SPEC §14 count/inspection). */
  readonly calls: RecordedCall[] = [];

  /** Register a response sequence for (method,url). Chainable. */
  on(method: string, url: string, ...responses: ScriptedResponse[]): this {
    if (responses.length === 0) throw new Error("FakeFetch.on requires ≥1 response");
    this.#routes.set(routeKey(method, url), responses);
    this.#cursor.set(routeKey(method, url), 0);
    return this;
  }

  /** The injectable `fetch` for PayfetchDeps.fetch. */
  readonly fetch: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const method = (init?.method ?? "GET").toUpperCase();

    const hdrs: Record<string, string> = {};
    new Headers(init?.headers ?? {}).forEach((v, k) => {
      hdrs[k] = v;
    });
    const body = typeof init?.body === "string" ? init.body : null;
    this.calls.push({ url, method, headers: hdrs, body });

    const key = routeKey(method, url);
    const seq = this.#routes.get(key);
    if (!seq) throw new Error(`FakeFetch: no route for ${key}`);
    const i = this.#cursor.get(key) ?? 0;
    const chosen = seq[Math.min(i, seq.length - 1)];
    this.#cursor.set(key, i + 1);
    return toResponse(chosen);
  };
}

// ---------------------------------------------------------------------------
// PayfetchDeps builder
// ---------------------------------------------------------------------------

export type LogEntry = { msg: string; fields?: Record<string, unknown> };

export type FakeDepsOverrides = {
  fetch?: typeof fetch;
  signer?: WalletSigner;
  now?: () => number;
  random?: () => Uint8Array;
  dataDir?: string;
  log?: PayfetchDeps["log"];
  elicit?: ElicitFn | null;
  /** If provided, log entries are appended here (leak-scan target, SPEC §14). */
  logSink?: LogEntry[];
};

/** Assemble a PayfetchDeps from fakes; unspecified fields get inert defaults. */
export function fakeDeps(over: FakeDepsOverrides = {}): PayfetchDeps {
  const logSink = over.logSink;
  const log: PayfetchDeps["log"] =
    over.log ??
    ((msg, fields) => {
      if (logSink) logSink.push({ msg, fields });
    });
  return {
    fetch:
      over.fetch ??
      (async () => {
        throw new Error("fakeDeps.fetch not configured");
      }),
    signer: over.signer ?? new FakeSigner(),
    now: over.now ?? (() => 0),
    random: over.random ?? seededRandom().random,
    dataDir: over.dataDir ?? "/tmp/payfetch-test",
    log,
    elicit: over.elicit ?? null,
  };
}

// ===========================================================================
// WAVE B1 additions (SPEC §14) — in-memory fs, resolver, fake HTTP client,
// fake guard/payer, receipt builder. All additive; stage-1 fakes untouched.
// ===========================================================================

// ---------------------------------------------------------------------------
// In-memory PayfetchFs (SPEC §8 testability directive). Enforces nothing about
// append-only — that is the Ledger's contract (tested via the real Ledger over
// this fs). mtime is a monotonic write sequence so config-change detection is
// deterministic regardless of the fake clock.
// ---------------------------------------------------------------------------

export type InMemoryFs = PayfetchFs & {
  /** Raw file map (path → contents) for assertions / leak scans. */
  files: Map<string, string | Uint8Array>;
};

export function inMemoryFs(): InMemoryFs {
  const files = new Map<string, string | Uint8Array>();
  const mtimes = new Map<string, number>();
  let seq = 1;
  const touch = (p: string): void => {
    mtimes.set(p, seq++);
  };
  const asText = (v: string | Uint8Array | undefined): string | null => {
    if (v === undefined) return null;
    return typeof v === "string" ? v : new TextDecoder().decode(v);
  };
  return {
    files,
    ensureDir(): void {
      /* flat map — dirs are implicit */
    },
    readText(p: string): string | null {
      return asText(files.get(p));
    },
    writeText(p: string, d: string): void {
      files.set(p, d);
      touch(p);
    },
    writeBytes(p: string, d: Uint8Array): void {
      files.set(p, Uint8Array.from(d));
      touch(p);
    },
    appendLine(p: string, line: string, _opts: { fsync: boolean }): void {
      const prev = asText(files.get(p)) ?? "";
      files.set(p, prev + (line.endsWith("\n") ? line : `${line}\n`));
      touch(p);
    },
    statMtimeMs(p: string): number | null {
      return mtimes.get(p) ?? null;
    },
    listDir(dir: string): string[] {
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      const names = new Set<string>();
      for (const k of files.keys()) {
        if (k.startsWith(prefix)) names.add(k.slice(prefix.length).split("/")[0]);
      }
      return [...names];
    },
    tryCreateExclusive(p: string, contents: string): boolean {
      if (files.has(p)) return false;
      files.set(p, contents);
      touch(p);
      return true;
    },
    remove(p: string): void {
      files.delete(p);
      mtimes.delete(p);
    },
  };
}

// ---------------------------------------------------------------------------
// Host resolver (transport DNS seam). Maps host → IPs; unknown hosts resolve to
// a benign public IP by default so most tests need no explicit map.
// ---------------------------------------------------------------------------

export function hostResolver(
  map: Record<string, string[]> = {},
  fallback: string[] = ["93.184.216.34"], // example.com (public)
): (host: string) => Promise<string[]> {
  return async (host: string) => map[host] ?? fallback;
}

/** An immediate no-op delay (neutralizes elicit/guard timeouts → fire instantly). */
export const immediateDelay = async (): Promise<void> => {};

/** A delay that NEVER resolves (an elicit that hangs; races against a timeout). */
export const neverResolves = <T>(): Promise<T> => new Promise<T>(() => {});

// ---------------------------------------------------------------------------
// Fake pre-pay guard (SPEC §7) — returns a scripted verdict, counts calls.
// ---------------------------------------------------------------------------

export function fakeGuard(
  id: "trust" | "safety",
  result: Partial<GuardResult> & { verdict: GuardResult["verdict"] },
  opts: { appliesFn?: (i: GuardInput) => boolean; throws?: boolean; hang?: boolean } = {},
): PrePayGuard & { calls: number } {
  const guard: PrePayGuard & { calls: number } = {
    id,
    calls: 0,
    applies: opts.appliesFn ?? (() => true),
    async check(input: GuardInput): Promise<GuardResult> {
      guard.calls += 1;
      if (opts.hang) return neverResolves<GuardResult>();
      if (opts.throws) throw new Error("guard boom");
      return {
        id,
        verdict: result.verdict,
        detail: result.detail ?? {},
        latencyMs: result.latencyMs ?? 1,
        costUsd: result.costUsd ?? 0,
      };
    },
  };
  return guard;
}

// ---------------------------------------------------------------------------
// Instrumented payer (SPEC §5.3 count-assertion) — wraps X402Payer, counts
// buildPayment so tests can assert ≤1 signature per logical request.
// ---------------------------------------------------------------------------

export class CountingPayer implements PaymentPayer {
  readonly rail = "x402" as const;
  readonly #inner = new X402Payer();
  buildCount = 0;
  detects(c: ParsedChallenge): boolean {
    return this.#inner.detects(c);
  }
  quotes(c: ParsedChallenge): PaymentQuote[] {
    return this.#inner.quotes(c);
  }
  buildPayment(q: PaymentQuote, s: WalletSigner, d: PayfetchDeps): Promise<PaymentProof> {
    this.buildCount += 1;
    return this.#inner.buildPayment(q, s, d);
  }
}

// ---------------------------------------------------------------------------
// Receipt builder (SPEC §8.3) — a minimal, valid Receipt for ledger/state tests.
// ---------------------------------------------------------------------------

export function makeReceipt(over: Partial<Receipt> = {}): Receipt {
  return {
    schema: "p3f.receipt.v1",
    receiptId: over.receiptId ?? "00000000-0000-4000-8000-000000000000",
    ts: over.ts ?? 1_700_000_000_000,
    clientVersion: "p3f-1.0.0",
    policyVersion: "p3f-policy-1.5.0",
    test: over.test ?? false,
    url: over.url ?? "https://api.example.com/data",
    method: over.method ?? "GET",
    host: over.host ?? "api.example.com",
    outcome: over.outcome ?? "free",
    denyCode: over.denyCode ?? null,
    guardBlockReason: over.guardBlockReason ?? null,
    verdictPath: over.verdictPath ?? [],
    quote: over.quote ?? null,
    rejectedQuotes: over.rejectedQuotes ?? null,
    guards: over.guards ?? [],
    approval: over.approval ?? null,
    payment: over.payment ?? null,
    budgets: over.budgets ?? {
      dayRemainingUsd: 2,
      hostRemainingUsd: 1,
      totalRemainingUsd: null,
    },
    http: over.http ?? null,
    notes: over.notes ?? [],
  };
}

/** A minimal PaymentQuote (Base mainnet USDC, $amountUsd) for hold/settle tests. */
export function makeQuote(amountUsd: number, over: Partial<PaymentQuote> = {}): PaymentQuote {
  const atomic = String(Math.round(amountUsd * 1_000_000));
  const network = over.network ?? "base";
  return {
    rail: "x402",
    scheme: "exact",
    network,
    asset: over.asset ?? "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    amountAtomic: over.amountAtomic ?? atomic,
    amountUsd,
    payTo: over.payTo ?? "0x000000000000000000000000000000000000beef",
    maxTimeoutSeconds: over.maxTimeoutSeconds ?? 60,
    resource: over.resource ?? "https://api.example.com/data",
    mimeType: over.mimeType ?? "application/json",
    outputSchemaSha256: over.outputSchemaSha256 ?? null,
    rawAccepts: over.rawAccepts ?? {},
    x402Version: over.x402Version ?? 1,
    networkAsDeclared: over.networkAsDeclared ?? network,
  };
}
