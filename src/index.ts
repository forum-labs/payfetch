/**
 * P3′ payfetch — library entry (SPEC §10). The substrate MCP tools wrap.
 *
 * Purpose: `createPayfetch(opts)` composes the money engine — policy loader,
 * ledger, budget, transport (with the DNS-pinned undici client), guards, and the
 * pipeline — into the `Payfetch` surface `{fetch, quote, status, receipts}`.
 * Denials are RESULTS, never exceptions; the factory throws only on programmer
 * error (missing signer / invalid arguments). `clearAutoDeny` is the operator's
 * out-of-band breaker reset (SPEC §5.4) — deliberately NOT reachable from a tool.
 *
 * Invariants:
 *  - `PAYFETCH_TEST_MODE` (§12): receipts carry `test: true` and base-mainnet
 *    quotes are refused (the pipeline denies with note `test_mode`).
 *  - Env/globals are read ONLY here (the composition root); `src/core/*` stays
 *    pure DI (P1 §1 discipline). Tests inject every seam and touch no env.
 *  - The transport dials through a pinned `undici.Agent` whose `connect.lookup`
 *    vets the resolved address before the socket connects (SPEC §11).
 */

import { lookup as dnsLookup } from "node:dns/promises";
import { Readable } from "node:stream";

import { Agent, request as undiciRequest } from "undici";

import {
  P1_SAFETY_BASE_URL,
  P2_TRUST_BASE_URL,
} from "./core/constants.js";
import { Budget } from "./core/budget.js";
import { realFs, type PayfetchFs } from "./core/fs.js";
import { Ledger } from "./core/ledger.js";
import type { Receipt } from "./core/ledger.js";
import {
  configPath,
  defaultPolicy,
  loadPolicy,
  mergePolicy,
  type Policy,
} from "./core/policy.js";
import {
  PayfetchEngine,
  type Decision,
  type FetchOpts,
  type GuardRuntime,
  type SpendStatus,
} from "./core/pipeline.js";
import {
  adaptFetch,
  createPinnedLookup,
  parseIpv4,
  type HttpClient,
  type HttpResponse,
} from "./core/transport.js";
import { X402Payer } from "./payer/x402.js";
import type { PayfetchDeps, PaymentPayer } from "./payer/types.js";
import type { GuardId, PrePayGuard } from "./guards/types.js";
// -- PARALLEL-AGENT DEPENDENCY (SPEC §7.5): the guard factories. If absent at
//    build time, see the fallback note in `buildDefaultGuards`.
import { createSafetyGuard, createTrustGuard } from "./guards/index.js";

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends readonly (infer U)[]
    ? U[]
    : T[K] extends object
      ? DeepPartial<T[K]>
      : T[K];
};

// ---------------------------------------------------------------------------
// Public surface (SPEC §10)
// ---------------------------------------------------------------------------

export interface Payfetch {
  fetch(
    url: string,
    init?: RequestInit,
    opts?: FetchOpts,
  ): Promise<{ response: Response | null; receipt: Receipt }>;
  quote(url: string, init?: RequestInit): Promise<{ decision: Decision; receipt: Receipt }>;
  status(): Promise<SpendStatus>;
  receipts(q: {
    sinceTs?: number;
    host?: string;
    outcome?: Receipt["outcome"];
    limit?: number;
  }): Promise<Receipt[]>;
  /** Release the single-writer ledger lock (additive to §10; for clean shutdown). */
  close(): void;
  /** The underlying engine (additive; MCP T5 approve/list substrate). */
  engine: PayfetchEngine;
}

export type CreatePayfetchOpts = {
  deps: PayfetchDeps;
  policy?: DeepPartial<Policy>;
  guards?: PrePayGuard[];
  payers?: PaymentPayer[];
  // --- internal / test seams (additive to §10; undocumented in the tool surface) ---
  fs?: PayfetchFs;
  httpClient?: HttpClient;
  resolve?: (host: string) => Promise<string[]>;
  testMode?: boolean;
  approver?: boolean;
  via?: string | null;
  delay?: (ms: number) => Promise<void>;
  setTimer?: (fn: () => void, ms: number) => { clear: () => void };
  guardBaseUrls?: { trust: string | null; safety: string | null };
};

function hex32(deps: PayfetchDeps): string {
  const b = deps.random();
  let s = "";
  for (let i = 0; i < 16; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

export function createPayfetch(opts: CreatePayfetchOpts): Payfetch {
  // --- programmer-error validation (SPEC §10) ---
  if (!opts || !opts.deps) throw new TypeError("createPayfetch: opts.deps is required");
  const deps = opts.deps;
  if (!deps.signer) throw new TypeError("createPayfetch: deps.signer is required");
  if (typeof deps.dataDir !== "string" || deps.dataDir.length === 0) {
    throw new TypeError("createPayfetch: deps.dataDir is required");
  }

  const fs = opts.fs ?? realFs;
  const dataDir = deps.dataDir;
  const testMode = opts.testMode ?? process.env.PAYFETCH_TEST_MODE != null;
  const approver = opts.approver ?? process.env.PAYFETCH_APPROVER === "1";
  const via = opts.via ?? null;
  const guardBaseUrls = opts.guardBaseUrls ?? { trust: P2_TRUST_BASE_URL, safety: P1_SAFETY_BASE_URL };

  // --- ledger + single-writer lock + state (rebuild if missing/corrupt) ---
  const ledger = new Ledger(fs, dataDir, deps.now);
  ledger.acquireLock();
  let state = ledger.loadStateRaw();
  if (!state) {
    state = ledger.rebuildState(hex32(deps));
    ledger.saveState(state);
  }
  const budget = new Budget(state, ledger, deps.now);

  // --- policy provider: mtime-reloaded, immutable per evaluation (SPEC §4.1) ---
  const basePolicy = mergePolicy(defaultPolicy(), opts.policy);
  let cached: { ok: true; policy: Policy } | { ok: false; error: string } = {
    ok: true,
    policy: basePolicy,
  };
  let lastMtime: number | null = null;
  const reload = (): void => {
    const load = loadPolicy(dataDir, { fs, log: deps.log }, basePolicy);
    if (load.ok) {
      cached = { ok: true, policy: load.policy };
      lastMtime = load.mtimeMs;
    } else {
      cached = { ok: false, error: load.error };
    }
  };
  reload();
  const policyProvider = (): { ok: true; policy: Policy } | { ok: false; error: string } => {
    const cur = fs.statMtimeMs(configPath(dataDir));
    if (cur !== lastMtime) reload();
    return cached;
  };

  // --- transport HTTP client: pinned undici in prod, injected in tests ---
  const resolve = opts.resolve ?? defaultResolve;
  const initialPolicy = cached.ok ? cached.policy : basePolicy;
  const httpClient =
    opts.httpClient ??
    createPinnedHttpClient(resolve, { allowPrivateTargets: initialPolicy.allowPrivateTargets });

  // --- engine ---
  const engine = new PayfetchEngine({
    deps,
    fs,
    ledger,
    budget,
    payers: opts.payers ?? [new X402Payer()],
    policyProvider,
    transportIo: { request: httpClient, resolve, setTimer: opts.setTimer },
    testMode,
    approverEnabled: approver,
    delay: opts.delay,
    guardBaseUrls,
    via,
  });

  // --- guards (default: trust+safety via factories; SPEC §7.5) ---
  engine.guards =
    opts.guards ?? buildDefaultGuards(engine, initialPolicy, state.installId, via, guardBaseUrls, deps);

  return {
    fetch: (url, init, o) => engine.fetch(url, init, o),
    quote: (url, init) => engine.quote(url, init),
    status: () => engine.status(),
    receipts: async (q) => engine.receipts(q),
    close: () => ledger.releaseLock(),
    engine,
  };
}

// ---------------------------------------------------------------------------
// Default guards (SPEC §7.5) — factories from ../guards/index.js
// ---------------------------------------------------------------------------

function buildDefaultGuards(
  engine: PayfetchEngine,
  policy: Policy,
  installId: string,
  via: string | null,
  baseUrls: { trust: string | null; safety: string | null },
  deps: PayfetchDeps,
): PrePayGuard[] {
  // L3: the guardFetch budget is a LIVE getter over `policyProvider` (via the
  // engine), NOT the build-time `dailyBudgetUsd` — so lowering it tightens guard
  // spend without a restart (and raising it loosens live), matching the mode/
  // verdict hot-reload. The build-time `policy.guards.<id>` still seeds the guard's
  // captured config (which the pipeline hot-reloads via `req.config`).
  const rtFor = (id: GuardId, baseUrl: string | null): GuardRuntime => ({
    guardFetch: engine.makeGuardFetch(id, () => engine.liveGuardBudgetUsd(id), baseUrl),
    now: deps.now,
    log: deps.log,
    installId8: installId.slice(0, 8),
    via,
    baseUrls,
  });
  const trust = createTrustGuard(policy.guards.trust, rtFor("trust", baseUrls.trust));
  const safety = createSafetyGuard(policy.guards.safety, rtFor("safety", baseUrls.safety));
  return [trust, safety];
}

// ---------------------------------------------------------------------------
// Operator-only auto-deny clear (SPEC §5.4) — NOT an MCP tool
// ---------------------------------------------------------------------------

/**
 * Clear a host's auto-deny state (SPEC §5.4 operator clear). This is the exported
 * CLI/admin path (`payfetch clear-autodeny`); no MCP tool reaches it — the agent
 * must not un-deny hosts (same invariant as caps, both directions of authority).
 */
export function clearAutoDeny(
  dataDir: string,
  host: string,
  io: { fs?: PayfetchFs; now?: () => number } = {},
): boolean {
  const fs = io.fs ?? realFs;
  const now = io.now ?? (() => Date.now());
  const ledger = new Ledger(fs, dataDir, now);
  const state = ledger.loadStateRaw() ?? ledger.rebuildState("0".repeat(32));
  const budget = new Budget(state, ledger, now);
  return budget.clearAutoDeny(host);
}

// ---------------------------------------------------------------------------
// Production wiring: DNS-pinned undici client + resolver
// ---------------------------------------------------------------------------

async function defaultResolve(host: string): Promise<string[]> {
  try {
    const res = await dnsLookup(host, { all: true });
    return res.map((r) => r.address);
  } catch {
    return [];
  }
}

/**
 * The production HTTP client (SPEC §11): an undici Agent whose `connect.lookup`
 * pins DNS (the vetted IP is the IP dialed), no auto-follow (transport owns
 * redirects), readable Location. Falls back to a stock-fetch adapter only for
 * environments without undici's low-level `request` (never the default).
 */
function createPinnedHttpClient(
  resolve: (host: string) => Promise<string[]>,
  policy: { allowPrivateTargets: boolean },
): HttpClient {
  const agent = new Agent({
    connect: { lookup: createPinnedLookup(resolve, policy) as never },
  });
  const client: HttpClient = async (url, init): Promise<HttpResponse> => {
    // A plain Agent does not auto-follow redirects (no RedirectHandler), so the
    // transport loop stays in control of every hop (SPEC §11).
    const res = await undiciRequest(url, {
      method: init.method as never,
      headers: init.headers,
      body: init.body ?? undefined,
      dispatcher: agent,
      signal: init.signal,
    });
    const headers = new Headers();
    for (const [k, v] of Object.entries(res.headers)) {
      if (Array.isArray(v)) headers.set(k, v.join(", "));
      else if (v != null) headers.set(k, String(v));
    }
    const body = res.body
      ? (Readable.toWeb(res.body) as unknown as ReadableStream<Uint8Array>)
      : null;
    return { status: res.statusCode, headers, body };
  };
  return client;
}

// Re-exports for consumers/tests.
export { adaptFetch, parseIpv4 };
export type { Decision, SpendStatus, FetchOpts };
export type { Policy } from "./core/policy.js";
export type { Receipt } from "./core/ledger.js";

// --- Public adapter surface (1.0.1, ADDITIVE) -----------------------------
// Out-of-tree framework adapters (@forum-labs/payfetch-agentkit / -vercel) build
// a payfetch instance from the operator's env EXACTLY as the CLI/MCP server do
// (`buildFromEnv` + `realConfigIo`) and mirror the fixed policy-lock / payment-
// rejected copy. The package `exports` map exposes only `"."`, so a published
// consumer cannot reach these via a deep `src/` import — they must be on the main
// entry. Re-exported here additively; no existing export is removed or renamed.
// (`config.ts`→`index.ts` and `mcp/tools.ts`→`index.ts` back-imports are type-only,
// so this introduces no runtime import cycle.)
export { buildFromEnv, realConfigIo } from "./config.js";
export type { ConfigIo, EnvRecord } from "./config.js";
export { policyLockNotice, paymentRejectedHint } from "./mcp/tools.js";
