/**
 * P3′ payfetch — guard-specific hermetic fixtures (SPEC §14 guard scope). NO
 * network, ever. Companion to test/fakes.ts (which stages 2/3 own); this file
 * is guards-only per the build boundary.
 *
 * Components:
 *  - `trustConfig` / `safetyConfig`  — config builders over the frozen §4.1
 *                                       defaults (fresh, mutable arrays so a test
 *                                       override never mutates a shared default).
 *  - `trustScore` + named variants   — P2 `TrustScore` bodies (PROBER_SPEC §8.5):
 *                                       reliable / mixed / unreliable / unrated.
 *  - `safetyScreen` + named variants — P1 screen bodies (THESIS §2): basic
 *                                       (deployer null) + deep (deployer block).
 *  - `ScriptedGuardFetch`            — a sequence-programmable `guardFetch` fake
 *                                       (last step repeats) that RECORDS every
 *                                       request (url/method/headers/body) and can
 *                                       emit 402/5xx, malformed JSON, timeout
 *                                       (abort), network-throw, sync-crash, or a
 *                                       genuine hang that respects the AbortSignal.
 *  - `FakeP1`                        — a CONTRACT-ENFORCING fake P1 server (SPEC
 *                                       §7.3 fake-contract rule): GET-only (a POST
 *                                       — the OLD contract — is a 405 tripwire);
 *                                       reads `mint`/`chain` from the URL QUERY and
 *                                       rejects (400, zod-style) a missing/empty
 *                                       `mint` (incl. a legacy token-in-body call);
 *                                       serves BOTH routes with their distinct
 *                                       shapes (basic never returns a deployer
 *                                       block and ignores depth hints; /deep returns
 *                                       the deployer block). A guard contract drift
 *                                       fails the suite here, not a live call.
 *  - `guardRuntime`                  — a `GuardRuntime` builder.
 */

import {
  DEFAULT_SAFETY_GUARD_CONFIG,
  DEFAULT_TRUST_GUARD_CONFIG,
  type GuardRuntime,
  type SafetyGuardConfig,
  type TrustGuardConfig,
} from "../src/guards/types.js";

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

/** Trust-guard config over the §4.1 defaults (arrays copied for isolation). */
export function trustConfig(over: Partial<TrustGuardConfig> = {}): TrustGuardConfig {
  return {
    ...DEFAULT_TRUST_GUARD_CONFIG,
    blockVerdicts: [...DEFAULT_TRUST_GUARD_CONFIG.blockVerdicts],
    ...over,
  };
}

/** Safety-guard config over the §4.1 defaults (arrays copied for isolation). */
export function safetyConfig(over: Partial<SafetyGuardConfig> = {}): SafetyGuardConfig {
  return {
    ...DEFAULT_SAFETY_GUARD_CONFIG,
    blockVerdicts: [...DEFAULT_SAFETY_GUARD_CONFIG.blockVerdicts],
    blockDeployerVerdicts: [...DEFAULT_SAFETY_GUARD_CONFIG.blockDeployerVerdicts],
    ...over,
  };
}

// ---------------------------------------------------------------------------
// P2 TrustScore fixtures (PROBER_SPEC §8.5)
// ---------------------------------------------------------------------------

/**
 * The scaffold response ENVELOPE (SPEC §7.2, SCAFFOLD_SPEC §3 step 5,
 * live-verified 2026-07-03): the scaffold wraps EVERY product response as
 * `{ data: <product payload>, freshnessTs, disclaimer }`. Both guards must
 * unwrap `.data`; the hermetic fakes MUST emit this shape (a flat fake hid the
 * defect at build time — the §7.2/§7.3 fake-contract rule). All wire fixtures
 * below go through this wrapper.
 */
export function scaffoldEnvelope(
  payload: unknown,
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    data: payload,
    freshnessTs: 1_700_000_000_000,
    disclaimer: "informational only, not financial advice",
    ...over,
  };
}

/** A full-shape P2 `TrustScore` PAYLOAD (bare, PROBER_SPEC §8.5). Any key overridable. */
export function trustPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "p2t.score.v1",
    endpointId: "ep_test",
    url: "https://api.example.com/data",
    asOfTs: 1_700_000_000_000,
    windowDays: 30,
    score: 88,
    verdict: "reliable",
    components: { availability: 0.95, latency: 0.85, stability: 0.9, challenge: 1 },
    caps: [],
    counts: {
      okAll: 40,
      endpointError: 1,
      confirmedUnreachable: 0,
      confirmedGone: 0,
      ambiguousExcluded: 0,
      rateLimited: 2,
      degradedCycleExcluded: 0,
      scoreable: 41,
    },
    latencyMs: { p50: 120, p95: 400, p99: 800 },
    terms: { currentHash: "abc123def456", driftEvents: 0, custodyChanges: 0, lastChangeTs: null },
    paidDelivery: { status: "verified", lastSampleTs: 1_699_000_000_000 },
    discovery: { firstSeenTs: 1_600_000_000_000, sources: ["bazaar"], listedNow: true },
    selfOperated: false,
    thresholdsVersion: "p2t-score-1.0.0",
    notes: [],
    ...over,
  };
}

/** The WIRE P2 TrustScore body: the payload wrapped in the scaffold envelope. */
export const trustScore = (over: Record<string, unknown> = {}): Record<string, unknown> =>
  scaffoldEnvelope(trustPayload(over));

export const trustReliable = (over: Record<string, unknown> = {}) =>
  trustScore({ verdict: "reliable", score: 88, ...over });
export const trustMixed = (over: Record<string, unknown> = {}) =>
  trustScore({ verdict: "mixed", score: 65, ...over });
export const trustUnreliable = (over: Record<string, unknown> = {}) =>
  trustScore({ verdict: "unreliable", score: 30, ...over });
/** Unrated: score null, components/latency/terms null (PROBER_SPEC §8.3/§8.4). */
export const trustUnrated = (over: Record<string, unknown> = {}) =>
  trustScore({ verdict: "unrated", score: null, components: null, latencyMs: null, terms: null, ...over });

// ---------------------------------------------------------------------------
// P1 screen fixtures (THESIS §2)
// ---------------------------------------------------------------------------

/** A full-shape P1 screen PAYLOAD (bare, THESIS §2; defaults = safe, deployer null). */
export function safetyPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    token: "So11111111111111111111111111111111111111112",
    chain: "solana",
    verdict: "safe",
    score: 90,
    signals: {
      honeypot: false,
      mintAuthActive: false,
      freezeAuthActive: false,
      lpBurnedOrLocked: true,
      top10HolderPct: 22,
      bundledFirstBlockPct: 3,
    },
    deployer: null, // basic responses carry no deployer block (THESIS §2)
    sources: ["helius", "goplus"],
    ...over,
  };
}

/** The WIRE P1 screen body: the payload wrapped in the scaffold envelope. */
export const safetyScreen = (over: Record<string, unknown> = {}): Record<string, unknown> =>
  scaffoldEnvelope(safetyPayload(over));

/** A BASIC screen (deployer null) with the given token verdict — enveloped. */
export const safetyBasic = (verdict: string, over: Record<string, unknown> = {}) =>
  safetyScreen({ verdict, deployer: null, ...over });

/**
 * A DEGRADED basic screen (dim5-MED, 200 OK): a danger-relevant upstream was
 * capped/absent, so P1 sets `degraded: true` on an otherwise-clean-looking screen.
 * The default `safetyPayload` emits only clean verdicts (`degraded` absent ⇒ false);
 * this fixture is the "honest-unknown but actually degraded" case the enforce
 * safety guard must fail closed on. Default verdict "unknown" (the common degrade).
 */
export const safetyDegraded = (verdict = "unknown", over: Record<string, unknown> = {}) =>
  safetyScreen({ verdict, deployer: null, degraded: true, ...over });

/** A deployer block carrying `deployerVerdict` (P1 THESIS §2 deep response). */
export const deployerBlock = (deployerVerdict: string): Record<string, unknown> => ({
  address: "0xdeadbeef00000000000000000000000000000000",
  priorLaunches: 12,
  priorRugs: 9,
  rugRate: 0.75,
  clusterId: "clu_1",
  clusterPriorRugs: 20,
  verdict: deployerVerdict,
});

/** A DEEP screen with a token verdict + a deployer block — enveloped. */
export const safetyDeep = (
  verdict: string,
  deployerVerdict: string,
  over: Record<string, unknown> = {},
) => safetyScreen({ verdict, deployer: deployerBlock(deployerVerdict), ...over });

// ---------------------------------------------------------------------------
// ScriptedGuardFetch — the programmable guardFetch fake
// ---------------------------------------------------------------------------

export type GuardStep =
  | { kind: "json"; status?: number; body: unknown }
  | { kind: "text"; status?: number; text: string; contentType?: string }
  | { kind: "status"; status: number }
  | { kind: "abort" } // reject as if the AbortSignal fired (timeout)
  | { kind: "network" } // reject with a network TypeError
  | { kind: "throw" } // synchronous crash before returning a promise
  | { kind: "hang" } // never settles unless the passed AbortSignal fires
  | { kind: "delay"; ms: number; status?: number; body: unknown }; // a slow-but-progressing screen: resolves JSON after `ms` (fake-timer ms) UNLESS aborted first

/** 200 (or `status`) with a JSON body. */
export const gJson = (body: unknown, status = 200): GuardStep => ({ kind: "json", status, body });
/** A bare status (e.g. `gStatus(402)`, `gStatus(500)`) with no body. */
export const gStatus = (status: number): GuardStep => ({ kind: "status", status });
/** 200 whose body is NOT valid JSON (so `res.json()` throws → malformed). */
export const gMalformed = (status = 200): GuardStep => ({
  kind: "text",
  status,
  text: "<<<not json>>>",
  contentType: "application/json",
});
/** Reject as if the guard's abort fired (timeout path). */
export const gAbort = (): GuardStep => ({ kind: "abort" });
/** Reject with a network error. */
export const gNetwork = (): GuardStep => ({ kind: "network" });
/** Throw synchronously (crash path). */
export const gThrow = (): GuardStep => ({ kind: "throw" });
/** Never settle unless the passed AbortSignal fires (real hang → abort). */
export const gHang = (): GuardStep => ({ kind: "hang" });
/**
 * A slow-but-PROGRESSING screen: resolves a JSON body after `ms` (advance fake
 * timers) — modelling a cache-cold P1/P2 screen that genuinely computes for a
 * few seconds and then answers. If the guard's abort fires first, it rejects
 * (AbortError) instead. Lets a test assert an enforce guard runs a cold screen to
 * completion inside the generous budget while a short (advisory) budget cuts it.
 */
export const gDelayJson = (ms: number, body: unknown, status = 200): GuardStep => ({
  kind: "delay",
  ms,
  status,
  body,
});

export type RecordedGuardRequest = {
  url: string;
  method: string;
  /** Header keys are lowercased (Web `Headers` semantics); values verbatim. */
  headers: Record<string, string>;
  body: string | null;
};

function abortError(): Error {
  return new DOMException("The operation was aborted.", "AbortError");
}

/**
 * A `GuardRuntime["guardFetch"]` fake driven by a step SEQUENCE (the last step
 * repeats once exhausted), recording every request. Assign `.fetch`.
 */
export class ScriptedGuardFetch {
  readonly #steps: GuardStep[];
  #cursor = 0;
  /** Every request, in order (headers lowercased, values verbatim). */
  readonly requests: RecordedGuardRequest[] = [];

  constructor(...steps: GuardStep[]) {
    if (steps.length === 0) throw new Error("ScriptedGuardFetch requires ≥1 step");
    this.#steps = steps;
  }

  /** Number of times the fake was invoked. */
  get callCount(): number {
    return this.requests.length;
  }

  readonly fetch: (url: string, init?: RequestInit) => Promise<Response> = (url, init = {}) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((v, k) => {
      headers[k] = v;
    });
    this.requests.push({
      url,
      method: (init.method ?? "GET").toUpperCase(),
      headers,
      body: typeof init.body === "string" ? init.body : null,
    });

    const step = this.#steps[Math.min(this.#cursor, this.#steps.length - 1)];
    this.#cursor += 1;

    switch (step.kind) {
      case "throw":
        throw new Error("scripted guardFetch synchronous crash");
      case "network":
        return Promise.reject(new TypeError("fetch failed"));
      case "abort":
        return Promise.reject(abortError());
      case "hang":
        return new Promise<Response>((_resolve, reject) => {
          const signal = init.signal;
          if (signal) {
            if (signal.aborted) reject(abortError());
            else signal.addEventListener("abort", () => reject(abortError()), { once: true });
          }
        });
      case "delay": {
        const { ms, body, status } = step;
        return new Promise<Response>((resolve, reject) => {
          const signal = init.signal;
          if (signal?.aborted) {
            reject(abortError());
            return;
          }
          const timer = setTimeout(() => {
            resolve(
              new Response(JSON.stringify(body), {
                status: status ?? 200,
                headers: { "content-type": "application/json" },
              }),
            );
          }, ms);
          signal?.addEventListener(
            "abort",
            () => {
              clearTimeout(timer);
              reject(abortError());
            },
            { once: true },
          );
        });
      }
      case "json":
        return Promise.resolve(
          new Response(JSON.stringify(step.body), {
            status: step.status ?? 200,
            headers: { "content-type": "application/json" },
          }),
        );
      case "text":
        return Promise.resolve(
          new Response(step.text, {
            status: step.status ?? 200,
            headers: step.contentType ? { "content-type": step.contentType } : {},
          }),
        );
      case "status":
        return Promise.resolve(new Response(null, { status: step.status }));
    }
  };
}

// ---------------------------------------------------------------------------
// FakeP1 — contract-enforcing fake P1 server (SPEC §7.3 fake-contract rule)
// ---------------------------------------------------------------------------

/** P1's input chain enum (P1 THESIS §2). */
const P1_CHAINS = ["solana", "base", "ethereum"] as const;
/** P1's real routes (SPEC §7.3): the route carries the tier, not the body. */
export const P1_SCREEN_PATH = "/v1/safety/screen";
export const P1_SCREEN_DEEP_PATH = "/v1/safety/screen/deep";

export type FakeP1Options = {
  /** Token verdict served on both routes (default "safe"). */
  verdict?: string;
  /** Composite score served (default 90). */
  score?: number;
  /** Deployer verdict — served ONLY by the /deep route (default "clean"). */
  deployerVerdict?: string;
};

function zod400(path: string, message: string): Response {
  // Zod-style rejection shape (what P1's zod-validated handler returns).
  return new Response(
    JSON.stringify({
      error: "invalid_request",
      issues: [{ code: "invalid_type", path: [path], message }],
    }),
    { status: 400, headers: { "content-type": "application/json" } },
  );
}

function json200(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A `guardFetch`-compatible fake that ENFORCES P1's real contract (SPEC §7.3,
 * lookup-bug lesson: fakes must encode real contracts, or drift ships):
 *  - GET only; unknown paths → 404. A POST (the OLD, wrong contract) → 405
 *    (method_not_allowed): the INVERTED regression tripwire — a guard drifting
 *    back to POST+body is caught here, not on a live call.
 *  - `mint` + `chain` are read from the URL QUERY (never a body). `mint` must be
 *    a non-empty string — missing/empty (e.g. a legacy call that put the address
 *    in a `token` body) is REJECTED 400 (zod-style on `mint`).
 *  - `chain` must be ∈ {solana, base, ethereum} → else 400 (zod-style on `chain`).
 *  - `/v1/safety/screen` (basic): verdict + score, deployer ALWAYS null,
 *    ignores any `depth` hint.
 *  - `/v1/safety/screen/deep`: same + the deployer block (`deployerVerdict`).
 * Responses echo the mint as `token` (P1 echoes `token` in RESPONSES only).
 */
export class FakeP1 {
  readonly #opts: FakeP1Options;
  /** Every request, in order (headers lowercased, values verbatim). */
  readonly requests: RecordedGuardRequest[] = [];

  constructor(opts: FakeP1Options = {}) {
    this.#opts = opts;
  }

  get callCount(): number {
    return this.requests.length;
  }

  readonly fetch: (url: string, init?: RequestInit) => Promise<Response> = async (
    url,
    init = {},
  ) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((v, k) => {
      headers[k] = v;
    });
    const rawBody = typeof init.body === "string" ? init.body : null;
    const method = (init.method ?? "GET").toUpperCase();
    this.requests.push({ url, method, headers, body: rawBody });

    const parsed = new URL(url);
    const path = parsed.pathname;
    const deep = path === P1_SCREEN_DEEP_PATH;
    if (path !== P1_SCREEN_PATH && !deep) {
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
    }
    // GET only: a POST (the OLD contract) is the inverted regression tripwire.
    if (method !== "GET") {
      return new Response(JSON.stringify({ error: "method_not_allowed" }), { status: 405 });
    }

    // THE CONTRACT: `mint` + `chain` come from the URL QUERY (never a body). A
    // legacy call that put the address in a `token` body reaches here with no
    // `mint` query → 400. P1 only echoes `token` in responses (SPEC §7.3 fix 1).
    const mint = parsed.searchParams.get("mint");
    const chain = parsed.searchParams.get("chain");
    if (typeof mint !== "string" || mint.length === 0) {
      return zod400("mint", "Required");
    }
    if (typeof chain !== "string" || !(P1_CHAINS as readonly string[]).includes(chain)) {
      return zod400("chain", `Expected one of ${P1_CHAINS.join(" | ")}`);
    }
    // NOTE: any `depth` hint is IGNORED — the route carries the tier.

    const verdict = this.#opts.verdict ?? "safe";
    const score = this.#opts.score ?? 90;
    const common = { token: mint, chain, verdict, score };
    return deep
      ? json200(safetyDeep(verdict, this.#opts.deployerVerdict ?? "clean", common))
      : json200(safetyScreen({ ...common, deployer: null }));
  };
}

// ---------------------------------------------------------------------------
// GuardRuntime builder
// ---------------------------------------------------------------------------

export type GuardRuntimeOverrides = {
  guardFetch?: GuardRuntime["guardFetch"];
  /** Provide `trust`/`safety` explicitly; pass `null` to simulate an unset deploy constant. */
  baseUrls?: { trust?: string | null; safety?: string | null };
  installId8?: string;
  via?: string | null;
  now?: () => number;
  log?: GuardRuntime["log"];
};

/** Assemble a `GuardRuntime` from fakes; unspecified fields get inert defaults. */
export function guardRuntime(over: GuardRuntimeOverrides = {}): GuardRuntime {
  const bu = over.baseUrls ?? {};
  return {
    guardFetch:
      over.guardFetch ??
      (async () => {
        throw new Error("guardRuntime.guardFetch not configured");
      }),
    now: over.now ?? (() => 0),
    log: over.log ?? (() => {}),
    installId8: over.installId8 ?? "abcd1234",
    via: over.via ?? null,
    baseUrls: {
      // `!== undefined` so an explicit `null` (unset deploy constant) survives.
      trust: bu.trust !== undefined ? bu.trust : "https://trust.p2.example",
      safety: bu.safety !== undefined ? bu.safety : "https://safety.p1.example",
    },
  };
}

// ---------------------------------------------------------------------------
// GuardInput builder
// ---------------------------------------------------------------------------

import type { GuardInput } from "../src/guards/types.js";
import type { PaymentQuote } from "../src/payer/types.js";

/** A minimal valid `PaymentQuote` (unused by the guards beyond presence). */
export function fakeQuote(over: Partial<PaymentQuote> = {}): PaymentQuote {
  return {
    rail: "x402",
    scheme: "exact",
    network: "base",
    asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    amountAtomic: "10000",
    amountUsd: 0.01,
    payTo: "0x000000000000000000000000000000000000beef",
    maxTimeoutSeconds: 60,
    resource: "https://api.example.com/data",
    mimeType: "application/json",
    outputSchemaSha256: null,
    rawAccepts: {},
    x402Version: 1,
    networkAsDeclared: "base",
    ...over,
  };
}

/** A `GuardInput`. `url` defaults to a query-bearing URL (to exercise stripping). */
export function guardInput(over: Partial<GuardInput> = {}): GuardInput {
  return {
    url: "https://api.example.com/data?secret=shhh&page=2",
    host: "api.example.com",
    quote: over.quote ?? fakeQuote(),
    context: over.context ?? {},
    ...over,
  };
}
