/**
 * P3′ payfetch — pre-payment guard interface + config + wiring seam (SPEC §7).
 *
 * Purpose: the contract through which the pipeline consults P2 (trust) and P1
 * (safety) BEFORE paying, degradation-safe. Holds three things, all normative:
 *  1. The §7.1 guard interface (`PrePayGuard`, `GuardInput`, `GuardResult`).
 *  2. The §4.1 guard config blocks (`TrustGuardConfig`, `SafetyGuardConfig`) —
 *     the SINGLE SOURCE OF TRUTH that `core/policy.ts` Policy.guards imports
 *     (SPEC §7.5), so config never drifts between the policy engine and the
 *     guards that consume it.
 *  3. The §7.5 wiring seam (`GuardRuntime`) the core supplies to the factories.
 *
 * Invariants (transcribed from SPEC §7):
 *  - `check` MUST resolve within the mode-scoped budget (`guardBudgetMs`, §7.1); a
 *    guard CRASH is surfaced as a `verdict: "unavailable"`, never a pipeline
 *    exception (§7.4). The guard implementations enforce this themselves (try/catch
 *    → unavailable) AND the pipeline double-wraps (§7.5).
 *  - `applies` gates a guard by request shape (safety: only when
 *    `context.tokenAddress` is present).
 *  - A guard NEVER returns "block" in advisory mode — advisory downgrades to
 *    "warn" (§7.2/§7.3). A guard NEVER pays and NEVER resolves "unavailable" into
 *    proceed/block: paying happens inside `GuardRuntime.guardFetch` and the
 *    proceed-vs-block resolution of an "unavailable" is the PIPELINE's job via
 *    `onUnavailable` (§7.2/§7.5).
 *  - `costUsd` is 0 here; guard fetches never trigger guards
 *    (GUARD_RECURSION_DEPTH = 0) and never trigger approval (§7.2).
 */

import {
  GUARD_DAILY_BUDGET_DEFAULT_USD,
  SAFETY_BLOCK_DEPLOYER_VERDICTS_DEFAULT,
  SAFETY_BLOCK_VERDICTS_DEFAULT,
  SAFETY_GUARD_DEPTH_DEFAULT,
  SAFETY_ON_DEGRADED_DEFAULT,
  TRUST_BLOCK_VERDICTS_DEFAULT,
} from "../core/constants.js";
import type { PayfetchDeps, PaymentQuote } from "../payer/types.js";

/** Guard identity. SPEC §7.1 — used in note codes (`guard_*:{id}`). */
export type GuardId = "trust" | "safety";

export interface PrePayGuard {
  id: GuardId;
  applies(req: GuardInput): boolean; // safety: only when context.tokenAddress
  check(req: GuardInput, deps: PayfetchDeps): Promise<GuardResult>; // MUST resolve ≤ guardBudgetMs
}

export type GuardInput = {
  url: string; // query STRIPPED unless GUARD_SEND_QUERY (§15) — THESIS §9
  host: string;
  quote: PaymentQuote;
  context: { tokenAddress?: string; chain?: "solana" | "base" | "ethereum" };
  /**
   * True for a payment_quote / dryRun paid_fetch — guards run on the FREE tier
   * only and MUST NOT pay/sign, even when the guard has a budget (SPEC §4.2/§L3).
   * A paying guard whose free tier is exhausted degrades to "unavailable" — a
   * dry-run never produces a signature.
   */
  dryRun?: boolean;
  /**
   * The LIVE per-request guard-config snapshot (SPEC §4.1 `guards.<id>`), supplied
   * by the pipeline from the mtime-reloaded `policyProvider`. A guard is BUILT once
   * (`createPayfetch`/`buildDefaultGuards`) but its config is HOT-RELOADABLE (M5/M6);
   * the guard MUST use THIS live snapshot — not the config captured at build time —
   * for its own time-box (`guardBudgetMs(mode)`) AND its verdict mapping
   * (`blockOrWarn(mode)`, `blockVerdicts`, `minScore`, `depth`, …), so the guard's
   * socket-abort NEVER drifts from the pipeline's `runGuard` race, which reads the
   * same live snapshot. Absent when `check()` is called standalone (tests) — the
   * guard then falls back to its captured build-time config. The pipeline passes
   * the config matching `guard.id`, so a guard narrows this union to its own type.
   */
  config?: TrustGuardConfig | SafetyGuardConfig;
};

export type GuardResult = {
  id: string;
  verdict: "pass" | "warn" | "block" | "unavailable";
  detail: Record<string, unknown>; // trust: {score, verdict, counts}; safety: {verdict, score, deployer}
  latencyMs: number;
  costUsd: number; // 0 on free tier
};

// ---------------------------------------------------------------------------
// Guard configuration (SPEC §4.1 guards.trust / guards.safety)
//
// SINGLE SOURCE OF TRUTH (SPEC §7.5): `core/policy.ts`'s `Policy.guards` imports
// these two types so the policy engine and the guards that consume the config
// can never drift. Field names/types/defaults are transcribed verbatim from
// SPEC §4.1; the concrete frozen defaults (built from the §15 constants) are
// `DEFAULT_TRUST_GUARD_CONFIG` / `DEFAULT_SAFETY_GUARD_CONFIG` below.
// ---------------------------------------------------------------------------

/**
 * Trust-guard (P2) policy block — SPEC §4.1 `guards.trust`. Consumed by
 * `createTrustGuard` (SPEC §7.2).
 */
export type TrustGuardConfig = {
  /** Guard enabled. SPEC §4.1 default `true` (THESIS §5, flagged decision). */
  enabled: boolean;
  /** advisory → warn only; enforce → may block. SPEC §4.1 default `"advisory"`.
   *  A guard NEVER returns "block" in advisory mode (SPEC §7.2 invariant). */
  mode: "advisory" | "enforce";
  /** Minimum acceptable TrustScore; `null` ⇒ verdict-driven only. SPEC §4.1
   *  default `null`. Ignored when the API `score` is null (SPEC §7.2). */
  minScore: number | null;
  /** P2 verdicts that block/warn. SPEC §4.1 default `["unreliable"]`
   *  (`TRUST_BLOCK_VERDICTS_DEFAULT`). */
  blockVerdicts: string[];
  /** Treat `unrated` as block/warn instead of pass. SPEC §4.1 default `false`
   *  (unrated = honest-unknown; blocking every new endpoint would strangle the
   *  ecosystem the client exists to serve — SPEC §7.2). */
  blockUnrated: boolean;
  /** Enforce-mode-only: what the PIPELINE does when the guard returns
   *  "unavailable". SPEC §4.1 default `"block"` (fail closed). The guard itself
   *  only ever RETURNS "unavailable"; resolution is core's job (SPEC §7.2/§7.5). */
  onUnavailable: "proceed" | "block";
  /** Guard's own daily spend ceiling (USD). SPEC §4.1 default `0`
   *  (`GUARD_DAILY_BUDGET_DEFAULT_USD` — free tier only). */
  dailyBudgetUsd: number;
};

/**
 * Safety-guard (P1) policy block — SPEC §4.1 `guards.safety`. Consumed by
 * `createSafetyGuard` (SPEC §7.3).
 */
export type SafetyGuardConfig = {
  /** Guard enabled. SPEC §4.1 default `false`. */
  enabled: boolean;
  /** advisory → warn only; enforce → may block. SPEC §4.1 default `"enforce"`
   *  (when enabled). A guard NEVER returns "block" in advisory mode (§7.3). */
  mode: "advisory" | "enforce";
  /** Screen depth sent to P1. SPEC §4.1 default `"basic"`
   *  (`SAFETY_GUARD_DEPTH_DEFAULT`) — `deep` is always-paid on P1, so with the
   *  default `dailyBudgetUsd: 0` a deep-configured guard would always 402 →
   *  unavailable (review #7). `deep` requires `dailyBudgetUsd > 0` to be useful. */
  depth: "basic" | "deep";
  /** P1 token verdicts that block/warn. SPEC §4.1 default `["danger"]`
   *  (`SAFETY_BLOCK_VERDICTS_DEFAULT`). */
  blockVerdicts: string[];
  /** P1 deployer verdicts that block/warn — applied ONLY when `depth === "deep"`
   *  (the deployer block exists only in deep responses). SPEC §4.1 default
   *  `["serial_rugger"]` (`SAFETY_BLOCK_DEPLOYER_VERDICTS_DEFAULT`). */
  blockDeployerVerdicts: string[];
  /** Enforce-mode-only: what the PIPELINE does when the guard returns
   *  "unavailable" (baseUrl unset / 402 / 5xx / network / malformed / timeout /
   *  crash — a genuinely dead P1). SPEC §4.1 default `"block"` (fail closed). */
  onUnavailable: "proceed" | "block";
  /** Enforce-mode-only: what the PIPELINE does when the safety guard reports a
   *  DEGRADED screen (`degraded: true` on an inconclusive verdict — a danger-
   *  relevant upstream capped/absent that may UNDER-call danger). SPEC §7.3
   *  default `"block"` (fail closed — same effect as before the split). Decoupled
   *  from `onUnavailable` (P3 review §4b): softening degrade-noise here does NOT
   *  soften a dead-P1 block. */
  onDegraded: "block" | "warn" | "proceed";
  /** Guard's own daily spend ceiling (USD). SPEC §4.1 default `0`. */
  dailyBudgetUsd: number;
};

/**
 * Frozen default trust-guard config (SPEC §4.1 defaults, sourced from §15
 * constants). The core's Policy merges operator overrides over this; exported
 * here so there is exactly one place the defaults live (SPEC §7.5).
 */
export const DEFAULT_TRUST_GUARD_CONFIG: TrustGuardConfig = Object.freeze({
  enabled: true,
  mode: "advisory",
  minScore: null,
  blockVerdicts: [...TRUST_BLOCK_VERDICTS_DEFAULT],
  blockUnrated: false,
  onUnavailable: "block",
  dailyBudgetUsd: GUARD_DAILY_BUDGET_DEFAULT_USD,
});

/**
 * Frozen default safety-guard config (SPEC §4.1 defaults, sourced from §15
 * constants). `mode` is the §4.1 "enforce when enabled" default; the guard is
 * `enabled: false` by default so it is inert until an operator opts in.
 */
export const DEFAULT_SAFETY_GUARD_CONFIG: SafetyGuardConfig = Object.freeze({
  enabled: false,
  mode: "enforce",
  depth: SAFETY_GUARD_DEPTH_DEFAULT,
  blockVerdicts: [...SAFETY_BLOCK_VERDICTS_DEFAULT],
  blockDeployerVerdicts: [...SAFETY_BLOCK_DEPLOYER_VERDICTS_DEFAULT],
  onUnavailable: "block",
  onDegraded: SAFETY_ON_DEGRADED_DEFAULT,
  dailyBudgetUsd: GUARD_DAILY_BUDGET_DEFAULT_USD,
});

// ---------------------------------------------------------------------------
// Wiring seam (SPEC §7.5) — supplied by core to the guard factories
// ---------------------------------------------------------------------------

/**
 * The runtime the core hands each guard factory (SPEC §7.5). Decouples guards
 * from the full `PayfetchDeps`: a guard only needs a fetch (possibly
 * budget-reserving), a clock, a log sink, the integration-header identity, and
 * the P1/P2 base URLs.
 */
export type GuardRuntime = {
  /**
   * Supplied by core: plain `deps.fetch` when the guard's `dailyBudgetUsd === 0`;
   * core's budget-reserving, payer-backed wrapper when `> 0` (SPEC §7.2). Guards
   * treat ANY 402 Response from `guardFetch` as "unavailable" — paying is core's
   * concern, never the guard's.
   *
   * `opts.dryRun: true` forces the FREE path — no reservation, no signature —
   * even when the guard has a budget (SPEC §4.2/§L3): a payment_quote / dryRun
   * paid_fetch must never move money, not even on a paying guard's behalf.
   */
  guardFetch: (
    url: string,
    init: RequestInit,
    opts?: { dryRun?: boolean },
  ) => Promise<Response>;
  now: () => number;
  log: PayfetchDeps["log"];
  /** SPEC §7.2 integration-header value (`payfetch/1;i={installId8}`). */
  installId8: string;
  /** Optional embedding-framework slug (`;via={viaSlug}` when set). */
  via: string | null;
  /**
   * From `P2_TRUST_BASE_URL` / `P1_SAFETY_BASE_URL`; `null` (unset deploy
   * constant) ⇒ the guard returns "unavailable" WITHOUT fetching (SPEC §7.5).
   */
  baseUrls: { trust: string | null; safety: string | null };
};
