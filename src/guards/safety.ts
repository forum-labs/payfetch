/**
 * P3′ payfetch — safety guard (P1 consultation), SPEC §7.3 (v1.1). Default OFF.
 *
 * Purpose: when the calling context supplies a token address, screen it via P1
 * before paying, and map its screen output (P1 THESIS §2) to a
 * pass/warn/block/unavailable verdict — degradation-safe.
 *
 * Invariants (SPEC §7.3 — P1's REAL contract, cross-product review fix 1):
 *  - `applies()` iff `context.tokenAddress` is present (else the guard never runs).
 *  - The request is `GET {base}/v1/safety/screen[/deep]?mint=<tokenAddress>&
 *    chain=<context.chain ?? "solana">` — mirroring the trust guard's
 *    `GET ?url=`. The input field is `mint` in the QUERY, NOT `token` (P1 only
 *    echoes `token` in responses), and there is NO `depth` param: THE ROUTE
 *    CARRIES THE TIER (x402 needs a static price per route). No request body.
 *  - `cfg.depth === "basic"` → `GET {base}/v1/safety/screen` (free; verdict +
 *    score, no deployer block); `cfg.depth === "deep"` →
 *    `GET {base}/v1/safety/screen/deep` ($0.05 paid; adds the deployer block).
 *    Default stays "basic" — deep is always-paid on P1 (review #7).
 *  - Same header / timeout discipline as the trust guard (X-P2-Integration,
 *    Accept: application/json, abort at the mode-scoped `guardBudgetMs` — enforce
 *    gets the generous cold-screen budget); there is no request body, so no
 *    Content-Type header.
 *  - The DEPLOYER block (`deployer.verdict ∈ blockDeployerVerdicts`) is applied
 *    ONLY when `depth === "deep"` — basic responses carry no deployer block.
 *  - `verdict "unknown"` / deployer `"insufficient_history"` (deep) ⇒ pass + note.
 *  - `baseUrls.safety === null`, ANY 402 / 5xx / other non-2xx / network /
 *    malformed JSON ⇒ "unavailable"; a crash ⇒ "unavailable" (never rejects);
 *    advisory mode NEVER returns "block". `costUsd` is 0 here (SPEC §7.5).
 */

import { guardBudgetMs } from "../core/constants.js";
import type { PrePayGuard, GuardInput, GuardResult, GuardRuntime, SafetyGuardConfig } from "./types.js";
import {
  GUARD_UNRATED_NOTE,
  blockOrWarn,
  guardFetchWithTimeout,
  guardHeaders,
  guardResult,
  safetyScreenUrl,
  unavailable,
  unwrapEnvelope,
} from "./internal.js";

/** The subset of the P1 screen output (THESIS §2) the guard maps + surfaces. */
type ParsedScreen = {
  verdict: string;
  score: number | null;
  deployer: { verdict: string | null } | Record<string, unknown> | null;
  deployerVerdict: string | null;
  /**
   * P1 basic-screen contract field (dim5-MED): true iff a DANGER-relevant upstream
   * was capped/absent (e.g. a RugCheck-cap degrade), so the verdict may UNDER-call
   * danger. Absent/non-boolean ⇒ false (forward-compatible with a pre-contract P1).
   */
  degraded: boolean;
};

/** Token verdicts that are inconclusive about danger (a degrade may hide a real danger). */
const DANGER_INCONCLUSIVE_VERDICTS: ReadonlySet<string> = new Set(["unknown", "caution"]);

/**
 * Defensively read a P1 screen body (THESIS §2). First unwraps the scaffold
 * `{data,freshnessTs,disclaimer}` envelope (SPEC §7.2, tolerant of a bare
 * payload — P1's paid response is wrapped identically to P2's). Requires a
 * string `verdict`; `score` tolerated as number or null; `deployer` is an
 * object (deep) or null (basic). Anything else ⇒ malformed (→ "unavailable"),
 * never guessed. The deployer block is read from the UNWRAPPED payload.
 */
function parseScreen(body: unknown): ParsedScreen | null {
  const b = unwrapEnvelope(body);
  if (b === null) return null;
  if (typeof b.verdict !== "string") return null;
  const score = typeof b.score === "number" ? b.score : null;
  // dim5-MED: the basic-screen `degraded` flag. Default false when absent (a
  // pre-contract P1) or non-boolean — never GUESS a degrade, and never let a
  // malformed value turn a clean screen fail-closed.
  const degraded = b.degraded === true;

  let deployer: ParsedScreen["deployer"] = null;
  let deployerVerdict: string | null = null;
  if (typeof b.deployer === "object" && b.deployer !== null) {
    deployer = b.deployer as Record<string, unknown>;
    const dv = (deployer as Record<string, unknown>).verdict;
    deployerVerdict = typeof dv === "string" ? dv : null;
  }
  return { verdict: b.verdict, score, deployer, deployerVerdict, degraded };
}

/**
 * Map a parsed P1 screen to a verdict — the SPEC §7.3 ladder, first match wins:
 *   1. token verdict ∈ blockVerdicts                          → block / warn
 *   2. depth === "deep" && deployer.verdict ∈
 *      blockDeployerVerdicts                                   → block / warn
 *   3. token verdict "unknown" (or deep deployer
 *      "insufficient_history")                                 → pass + guard_unrated
 *   4. else                                                    → pass
 */
function mapSafety(
  cfg: SafetyGuardConfig,
  parsed: ParsedScreen,
  startMs: number,
  rt: GuardRuntime,
): GuardResult {
  const { verdict, score, deployer, deployerVerdict, degraded } = parsed;
  const detail: Record<string, unknown> = { verdict, score, deployer, degraded };

  if (cfg.blockVerdicts.includes(verdict)) {
    return guardResult("safety", blockOrWarn(cfg.mode), detail, startMs, rt);
  }
  // SPEC §7.3: deployer block ONLY at deep (basic responses carry no deployer block).
  if (
    cfg.depth === "deep" &&
    deployerVerdict !== null &&
    cfg.blockDeployerVerdicts.includes(deployerVerdict)
  ) {
    return guardResult("safety", blockOrWarn(cfg.mode), detail, startMs, rt);
  }

  // dim5-MED (fail-closed on a DEGRADED screen): a danger-relevant upstream was
  // capped/absent, so a non-blocking-but-inconclusive verdict (unknown/caution)
  // may be UNDER-calling danger — it looks like an honest unknown but isn't. In
  // ENFORCE mode, surface it as "unavailable" so the pipeline's `onUnavailable`
  // (default "block") fails closed. Advisory never blocks, so it keeps proceeding
  // (the honest-unknown pass below) — there is nothing to fail closed. A CLEAN
  // (non-degraded) unknown, and a conclusive safe/danger verdict, are unaffected.
  if (cfg.mode === "enforce" && degraded && DANGER_INCONCLUSIVE_VERDICTS.has(verdict)) {
    return unavailable("safety", "degraded_screen", startMs, rt);
  }

  const inconclusive =
    verdict === "unknown" ||
    (cfg.depth === "deep" && deployerVerdict === "insufficient_history");
  if (inconclusive) {
    detail.notes = [GUARD_UNRATED_NOTE];
  }
  return guardResult("safety", "pass", detail, startMs, rt);
}

/**
 * Construct the safety guard (SPEC §7.5 factory). `cfg` is the §4.1
 * `guards.safety` block; `rt` is the §7.5 runtime.
 */
export function createSafetyGuard(cfg: SafetyGuardConfig, rt: GuardRuntime): PrePayGuard {
  return {
    id: "safety",
    // SPEC §7.3: applies only when the context supplies a token address.
    applies(req: GuardInput): boolean {
      const token = req.context.tokenAddress;
      return typeof token === "string" && token.length > 0;
    },
    // `deps` (PrePayGuard interface) is unused: the guard fetches via rt.guardFetch (§7.5).
    async check(req: GuardInput): Promise<GuardResult> {
      const start = rt.now();
      // HOT-RELOAD (SPEC §4.1/§7.5): use the LIVE per-request config the pipeline
      // threads in (`req.config`), NOT the build-time `cfg` captured here —
      // otherwise the guard's time-box (`guardBudgetMs`), route TIER (`depth`), and
      // verdict mapping (`blockOrWarn(mode)`/`blockVerdicts`/deployer block) drift
      // from the pipeline's runGuard race when `guards.safety` is hot-reloaded (e.g.
      // an operator flips advisory→enforce with no restart, which would otherwise
      // SILENTLY re-open the cold-screen timeout blocker). Falls back to `cfg` for
      // standalone calls. The pipeline id-matches the safety config to this guard.
      const activeCfg = (req.config as SafetyGuardConfig | undefined) ?? cfg;
      try {
        const base = rt.baseUrls.safety;
        if (base === null) {
          return unavailable("safety", "base_url_unset", start, rt);
        }
        const token = req.context.tokenAddress;
        if (token == null || token === "") {
          // Defensive: applies() gates this; if reached, degrade (never fetch a null token).
          return unavailable("safety", "no_token", start, rt);
        }

        // SPEC §7.3 (P1's real contract): the input field is `mint` (never
        // `token`) carried in the QUERY; no `depth` param — the route carries
        // the tier. GET, no body, so no Content-Type header.
        const chain = req.context.chain ?? "solana";
        const url = safetyScreenUrl(base, token, chain, activeCfg.depth === "deep");

        let res: Response;
        try {
          // SPEC §4.2/§L3: a dry-run/quote forces guardFetch onto the free tier.
          res = await guardFetchWithTimeout(
            rt,
            url,
            {
              method: "GET",
              headers: guardHeaders(rt),
            },
            // §7.1: the safety guard defaults to enforce, which gets the generous
            // cold-screen budget so it can actually GET `danger` on a first-touch
            // (cache-cold) token — the confirmed go-live blocker. Sized from the
            // LIVE mode so it matches the pipeline `runGuard` race.
            guardBudgetMs(activeCfg.mode),
            req.dryRun,
          );
        } catch {
          return unavailable("safety", "fetch_failed", start, rt);
        }

        if (!res.ok) {
          return unavailable("safety", `http_${res.status}`, start, rt);
        }

        let body: unknown;
        try {
          body = await res.json();
        } catch {
          return unavailable("safety", "malformed_json", start, rt);
        }

        const parsed = parseScreen(body);
        if (parsed === null) {
          return unavailable("safety", "malformed_body", start, rt);
        }
        // LIVE cfg (depth / blockVerdicts / blockDeployerVerdicts / blockOrWarn(mode)).
        return mapSafety(activeCfg, parsed, start, rt);
      } catch {
        // SPEC §7.4: a guard crash is "unavailable", never a pipeline exception.
        return unavailable("safety", "crash", start, rt);
      }
    },
  };
}
