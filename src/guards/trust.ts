/**
 * P3′ payfetch — trust guard (P2 consultation), SPEC §7.2. Default ON, advisory.
 *
 * Purpose: before paying, ask P2's scoring API whether the target endpoint is
 * trustworthy, and map its `TrustScore` (P2 PROBER_SPEC §8.5) to a
 * pass/warn/block/unavailable verdict — degradation-safe.
 *
 * Invariants (SPEC §7.2):
 *  - `applies()` is ALWAYS true — the trust guard runs on every evaluated 402.
 *  - The target URL has its query string stripped (unless `GUARD_SEND_QUERY`,
 *    THESIS §9) before it is embedded in `?url=`.
 *  - The request carries the `X-P2-Integration` header (THESIS §7 instrument)
 *    and `Accept: application/json`, and aborts at the mode-scoped `guardBudgetMs`
 *    (advisory — the trust default — proceeds fast).
 *  - `baseUrls.trust === null` ⇒ "unavailable" WITHOUT any fetch.
 *  - ANY 402 / 5xx / other non-2xx / network / malformed JSON ⇒ "unavailable".
 *    The guard NEVER resolves an "unavailable" into proceed/block (that is the
 *    pipeline's `onUnavailable` job) and NEVER returns "block" in advisory mode.
 *  - A crash inside `check()` returns "unavailable" — it never rejects (SPEC §7.4).
 *  - `costUsd` is 0 here; any payment happens inside `rt.guardFetch` (SPEC §7.5).
 */

import { guardBudgetMs } from "../core/constants.js";
import type { PrePayGuard, GuardInput, GuardResult, GuardRuntime, TrustGuardConfig } from "./types.js";
import {
  GUARD_UNRATED_NOTE,
  blockOrWarn,
  guardFetchWithTimeout,
  guardHeaders,
  guardResult,
  stripTarget,
  trustScoreUrl,
  unavailable,
  unwrapEnvelope,
} from "./internal.js";

/** The subset of P2 `TrustScore` (PROBER_SPEC §8.5) the guard maps + surfaces. */
type ParsedTrustScore = { score: number | null; verdict: string; counts: unknown };

/**
 * Defensively read a `TrustScore` body (P2 PROBER_SPEC §8.5). First unwraps the
 * scaffold `{data,freshnessTs,disclaimer}` envelope (SPEC §7.2, tolerant of a
 * bare payload). Requires a string `verdict` and a `score` that is a number or
 * null; anything else is treated as malformed (→ "unavailable"), never guessed.
 * `counts` is surfaced as-is.
 */
function parseTrustScore(body: unknown): ParsedTrustScore | null {
  const b = unwrapEnvelope(body);
  if (b === null) return null;
  if (typeof b.verdict !== "string") return null;
  const score = b.score;
  if (typeof score !== "number" && score !== null) return null;
  return { score, verdict: b.verdict, counts: b.counts ?? null };
}

/**
 * Map a parsed `TrustScore` to a verdict — the SPEC §7.2 ladder, first match wins:
 *   1. API verdict ∈ blockVerdicts               → block (enforce) / warn (advisory)
 *   2. score !== null && minScore !== null &&
 *      score < minScore                          → block / warn
 *   3. API verdict "unrated"                      → pass + guard_unrated
 *      (blockUnrated: true flips to block / warn)
 *   4. else                                       → pass
 */
function mapTrust(
  cfg: TrustGuardConfig,
  parsed: ParsedTrustScore,
  startMs: number,
  rt: GuardRuntime,
): GuardResult {
  const { score, verdict, counts } = parsed;
  const detail: Record<string, unknown> = { score, verdict, counts };

  if (cfg.blockVerdicts.includes(verdict)) {
    return guardResult("trust", blockOrWarn(cfg.mode), detail, startMs, rt);
  }
  if (score !== null && cfg.minScore !== null && score < cfg.minScore) {
    return guardResult("trust", blockOrWarn(cfg.mode), detail, startMs, rt);
  }
  if (verdict === "unrated") {
    if (cfg.blockUnrated) {
      return guardResult("trust", blockOrWarn(cfg.mode), detail, startMs, rt);
    }
    detail.notes = [GUARD_UNRATED_NOTE];
    return guardResult("trust", "pass", detail, startMs, rt);
  }
  return guardResult("trust", "pass", detail, startMs, rt);
}

/**
 * Construct the trust guard (SPEC §7.5 factory). `cfg` is the §4.1 `guards.trust`
 * block; `rt` is the §7.5 runtime (fetch, clock, log, identity, base URLs).
 */
export function createTrustGuard(cfg: TrustGuardConfig, rt: GuardRuntime): PrePayGuard {
  return {
    id: "trust",
    // SPEC §7.2: the trust guard applies to every evaluated 402.
    applies(): boolean {
      return true;
    },
    // `deps` (PrePayGuard interface) is unused: the guard fetches via rt.guardFetch (§7.5).
    async check(req: GuardInput): Promise<GuardResult> {
      const start = rt.now();
      // HOT-RELOAD (SPEC §4.1/§7.5): use the LIVE per-request config the pipeline
      // threads in (`req.config`), NOT the build-time `cfg` captured in this
      // closure — otherwise the guard's own time-box + verdict mapping drift from
      // the pipeline's runGuard race the moment an operator hot-reloads
      // `guards.trust`. Fall back to `cfg` for standalone calls (tests). The
      // pipeline passes the trust config to the trust guard (id-matched).
      const activeCfg = (req.config as TrustGuardConfig | undefined) ?? cfg;
      try {
        const base = rt.baseUrls.trust;
        if (base === null) {
          // SPEC §7.5: unset deploy constant ⇒ unavailable WITHOUT fetching.
          return unavailable("trust", "base_url_unset", start, rt);
        }

        const target = stripTarget(req.url);
        const url = trustScoreUrl(base, target);

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
            // §7.1: advisory (the trust default) proceeds fast; enforce gets the
            // generous cold-screen budget. Sized from the LIVE mode so it matches
            // the pipeline `runGuard` race (which reads the same live snapshot).
            guardBudgetMs(activeCfg.mode),
            req.dryRun,
          );
        } catch {
          // timeout (abort) or network error (SPEC §7.2).
          return unavailable("trust", "fetch_failed", start, rt);
        }

        if (!res.ok) {
          // 402 (free tier exhausted, $0 guard budget), 5xx, or any other non-2xx.
          return unavailable("trust", `http_${res.status}`, start, rt);
        }

        let body: unknown;
        try {
          body = await res.json();
        } catch {
          return unavailable("trust", "malformed_json", start, rt);
        }

        const parsed = parseTrustScore(body);
        if (parsed === null) {
          return unavailable("trust", "malformed_body", start, rt);
        }
        // LIVE cfg (blockVerdicts / minScore / blockUnrated / blockOrWarn(mode)).
        return mapTrust(activeCfg, parsed, start, rt);
      } catch {
        // SPEC §7.4: a guard crash is "unavailable", never a pipeline exception.
        return unavailable("trust", "crash", start, rt);
      }
    },
  };
}
