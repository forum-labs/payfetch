/**
 * P3′ payfetch — guard-internal helpers (SPEC §7.2/§7.3/§7.5). NOT part of the
 * §7.5 export surface (`index.ts` re-exports only the two factories + types).
 *
 * Purpose: the discipline shared by the trust and safety guards — integration
 * header construction (THESIS §7), query stripping (THESIS §9), the abortable
 * time-boxed fetch (SPEC §7.5), the advisory-never-blocks mode mapping (SPEC
 * §7.2/§7.3), and the `GuardResult` builders (latency from `rt.now()`, always
 * `costUsd: 0`).
 *
 * Invariants:
 *  - `blockOrWarn` NEVER returns "block" in advisory mode (SPEC §7.2/§7.3).
 *  - Every call goes through `guardFetchWithTimeout`, which aborts at the caller's
 *    mode-scoped `budgetMs` (`guardBudgetMs`, SPEC §7.1) and always clears its
 *    timer (no leaked timers in tests).
 *  - No magic numbers/strings: the guard budget comes from `guardBudgetMs`,
 *    `GUARD_SEND_QUERY`/`INTEGRATION_HEADER` from constants; `guard_unrated` is
 *    typed against the §13 `NoteCode` vocabulary.
 */

import {
  GUARD_SEND_QUERY,
  INTEGRATION_HEADER,
} from "../core/constants.js";
import type { NoteCode } from "../core/notes.js";
import type { GuardId, GuardResult, GuardRuntime } from "./types.js";

/**
 * The one non-verdict-derivable note a guard signals: a passing result whose
 * underlying rating was honest-unknown (trust `unrated`; safety
 * `unknown`/`insufficient_history`). Surfaced in `GuardResult.detail.notes` so
 * the pipeline can emit `guard_unrated` on the receipt (SPEC §7.2/§7.3/§13);
 * guard_blocked/guard_warn/guard_unavailable are derivable from the verdict and
 * are NOT duplicated here. Typed against the §13 vocabulary so a typo won't compile.
 */
export const GUARD_UNRATED_NOTE: NoteCode = "guard_unrated";

/**
 * Integration-header VALUE (THESIS §7): `payfetch/1;i={installId8}` with
 * `;via={viaSlug}` appended only when `via` is a non-empty slug. The header NAME
 * is `INTEGRATION_HEADER` (`X-P2-Integration`).
 */
export function integrationHeaderValue(installId8: string, via: string | null): string {
  const value = `payfetch/1;i=${installId8}`;
  return via != null && via !== "" ? `${value};via=${via}` : value;
}

/** Common guard request headers: the integration header + `Accept: application/json`. */
export function guardHeaders(rt: GuardRuntime): Record<string, string> {
  return {
    [INTEGRATION_HEADER]: integrationHeaderValue(rt.installId8, rt.via),
    Accept: "application/json",
  };
}

/**
 * Strip the query string (and fragment) from a target URL unless
 * `GUARD_SEND_QUERY` (THESIS §9 — a target's query can carry the operator's own
 * secrets). Unparseable input is passed through unchanged (best-effort).
 */
export function stripTarget(url: string): string {
  try {
    const u = new URL(url);
    u.hash = "";
    if (!GUARD_SEND_QUERY) u.search = "";
    return u.toString();
  } catch {
    return url;
  }
}

/** Drop trailing slashes so `{base}/v1/...` never doubles up. */
function trimSlash(base: string): string {
  return base.replace(/\/+$/, "");
}

/** `GET {base}/v1/trust/score?url={target}` — target URL-encoded (SPEC §7.2). */
export function trustScoreUrl(base: string, target: string): string {
  const u = new URL(`${trimSlash(base)}/v1/trust/score`);
  u.searchParams.set("url", target);
  return u.toString();
}

/** `GET {base}/v1/safety/screen[/deep]?mint={mint}&chain={chain}` (SPEC §7.3). */
export function safetyScreenUrl(base: string, mint: string, chain: string, deep: boolean): string {
  const path = deep ? "/v1/safety/screen/deep" : "/v1/safety/screen";
  const u = new URL(`${trimSlash(base)}${path}`);
  u.searchParams.set("mint", mint);
  u.searchParams.set("chain", chain);
  return u.toString();
}

/**
 * Fetch through `rt.guardFetch` with an AbortSignal that fires at the caller's
 * mode-scoped `budgetMs` (SPEC §7.5; enforce = generous cold-screen budget,
 * advisory = proceed-fast — see `guardBudgetMs`). The timer is always cleared, so
 * a fast response leaves no pending timer. Rejections (network/abort/malformed)
 * are the caller's to map to "unavailable" — a genuinely dead host that rejects
 * (connection refused / DNS / reset) surfaces IMMEDIATELY, never waiting out the
 * budget (the fast no-progress abort on a dead host).
 *
 * `dryRun` (SPEC §4.2/§L3) is forwarded to `rt.guardFetch` so a payment_quote /
 * dryRun paid_fetch forces the FREE path — a paying guard signs nothing on a
 * dry-run.
 */
export async function guardFetchWithTimeout(
  rt: GuardRuntime,
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
  budgetMs: number,
  dryRun?: boolean,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budgetMs);
  try {
    return await rt.guardFetch(url, { ...init, signal: controller.signal }, { dryRun });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Unwrap the scaffold response envelope (SPEC §7.2, live-verified 2026-07-03):
 * the scaffold wraps every product response as
 * `{ data: <product payload>, freshnessTs, disclaimer }` (SCAFFOLD_SPEC §3
 * step 5). Both guards read the product payload from `.data` when the body is a
 * `{data:{…}}` envelope, and fall back to the top-level object otherwise
 * (tolerant of a bare payload). Non-object input returns `null` (→ malformed).
 */
export function unwrapEnvelope(body: unknown): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;
  const data = b.data;
  if (typeof data === "object" && data !== null && !Array.isArray(data)) {
    return data as Record<string, unknown>;
  }
  return b;
}

/**
 * Mode → blocking verdict. SPEC §7.2/§7.3 invariant: advisory mode NEVER returns
 * "block"; it downgrades to "warn".
 */
export function blockOrWarn(mode: "advisory" | "enforce"): "block" | "warn" {
  return mode === "enforce" ? "block" : "warn";
}

/** Build a `GuardResult` with latency from `rt.now()` and `costUsd: 0` (SPEC §7.1). */
export function guardResult(
  id: GuardId,
  verdict: GuardResult["verdict"],
  detail: Record<string, unknown>,
  startMs: number,
  rt: GuardRuntime,
): GuardResult {
  return {
    id,
    verdict,
    detail,
    latencyMs: Math.max(0, rt.now() - startMs),
    costUsd: 0, // paying, if any, happens inside rt.guardFetch — core's concern (SPEC §7.5)
  };
}

/**
 * An "unavailable" result (SPEC §7.2/§7.3): baseUrl unset, 402, 5xx, other
 * non-2xx, network error, malformed JSON, timeout, or crash. The proceed-vs-block
 * resolution is the pipeline's job (`onUnavailable`), never the guard's. `reason`
 * is diagnostics only.
 */
export function unavailable(
  id: GuardId,
  reason: string,
  startMs: number,
  rt: GuardRuntime,
): GuardResult {
  return guardResult(id, "unavailable", { reason }, startMs, rt);
}
