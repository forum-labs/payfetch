/**
 * P3′ payfetch — machine-readable note codes (SPEC §13).
 *
 * Purpose: a closed, typed vocabulary of the `notes[]` codes that land on
 * receipts (§8.3), plus constructors for the PARAMETERIZED codes so call sites
 * cannot typo a code or forget the separator/format.
 *
 * Invariants:
 *  - Every code the codebase emits is either a member of `NoteCode` or produced
 *    by a constructor here. No hand-built note strings elsewhere (SPEC §13).
 *  - Parameterized codes use the SPEC §13 spelling exactly: `:` separates the
 *    stem from a free parameter (`budget_exhausted:{which}`, `guard_*:{id}`,
 *    `redirected:{n}`, `autodeny_strike:{n}`, `elicit_unsupported_fallback:{m}`).
 *    The one underscore-parameterized code, `unsupported_scheme_upto`, is a fixed
 *    §13 literal (upto is the only scheme it applies to in v1).
 *  - Degrade rule (SPEC §13): codes describe degradation toward not-paying /
 *    over-counting spend, never toward paying or freeing budget.
 */

import type { GuardId } from "../guards/types.js";

// ---------------------------------------------------------------------------
// Fixed codes (no parameter) — verbatim from SPEC §13
// ---------------------------------------------------------------------------

/** Note codes with no runtime parameter. SPEC §13. */
export type FixedNoteCode =
  | "malformed_402"
  | "unsupported_terms"
  | "unsupported_scheme_upto"
  | "unknown_asset"
  | "unsupported_network"
  | "host_denied"
  | "host_not_allowlisted"
  | "host_auto_denied"
  | "per_call_cap_exceeded"
  | "guard_unrated"
  | "approval_mode_deny"
  | "approval_timeout"
  | "approval_queue_expired"
  // The client could NOT service a human elicitation (§6, P3 desktop-fallback fix):
  //  - `elicit_unsupported`: the client never advertised the `elicitation` capability.
  //  - `elicit_cancelled`:   the client advertised it but returned `cancel`/dismissed
  //    the dialog without a human decision (e.g. Claude Desktop). NEITHER is a human
  //    denial; both route through `approval.elicitFallback` (queue or a CLEAR deny).
  | "elicit_unsupported"
  | "elicit_cancelled"
  | "settlement_unconfirmed"
  | "body_truncated"
  | "insecure_redirect"
  | "private_target_blocked"
  | "hold_released_expiry"
  | "test_mode";

// ---------------------------------------------------------------------------
// Parameterized code shapes (template-literal types) — SPEC §13
// ---------------------------------------------------------------------------

/** Which budget counter was exhausted (D11 / §5.1). SPEC §13 `budget_exhausted:{which}`. */
export type BudgetWhich = "day" | "host" | "total";
/** Elicitation-unsupported fallback taken (§6). SPEC §13. */
export type ElicitFallback = "queue" | "deny";
/** Why a config pre-approval fired (§6, P3 review): a per-host allow, or the cap ceiling. */
export type PreapprovedWhich = "host" | "cap";

export type BudgetExhaustedNote = `budget_exhausted:${BudgetWhich}`;
export type PreapprovedNote = `preapproved:${PreapprovedWhich}`;
export type GuardBlockedNote = `guard_blocked:${GuardId}`;
export type GuardUnavailableNote = `guard_unavailable:${GuardId}`;
export type GuardWarnNote = `guard_warn:${GuardId}`;
export type RedirectedNote = `redirected:${number}`;
export type AutodenyStrikeNote = `autodeny_strike:${number}`;
export type ElicitFallbackNote = `elicit_unsupported_fallback:${ElicitFallback}`;

/** The full closed vocabulary of receipt `notes[]` codes. SPEC §13. */
export type NoteCode =
  | FixedNoteCode
  | BudgetExhaustedNote
  | PreapprovedNote
  | GuardBlockedNote
  | GuardUnavailableNote
  | GuardWarnNote
  | RedirectedNote
  | AutodenyStrikeNote
  | ElicitFallbackNote;

// ---------------------------------------------------------------------------
// Constructors for the parameterized codes — the typo-proof seam
// ---------------------------------------------------------------------------

/** `budget_exhausted:{day|host|total}` (D11 / §5.1). */
export function budgetExhausted(which: BudgetWhich): BudgetExhaustedNote {
  return `budget_exhausted:${which}`;
}

/** `preapproved:{host|cap}` — a config pre-approval consumed above-threshold (§6). */
export function preapproved(which: PreapprovedWhich): PreapprovedNote {
  return `preapproved:${which}`;
}

/** `guard_blocked:{id}` (D8 / §7). */
export function guardBlocked(id: GuardId): GuardBlockedNote {
  return `guard_blocked:${id}`;
}

/** `guard_unavailable:{id}` (§7.2/§7.3 — guard crashed/timed out/402'd). */
export function guardUnavailable(id: GuardId): GuardUnavailableNote {
  return `guard_unavailable:${id}`;
}

/** `guard_warn:{id}` (advisory-mode block, or minScore breach) (§7). */
export function guardWarn(id: GuardId): GuardWarnNote {
  return `guard_warn:${id}`;
}

/** `redirected:{n}` — n hops followed (§11). */
export function redirected(n: number): RedirectedNote {
  return `redirected:${n}`;
}

/** `autodeny_strike:{n}` — nth strike recorded for the host (§5.4). */
export function autodenyStrike(n: number): AutodenyStrikeNote {
  return `autodeny_strike:${n}`;
}

/** `elicit_unsupported_fallback:{queue|deny}` — elicit==null fallback taken (§6). */
export function elicitUnsupportedFallback(mode: ElicitFallback): ElicitFallbackNote {
  return `elicit_unsupported_fallback:${mode}`;
}
