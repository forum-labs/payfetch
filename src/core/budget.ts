/**
 * P3′ payfetch — budget accounting: reserve → settle/release, holds, auto-deny
 * (SPEC §5.1, §5.2, §5.4). The money-safety core: nothing is ever paid outside a
 * reservation, and no ambiguity releases a hold early.
 *
 * Purpose: an in-memory view over the rebuildable `State` (§8.2) that performs
 * the ONE atomic reservation covering all applicable caps, tracks live holds
 * whose authorizations exist in the wild until `validBeforeTs`, sweeps expired
 * holds lazily, and runs the per-host auto-deny circuit breaker. All mutations
 * persist through the injected `Ledger` (state.json + adjust records).
 *
 * Invariants (SPEC §5, §0):
 *  - `reserve()` is check-and-hold across {daily, perHostDaily, total?} (+ any
 *    guard sub-budget) in ONE step; on failure it names WHICH cap blocked and
 *    holds nothing.
 *  - Budgets OVER-count, never under-count: a live hold counts against every cap
 *    it touches until it settles or expires.
 *  - `release()` is called ONLY for the §5.2 "provably unspendable" case (a
 *    signature that was never built). Expiry sweep releases ONLY holds past
 *    `validBeforeTs + HOLD_RELEASE_MARGIN_S`. **No path releases a hold while its
 *    authorization is still temporally valid** (test-asserted).
 *  - Money comparisons run in integer micro-USD (atomic USDC precision) so cap
 *    boundaries are exact — no floating-point drift at "$1.99 + $0.02 > $2.00".
 */

import {
  APPROVAL_QUEUE_TTL_S,
  HOLD_RELEASE_MARGIN_S,
  PAYMENT_VALIDITY_MAX_S,
} from "./constants.js";
import {
  Ledger,
  TOTAL_KEY,
  applyStrike,
  dayKey,
  hostDayKey,
  isHostAutoDenied,
  utcDate,
  type ApprovalGrant,
  type Hold,
  type State,
  type StrikeClass,
} from "./ledger.js";

/** Integer micro-USD (USDC-atomic precision) for exact cap arithmetic. */
function micro(usd: number): number {
  return Math.round(usd * 1_000_000);
}

/** Effective caps for one reservation (from policy.caps; SPEC §4.1/§5.1). */
export type ReserveCaps = {
  dailyUsd: number;
  perHostDailyUsd: number;
  totalUsd: number | null;
};

/** An extra sub-budget a reservation must also fit (guard budget; SPEC §7.2). */
export type ExtraCap = { key: string; cap: number; which: string };

export type ReserveRequest = {
  holdId: string; // === receiptId (SPEC §5.1 hold identity)
  amountUsd: number;
  host: string;
  caps: ReserveCaps;
  extra?: ExtraCap[];
};

export type ReserveResult =
  | { ok: true; holdId: string }
  | { ok: false; which: string };

export type RemainingBudgets = {
  dayRemainingUsd: number;
  hostRemainingUsd: number;
  totalRemainingUsd: number | null;
};

/**
 * Mutable budget view over `State`. Every mutation persists via `Ledger`.
 * Sweeping expired holds is the caller's first act before reserving or reading
 * status (SPEC §5.2 lazy sweep).
 */
export class Budget {
  readonly #state: State;
  readonly #ledger: Ledger;
  readonly #now: () => number;

  constructor(state: State, ledger: Ledger, now: () => number) {
    this.#state = state;
    this.#ledger = ledger;
    this.#now = now;
  }

  get state(): State {
    return this.#state;
  }

  private persist(): void {
    this.#ledger.saveState(this.#state);
  }

  // --- counter reads (micro-USD) ----------------------------------------

  private spentMicro(key: string): number {
    return micro(this.#state.counters[key] ?? 0);
  }
  private heldMicro(key: string): number {
    let sum = 0;
    for (const h of this.#state.holds) {
      if (h.counterKeys.includes(key)) sum += micro(h.amountUsd);
    }
    return sum;
  }
  private usedMicro(key: string): number {
    return this.spentMicro(key) + this.heldMicro(key);
  }

  /** Remaining USD for each applicable cap (SPEC §8.3 receipt.budgets). */
  remaining(caps: ReserveCaps, host: string): RemainingBudgets {
    const d = utcDate(this.#now());
    const dayRem = (micro(caps.dailyUsd) - this.usedMicro(dayKey(d))) / 1_000_000;
    const hostRem =
      (micro(caps.perHostDailyUsd) - this.usedMicro(hostDayKey(host, d))) / 1_000_000;
    const totalRem =
      caps.totalUsd == null
        ? null
        : (micro(caps.totalUsd) - this.usedMicro(TOTAL_KEY)) / 1_000_000;
    return {
      dayRemainingUsd: dayRem,
      hostRemainingUsd: hostRem,
      totalRemainingUsd: totalRem,
    };
  }

  // --- expiry sweep (SPEC §5.2) -----------------------------------------

  /**
   * Sweep every hold past `validBeforeTs + HOLD_RELEASE_MARGIN_S` (SPEC §5.2/§8.3),
   * removing it from the live set. A hold's disposition depends on whether a real
   * signature was ever built for it:
   *  - SIGNED (or legacy/undefined ⇒ assume signed) → SETTLE as spend (fix M2): a
   *    malicious seller can take the signed EIP-3009 authorization, settle it
   *    on-chain, and return no PAYMENT-RESPONSE; the hold reaches expiry in "keep"
   *    state but the money may have moved. Counting it (over-count) is the only
   *    safe direction — SPEC §0/§5.2 "budgets over-count, never under-count; no
   *    path forgets money that moved".
   *  - UNSIGNED (`signed === false`) → RELEASE with no spend (a reserve that never
   *    reached buildPayment — provably no authorization exists).
   * Returns ALL removed hold ids (settled + released). Never touches a hold whose
   * authorization is still temporally valid.
   */
  sweepExpired(): string[] {
    const now = this.#now();
    const swept: string[] = [];
    const kept: Hold[] = [];
    for (const h of this.#state.holds) {
      const expireAtMs = (h.validBeforeTs + HOLD_RELEASE_MARGIN_S) * 1000;
      if (now < expireAtMs) {
        kept.push(h); // authorization still temporally valid — money may still move
        continue;
      }
      swept.push(h.holdId);
      if (h.signed !== false) {
        // SIGNED (true) or legacy/undefined (assume signed — the safe over-count
        // direction; only an explicit `signed === false` is a known-unsigned,
        // reserve-before-buildPayment orphan). A signature is in the wild and may
        // have moved money on-chain even though we never observed settlement, so
        // count it as SPEND — SPEC §0/§5.2 (over-count, never under-count; no path
        // forgets money that moved). NOTE: NO auto-deny strike here — the strike
        // already happened at classification time; settling on expiry must not
        // double-strike.
        for (const k of h.counterKeys) {
          this.#state.counters[k] = (this.#state.counters[k] ?? 0) + h.amountUsd;
        }
        this.#ledger.appendAdjust({
          schema: "p3f.adjust.v1",
          receiptId: h.holdId,
          ts: now,
          kind: "hold_settled_expiry",
          detail: { amountUsd: h.amountUsd, host: h.host, validBeforeTs: h.validBeforeTs },
        });
      } else {
        // UNSIGNED: no signature was ever built — release, incrementing nothing.
        this.#ledger.appendAdjust({
          schema: "p3f.adjust.v1",
          receiptId: h.holdId,
          ts: now,
          kind: "hold_released_expiry",
          detail: { amountUsd: h.amountUsd, host: h.host, validBeforeTs: h.validBeforeTs },
        });
      }
    }
    if (swept.length > 0) {
      this.#state.holds = kept;
      this.persist();
    }
    return swept;
  }

  // --- reserve / settle / release (SPEC §5.1, §5.2) ---------------------

  /**
   * ONE atomic check-and-hold across all applicable caps (SPEC §5.1). On success
   * a hold is appended with a PROVISIONAL `validBeforeTs` (the true value is set
   * from the signature via `setHoldValidBefore` after `buildPayment`). On failure
   * nothing is held and the blocking cap is named.
   */
  reserve(req: ReserveRequest): ReserveResult {
    const now = this.#now();
    const d = utcDate(now);
    const amt = micro(req.amountUsd);

    const checks: { key: string; capMicro: number; which: string }[] = [
      { key: dayKey(d), capMicro: micro(req.caps.dailyUsd), which: "day" },
      { key: hostDayKey(req.host, d), capMicro: micro(req.caps.perHostDailyUsd), which: "host" },
    ];
    if (req.caps.totalUsd != null) {
      checks.push({ key: TOTAL_KEY, capMicro: micro(req.caps.totalUsd), which: "total" });
    }
    for (const e of req.extra ?? []) {
      checks.push({ key: e.key, capMicro: micro(e.cap), which: e.which });
    }

    for (const c of checks) {
      if (this.usedMicro(c.key) + amt > c.capMicro) {
        return { ok: false, which: c.which };
      }
    }

    const counterKeys = [
      dayKey(d),
      hostDayKey(req.host, d),
      TOTAL_KEY,
      ...(req.extra ?? []).map((e) => e.key),
    ];
    this.#state.holds.push({
      holdId: req.holdId,
      amountUsd: req.amountUsd,
      host: req.host,
      validBeforeTs: Math.floor(now / 1000) + PAYMENT_VALIDITY_MAX_S, // provisional upper bound
      createdTs: now,
      counterKeys,
      signed: false, // no signature yet — reserve PRECEDES buildPayment (fix M2, §5.2)
    });
    this.persist();
    return { ok: true, holdId: req.holdId };
  }

  /**
   * Pin a hold's real authorization window after `buildPayment` (SPEC §5.2) AND
   * mark the hold SIGNED. Called exactly once, immediately after buildPayment
   * succeeds — a real EIP-3009 authorization now exists, so if this hold later
   * expires unobserved it is SETTLED (counted as spend), not released (fix M2).
   */
  setHoldValidBefore(holdId: string, validBeforeTs: number): void {
    const h = this.#state.holds.find((x) => x.holdId === holdId);
    if (h) {
      h.validBeforeTs = validBeforeTs;
      h.signed = true; // a signature now exists (fix M2, §5.2)
      this.persist();
    }
  }

  /** Convert a hold to spend (SPEC §5.2 settle; reconciled to `actualUsd`). */
  settle(holdId: string, actualUsd: number): void {
    const h = this.#state.holds.find((x) => x.holdId === holdId);
    if (!h) return;
    for (const k of h.counterKeys) {
      this.#state.counters[k] = (this.#state.counters[k] ?? 0) + actualUsd;
    }
    this.#state.holds = this.#state.holds.filter((x) => x.holdId !== holdId);
    this.persist();
  }

  /**
   * Remove a hold WITHOUT spending — ONLY the §5.2 "provably unspendable" case
   * (a signature that was never built). Never call while an authorization exists.
   */
  release(holdId: string): void {
    const before = this.#state.holds.length;
    this.#state.holds = this.#state.holds.filter((x) => x.holdId !== holdId);
    if (this.#state.holds.length !== before) this.persist();
  }

  getHold(holdId: string): Hold | undefined {
    return this.#state.holds.find((x) => x.holdId === holdId);
  }

  // --- auto-deny circuit breaker (SPEC §5.4) ----------------------------

  isAutoDenied(host: string): boolean {
    return isHostAutoDenied(this.#state.autoDeny, host, this.#now());
  }

  /**
   * Record a strike and (re)evaluate the breaker. When it engages, append an
   * `autodeny_set` adjust (SPEC §5.4/§8.3). Returns {strikeCount, engaged}.
   */
  recordStrike(host: string, cls: StrikeClass): { strikeCount: number; engaged: boolean } {
    const res = applyStrike(this.#state.autoDeny, host, this.#now(), cls);
    if (res.engaged) {
      this.#ledger.appendAdjust({
        schema: "p3f.adjust.v1",
        receiptId: host, // adjust references the host (no receiptId for a breaker event)
        ts: this.#now(),
        kind: "autodeny_set",
        detail: {
          host,
          strikeCount: res.strikeCount,
          deniedUntilTs: this.#state.autoDeny[host]?.deniedUntilTs ?? null,
        },
      });
    }
    this.persist();
    return res;
  }

  /** Operator clear (SPEC §5.4) — NOT reachable from any MCP tool. */
  clearAutoDeny(host: string): boolean {
    if (!(host in this.#state.autoDeny)) return false;
    delete this.#state.autoDeny[host];
    this.#ledger.appendAdjust({
      schema: "p3f.adjust.v1",
      receiptId: host,
      ts: this.#now(),
      kind: "autodeny_cleared",
      detail: { host },
    });
    this.persist();
    return true;
  }

  autoDeniedHosts(): { host: string; untilTs: number }[] {
    const now = this.#now();
    const out: { host: string; untilTs: number }[] = [];
    for (const [host, e] of Object.entries(this.#state.autoDeny)) {
      if (e.deniedUntilTs != null && now < e.deniedUntilTs) {
        out.push({ host, untilTs: e.deniedUntilTs });
      }
    }
    return out;
  }

  // --- approval queue grants (SPEC §6) ----------------------------------

  /**
   * Find a live, GRANTED approval matching (host, exact amount) (SPEC §6). Prunes
   * expired grants as a side effect. TTL is APPROVAL_QUEUE_TTL_S from creation.
   */
  findGrant(host: string, amountUsd: number): ApprovalGrant | null {
    this.pruneExpiredApprovals();
    const amt = micro(amountUsd);
    return (
      this.#state.approvals.find(
        (g) =>
          g.status === "granted" && g.host === host && micro(g.amountUsd) === amt,
      ) ?? null
    );
  }

  consumeGrant(approvalId: string): void {
    this.#state.approvals = this.#state.approvals.filter((g) => g.approvalId !== approvalId);
    this.persist();
  }

  addPendingApproval(entry: Omit<ApprovalGrant, "status">): ApprovalGrant {
    const grant: ApprovalGrant = { ...entry, status: "pending" };
    this.#state.approvals.push(grant);
    this.persist();
    return grant;
  }

  listApprovals(): ApprovalGrant[] {
    this.pruneExpiredApprovals();
    return [...this.#state.approvals];
  }

  resolvePending(approvalId: string, approve: boolean): ApprovalGrant | null {
    this.pruneExpiredApprovals();
    const g = this.#state.approvals.find((x) => x.approvalId === approvalId);
    if (!g) return null;
    if (approve) {
      g.status = "granted";
    } else {
      this.#state.approvals = this.#state.approvals.filter((x) => x.approvalId !== approvalId);
    }
    this.persist();
    return g;
  }

  private pruneExpiredApprovals(): void {
    const cutoff = this.#now() - APPROVAL_QUEUE_TTL_S * 1000;
    const before = this.#state.approvals.length;
    this.#state.approvals = this.#state.approvals.filter((g) => g.createdTs >= cutoff);
    if (this.#state.approvals.length !== before) this.persist();
  }
}
