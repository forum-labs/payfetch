/**
 * P3′ payfetch — budget tests (SPEC §5.1, §5.2, §5.4, §14 money-path cases).
 *
 * Covers: atomic reserve naming the blocking cap; exact micro-USD boundary math
 * ($1.99 + $0.02 → exhausted:day; at-cap passes, cap+ε denies); holds over-count
 * (a hold blocks a marginal reservation); settle/release; the hold-never-released-
 * early invariant + lazy expiry sweep; the §5.4 auto-deny class matrix; queue
 * approval grant match / TTL / drift.
 */

import { describe, expect, it } from "vitest";

import { AUTO_DENY_WINDOW_DAYS, HOLD_RELEASE_MARGIN_S } from "../src/core/constants.js";
import { Budget } from "../src/core/budget.js";
import { Ledger, type Adjust, type State } from "../src/core/ledger.js";
import { fakeClock, inMemoryFs, type InMemoryFs } from "./fakes.js";

const DAY_MS = 86_400_000;
const NOV = Date.UTC(2023, 10, 14, 0, 0, 0);

function emptyState(): State {
  return {
    schema: "p3f.state.v1",
    installId: "0".repeat(32),
    counters: {},
    holds: [],
    autoDeny: {},
    approvals: [],
  };
}

function mkBudget(now: () => number, state = emptyState()): { budget: Budget; state: State } {
  const ledger = new Ledger(inMemoryFs(), "/d", now);
  return { budget: new Budget(state, ledger, now), state };
}

/** Like `mkBudget`, but also exposes the fake fs so tests can read adjust records. */
function mkBudgetFs(
  now: () => number,
  state = emptyState(),
): { budget: Budget; state: State; fs: InMemoryFs } {
  const fs = inMemoryFs();
  const ledger = new Ledger(fs, "/d", now);
  return { budget: new Budget(state, ledger, now), state, fs };
}

/** All `p3f.adjust.v1` records written to the ledger `.jsonl` files (not sidecars). */
function adjustsIn(fs: InMemoryFs): Adjust[] {
  const out: Adjust[] = [];
  for (const [path, val] of fs.files) {
    if (!path.endsWith(".jsonl")) continue; // skip `*.jsonl.integrity` sidecars
    const text = typeof val === "string" ? val : "";
    for (const line of text.split("\n")) {
      const s = line.trim();
      if (s.length === 0) continue;
      try {
        const o = JSON.parse(s) as { schema?: string };
        if (o.schema === "p3f.adjust.v1") out.push(o as Adjust);
      } catch {
        /* skip */
      }
    }
  }
  return out;
}

const CAPS = { dailyUsd: 2.0, perHostDailyUsd: 1.0, totalUsd: null };

describe("Budget.reserve — atomic check-and-hold, boundary math (SPEC §5.1)", () => {
  it("$1.99 spent + $0.02 quote at $2.00 daily cap → budget_exhausted:day", () => {
    const s = emptyState();
    s.counters["day:2023-11-14"] = 1.99;
    const { budget } = mkBudget(() => NOV, s);
    const r = budget.reserve({ holdId: "h1", amountUsd: 0.02, host: "a.com", caps: CAPS });
    expect(r).toEqual({ ok: false, which: "day" });
  });

  it("a reservation exactly AT the cap passes; cap + ε denies", () => {
    const s = emptyState();
    s.counters["day:2023-11-14"] = 1.98;
    const { budget } = mkBudget(() => NOV, s);
    expect(budget.reserve({ holdId: "h1", amountUsd: 0.02, host: "a.com", caps: CAPS }).ok).toBe(true);
    // now day used = 1.98 spent + 0.02 held = 2.00; another ε denies on day
    const r2 = budget.reserve({ holdId: "h2", amountUsd: 0.000001, host: "z.com", caps: CAPS });
    expect(r2).toEqual({ ok: false, which: "day" });
  });

  it("names the per-host cap when the host ceiling binds first", () => {
    const { budget } = mkBudget(() => NOV);
    const r = budget.reserve({ holdId: "h1", amountUsd: 1.5, host: "a.com", caps: CAPS });
    expect(r).toEqual({ ok: false, which: "host" }); // 1.5 > perHostDaily 1.0
  });

  it("a live HOLD over-counts: it blocks a marginal reservation (SPEC §5.2/§0)", () => {
    const { budget } = mkBudget(() => NOV);
    expect(budget.reserve({ holdId: "h1", amountUsd: 0.6, host: "a.com", caps: CAPS }).ok).toBe(true);
    // host cap 1.0; 0.6 held + 0.5 would exceed → denied even though nothing SPENT yet
    const r2 = budget.reserve({ holdId: "h2", amountUsd: 0.5, host: "a.com", caps: CAPS });
    expect(r2).toEqual({ ok: false, which: "host" });
  });

  it("enforces the total (lifetime) cap when set", () => {
    const { budget } = mkBudget(() => NOV);
    const caps = { dailyUsd: 100, perHostDailyUsd: 100, totalUsd: 0.05 };
    expect(budget.reserve({ holdId: "h1", amountUsd: 0.05, host: "a.com", caps }).ok).toBe(true);
    expect(budget.reserve({ holdId: "h2", amountUsd: 0.01, host: "b.com", caps })).toEqual({
      ok: false,
      which: "total",
    });
  });
});

describe("Budget.settle / release (SPEC §5.2)", () => {
  it("settle moves a hold to spend (reconciled to actual)", () => {
    const { budget, state } = mkBudget(() => NOV);
    budget.reserve({ holdId: "h1", amountUsd: 0.1, host: "a.com", caps: CAPS });
    budget.settle("h1", 0.08); // reconcile down
    expect(state.holds).toHaveLength(0);
    expect(state.counters["total"]).toBeCloseTo(0.08, 9);
    expect(state.counters["day:2023-11-14"]).toBeCloseTo(0.08, 9);
  });

  it("release removes a hold without spending (provably-unspendable only)", () => {
    const { budget, state } = mkBudget(() => NOV);
    budget.reserve({ holdId: "h1", amountUsd: 0.1, host: "a.com", caps: CAPS });
    budget.release("h1");
    expect(state.holds).toHaveLength(0);
    expect(state.counters["total"] ?? 0).toBe(0);
  });
});

describe("Budget.sweepExpired — hold never released early (SPEC §5.2 invariant)", () => {
  it("keeps a hold whose authorization is still temporally valid; releases only past margin", () => {
    const clock = fakeClock(NOV);
    const { budget, state } = mkBudget(clock.now);
    budget.reserve({ holdId: "h1", amountUsd: 0.1, host: "a.com", caps: CAPS });
    const validBeforeTs = Math.floor(NOV / 1000) + 300;
    budget.setHoldValidBefore("h1", validBeforeTs);

    // Just BEFORE validBefore + margin → must NOT release (money in motion).
    clock.set((validBeforeTs + HOLD_RELEASE_MARGIN_S) * 1000 - 1);
    expect(budget.sweepExpired()).toEqual([]);
    expect(state.holds).toHaveLength(1);

    // AT/after validBefore + margin → swept (settled, since it was signed).
    clock.set((validBeforeTs + HOLD_RELEASE_MARGIN_S) * 1000);
    expect(budget.sweepExpired()).toEqual(["h1"]);
    expect(state.holds).toHaveLength(0);
  });
});

describe("Budget.sweepExpired — signed vs unsigned expiry (fix M2, SPEC §5.2/§0)", () => {
  it("signed hold settles on expiry (over-count, not release)", () => {
    const clock = fakeClock(NOV);
    const { budget, state, fs } = mkBudgetFs(clock.now);
    budget.reserve({ holdId: "h1", amountUsd: 0.1, host: "a.com", caps: CAPS });
    // setHoldValidBefore marks the hold SIGNED — a real authorization now exists.
    const validBeforeTs = Math.floor(NOV / 1000) + 300;
    budget.setHoldValidBefore("h1", validBeforeTs);

    // Advance past validBefore + margin → the signed authorization expired unobserved.
    clock.set((validBeforeTs + HOLD_RELEASE_MARGIN_S) * 1000);
    expect(budget.sweepExpired()).toEqual(["h1"]);

    // Counted as SPEND across every counter the hold reserved (day/host/total).
    expect(state.counters["day:2023-11-14"]).toBeCloseTo(0.1, 9);
    expect(state.counters["host:a.com:2023-11-14"]).toBeCloseTo(0.1, 9);
    expect(state.counters["total"]).toBeCloseTo(0.1, 9);
    expect(state.holds).toHaveLength(0);

    // A `hold_settled_expiry` adjust was appended (NOT `hold_released_expiry`).
    const adjusts = adjustsIn(fs);
    const settled = adjusts.filter((a) => a.kind === "hold_settled_expiry");
    expect(settled).toHaveLength(1);
    expect(settled[0].receiptId).toBe("h1");
    expect(settled[0].detail).toMatchObject({ amountUsd: 0.1, host: "a.com" });
    expect(adjusts.some((a) => a.kind === "hold_released_expiry")).toBe(false);
  });

  it("unsigned hold releases on expiry (no spend)", () => {
    const clock = fakeClock(NOV);
    const { budget, state, fs } = mkBudgetFs(clock.now);
    // Reserve but never setHoldValidBefore → hold stays UNSIGNED (buildPayment never ran).
    budget.reserve({ holdId: "h1", amountUsd: 0.1, host: "a.com", caps: CAPS });

    // Advance well past even the provisional validBefore + margin.
    clock.set(NOV + 30 * DAY_MS);
    expect(budget.sweepExpired()).toEqual(["h1"]);

    // No spend recorded anywhere; the hold is gone.
    expect(state.counters["day:2023-11-14"] ?? 0).toBe(0);
    expect(state.counters["host:a.com:2023-11-14"] ?? 0).toBe(0);
    expect(state.counters["total"] ?? 0).toBe(0);
    expect(state.holds).toHaveLength(0);

    // A `hold_released_expiry` adjust was appended (NOT `hold_settled_expiry`).
    const adjusts = adjustsIn(fs);
    const released = adjusts.filter((a) => a.kind === "hold_released_expiry");
    expect(released).toHaveLength(1);
    expect(released[0].receiptId).toBe("h1");
    expect(adjusts.some((a) => a.kind === "hold_settled_expiry")).toBe(false);
  });
});

describe("Budget auto-deny — §5.4 class matrix", () => {
  const mk = () => {
    const clock = fakeClock(NOV);
    return { clock, ...mkBudget(clock.now) };
  };

  it("1 confirmed + 1 soft in-window → engaged", () => {
    const { budget } = mk();
    budget.recordStrike("a.com", "confirmed");
    budget.recordStrike("a.com", "soft");
    expect(budget.isAutoDenied("a.com")).toBe(true);
  });

  it("2 soft-only → NOT engaged", () => {
    const { budget } = mk();
    budget.recordStrike("a.com", "soft");
    budget.recordStrike("a.com", "soft");
    expect(budget.isAutoDenied("a.com")).toBe(false);
  });

  it("4 soft-only → engaged", () => {
    const { budget } = mk();
    for (let i = 0; i < 4; i++) budget.recordStrike("a.com", "soft");
    expect(budget.isAutoDenied("a.com")).toBe(true);
  });

  it("2 confirmed straddling the window → NOT engaged (old strike pruned)", () => {
    const { clock, budget } = mk();
    budget.recordStrike("a.com", "confirmed");
    clock.advance(AUTO_DENY_WINDOW_DAYS * DAY_MS + DAY_MS); // beyond the window
    budget.recordStrike("a.com", "confirmed");
    expect(budget.isAutoDenied("a.com")).toBe(false);
  });

  it("engaged deny expires after the TTL; operator clear removes it early", () => {
    const { clock, budget } = mk();
    budget.recordStrike("a.com", "confirmed");
    budget.recordStrike("a.com", "confirmed");
    expect(budget.isAutoDenied("a.com")).toBe(true);
    clock.advance(8 * DAY_MS); // past AUTO_DENY_TTL_DAYS (7)
    expect(budget.isAutoDenied("a.com")).toBe(false);

    // Re-engage then operator-clear.
    clock.advance(DAY_MS);
    budget.recordStrike("a.com", "confirmed");
    budget.recordStrike("a.com", "confirmed");
    expect(budget.isAutoDenied("a.com")).toBe(true);
    expect(budget.clearAutoDeny("a.com")).toBe(true);
    expect(budget.isAutoDenied("a.com")).toBe(false);
  });
});

describe("Budget approval grants — queue mode (SPEC §6)", () => {
  it("grant matches exact (host, amount); drift → no match; TTL expiry → no match", () => {
    const clock = fakeClock(NOV);
    const { budget } = mkBudget(clock.now);
    const g = budget.addPendingApproval({
      approvalId: "ap1",
      host: "a.com",
      amountUsd: 0.3,
      createdTs: clock.now(),
      resource: null,
    });
    budget.resolvePending(g.approvalId, true); // operator approves → granted
    expect(budget.findGrant("a.com", 0.3)?.approvalId).toBe("ap1"); // exact match
    expect(budget.findGrant("a.com", 0.31)).toBeNull(); // drift → re-approval
    expect(budget.findGrant("b.com", 0.3)).toBeNull(); // host mismatch

    // Consume then expire.
    budget.consumeGrant("ap1");
    expect(budget.findGrant("a.com", 0.3)).toBeNull();
  });

  it("a grant past APPROVAL_QUEUE_TTL_S no longer matches", () => {
    const clock = fakeClock(NOV);
    const { budget } = mkBudget(clock.now);
    const g = budget.addPendingApproval({
      approvalId: "ap2",
      host: "a.com",
      amountUsd: 0.3,
      createdTs: clock.now(),
      resource: null,
    });
    budget.resolvePending(g.approvalId, true);
    clock.advance(3_600_000 + 1000); // > APPROVAL_QUEUE_TTL_S
    expect(budget.findGrant("a.com", 0.3)).toBeNull();
  });
});
