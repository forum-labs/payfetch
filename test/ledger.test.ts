/**
 * P3′ payfetch — ledger + state tests (SPEC §8, §14 "Ledger/state").
 *
 * Hermetic (in-memory fs): append-only enforcement (double-append throws);
 * fsync decision for payment-class records; state rebuild from generated receipt
 * sequences reproduces counters/holds; adjust records release the referenced
 * hold. PLUS a small REAL-fs integration test (node:fs mkdtemp) for lockfile
 * O_EXCL semantics + monthly rotation naming.
 */

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { realFs, type PayfetchFs } from "../src/core/fs.js";
import { integrityKeyPath, sidecarPath } from "../src/core/integrity.js";
import {
  Ledger,
  LedgerAppendConflictError,
  LedgerLockedError,
} from "../src/core/ledger.js";
import {
  fakeClock,
  inMemoryFs,
  makeQuote,
  makeReceipt,
  seededRandom,
  type InMemoryFs,
} from "./fakes.js";

const NOV = Date.UTC(2023, 10, 14, 12, 0, 0); // 2023-11-14

describe("Ledger.append — append-only + fsync (SPEC §8.1)", () => {
  it("refuses to re-append the same receiptId (append-only contract)", () => {
    const led = new Ledger(inMemoryFs(), "/d", () => NOV);
    const r = makeReceipt({ receiptId: "r-1", ts: NOV });
    led.append(r);
    expect(() => led.append(makeReceipt({ receiptId: "r-1", ts: NOV }))).toThrow(
      LedgerAppendConflictError,
    );
  });

  it("fsyncs payment-class records and holds, not free receipts", () => {
    const flags: { outcome: string; fsync: boolean }[] = [];
    const base = inMemoryFs();
    const spy: PayfetchFs = {
      ...base,
      appendLine(p, line, opts) {
        flags.push({ outcome: JSON.parse(line).outcome, fsync: opts.fsync });
        base.appendLine(p, line, opts);
      },
    };
    const led = new Ledger(spy, "/d", () => NOV);
    led.append(makeReceipt({ receiptId: "a", outcome: "free" }));
    led.append(makeReceipt({ receiptId: "b", outcome: "paid_delivered", payment: pay() }));
    led.append(makeReceipt({ receiptId: "c", outcome: "payment_rejected", payment: pay() }));
    led.append(makeReceipt({ receiptId: "d", outcome: "policy_denied" }));
    expect(flags.find((f) => f.outcome === "free")!.fsync).toBe(false);
    expect(flags.find((f) => f.outcome === "paid_delivered")!.fsync).toBe(true);
    expect(flags.find((f) => f.outcome === "payment_rejected")!.fsync).toBe(true);
    expect(flags.find((f) => f.outcome === "policy_denied")!.fsync).toBe(false);
  });
});

function pay(over: Record<string, unknown> = {}) {
  return {
    payerAddress: "0x00000000000000000000000000000000000000a1",
    nonce: "0xabc",
    validBeforeTs: Math.floor(NOV / 1000) + 300,
    settledAmountUsd: null,
    txRef: null,
    settlementConfirmed: false,
    ...over,
  };
}

describe("Ledger.rebuildState — reproduce counters/holds (SPEC §8.2, property-style)", () => {
  const seqs: { name: string; receipts: ReturnType<typeof makeReceipt>[] }[] = [
    {
      name: "two settled + one kept",
      receipts: [
        makeReceipt({ receiptId: "s1", ts: NOV, host: "a.com", outcome: "paid_delivered",
          quote: makeQuote(0.02), payment: pay({ settledAmountUsd: 0.02 }) }),
        makeReceipt({ receiptId: "s2", ts: NOV + 1000, host: "a.com", outcome: "paid_delivered",
          quote: makeQuote(0.03), payment: pay({ settledAmountUsd: 0.03 }) }),
        makeReceipt({ receiptId: "k1", ts: NOV + 2000, host: "b.com", outcome: "payment_rejected",
          quote: makeQuote(0.5), payment: pay() }),
      ],
    },
    {
      name: "unknown-settlement kept + delivered on two hosts",
      receipts: [
        makeReceipt({ receiptId: "u1", ts: NOV, host: "c.com", outcome: "unknown_settlement",
          quote: makeQuote(0.1), payment: pay() }),
        makeReceipt({ receiptId: "d1", ts: NOV + 1000, host: "d.com", outcome: "paid_delivered",
          quote: makeQuote(0.07), payment: pay({ settledAmountUsd: 0.07 }) }),
      ],
    },
  ];

  for (const seq of seqs) {
    it(`rebuild reproduces counters + holds: ${seq.name}`, () => {
      const fs = inMemoryFs();
      const led = new Ledger(fs, "/d", () => NOV);
      for (const r of seq.receipts) led.append(r);

      const rebuilt = new Ledger(fs, "/d", () => NOV).rebuildState("f".repeat(32));

      // Expected settled total and per-host, and expected live holds.
      let settledTotal = 0;
      const perHost: Record<string, number> = {};
      const expectedHolds: string[] = [];
      for (const r of seq.receipts) {
        if (r.outcome === "paid_delivered" || r.outcome === "paid_not_delivered") {
          const amt = r.payment!.settledAmountUsd ?? r.quote!.amountUsd;
          settledTotal += amt;
          perHost[r.host] = (perHost[r.host] ?? 0) + amt;
        } else if (["payment_rejected", "unknown_settlement", "fetch_error"].includes(r.outcome)) {
          expectedHolds.push(r.receiptId);
        }
      }
      expect(rebuilt.counters["total"] ?? 0).toBeCloseTo(settledTotal, 9);
      expect(rebuilt.counters["day:2023-11-14"] ?? 0).toBeCloseTo(settledTotal, 9);
      for (const [h, amt] of Object.entries(perHost)) {
        expect(rebuilt.counters[`host:${h}:2023-11-14`] ?? 0).toBeCloseTo(amt, 9);
      }
      expect(rebuilt.holds.map((h) => h.holdId).sort()).toEqual(expectedHolds.sort());
    });
  }

  it("a hold_released_expiry adjust removes the referenced hold — and credits nothing — on rebuild", () => {
    const fs = inMemoryFs();
    const led = new Ledger(fs, "/d", () => NOV);
    led.append(makeReceipt({ receiptId: "k1", ts: NOV, host: "b.com", outcome: "payment_rejected",
      quote: makeQuote(0.5), payment: pay() }));
    led.appendAdjust({
      schema: "p3f.adjust.v1",
      receiptId: "k1",
      ts: NOV + 5000,
      kind: "hold_released_expiry",
      detail: {},
    });
    const rebuilt = new Ledger(fs, "/d", () => NOV).rebuildState("f".repeat(32));
    expect(rebuilt.holds).toHaveLength(0);
    expect(rebuilt.counters["total"] ?? 0).toBe(0); // released → no spend
  });

  it("a hold_settled_expiry adjust credits counters + leaves no live hold on rebuild (fix M2)", () => {
    const fs = inMemoryFs();
    const led = new Ledger(fs, "/d", () => NOV);
    // A hold-kept receipt (signature was in the wild) whose signed hold later
    // expired unobserved and was SETTLED on expiry (SPEC §5.2/§0 over-count).
    led.append(makeReceipt({ receiptId: "k1", ts: NOV, host: "b.com", outcome: "payment_rejected",
      quote: makeQuote(0.5), payment: pay() }));
    led.appendAdjust({
      schema: "p3f.adjust.v1",
      receiptId: "k1",
      ts: NOV + 5000,
      kind: "hold_settled_expiry",
      detail: { amountUsd: 0.5, host: "b.com", validBeforeTs: Math.floor(NOV / 1000) + 300 },
    });
    const rebuilt = new Ledger(fs, "/d", () => NOV).rebuildState("f".repeat(32));
    // Credited as spend; NO live hold re-created (would double-count if it were).
    expect(rebuilt.holds).toHaveLength(0);
    expect(rebuilt.counters["total"] ?? 0).toBeCloseTo(0.5, 9);
    expect(rebuilt.counters["day:2023-11-14"] ?? 0).toBeCloseTo(0.5, 9);
    expect(rebuilt.counters["host:b.com:2023-11-14"] ?? 0).toBeCloseTo(0.5, 9);
  });
});

// ---------------------------------------------------------------------------
// L14 tamper-evidence sidecar (SPEC §8/§14) — hermetic (fake fs + injected random)
// ---------------------------------------------------------------------------

describe("Ledger.verifyIntegrity — keyed hash-chain sidecar (fix L14)", () => {
  const mkLedger = (): { fs: InMemoryFs; led: Ledger } => {
    const fs = inMemoryFs();
    const led = new Ledger(fs, "/d", () => NOV, { random: seededRandom(7).random });
    return { fs, led };
  };

  const seed = (led: Ledger): void => {
    led.append(makeReceipt({ receiptId: "r-1", ts: NOV, host: "a.com", outcome: "paid_delivered",
      quote: makeQuote(0.02), payment: pay({ settledAmountUsd: 0.02 }) }));
    led.append(makeReceipt({ receiptId: "r-2", ts: NOV + 1000, host: "b.com", outcome: "payment_rejected",
      quote: makeQuote(0.5), payment: pay() }));
    led.appendAdjust({ schema: "p3f.adjust.v1", receiptId: "r-2", ts: NOV + 2000,
      kind: "hold_released_expiry", detail: {} });
  };

  const jsonlPath = (fs: InMemoryFs): string => {
    for (const p of fs.files.keys()) if (p.endsWith(".jsonl")) return p;
    throw new Error("no ledger .jsonl file in fake fs");
  };
  const nonEmptyLines = (fs: InMemoryFs, path: string): string[] =>
    (fs.readText(path) ?? "").split("\n").filter((l) => l.trim().length > 0);

  it("verifies ok:true after a run of receipts + adjusts, and mints a key file", () => {
    const { fs, led } = mkLedger();
    seed(led);
    const report = led.verifyIntegrity();
    expect(report.ok).toBe(true);
    expect(report.months).toHaveLength(1);
    expect(report.months[0].checked).toBe(3); // 2 receipts + 1 adjust
    expect(report.months[0].issues).toEqual([]);
    expect(fs.files.has(integrityKeyPath("/d"))).toBe(true);
  });

  it("tampering one JSONL line (valid JSON, changed bytes) → ok:false naming that receiptId/seq", () => {
    const { fs, led } = mkLedger();
    seed(led);
    const path = jsonlPath(fs);
    const lines = nonEmptyLines(fs, path);
    const first = JSON.parse(lines[0]) as { receiptId: string; host: string };
    expect(first.receiptId).toBe("r-1");
    first.host = "evil.com"; // different-but-valid JSON, same receiptId
    lines[0] = JSON.stringify(first);
    fs.writeText(path, `${lines.join("\n")}\n`);

    const report = led.verifyIntegrity();
    expect(report.ok).toBe(false);
    expect(report.months[0].issues.some((s) => s.includes("r-1"))).toBe(true);
    // Localized: only the tampered line (seq 0) reports — later lines still verify.
    expect(report.months[0].issues.every((s) => s.includes("seq 0"))).toBe(true);
  });

  it("deleting a sidecar record → ok:false (missing sidecar record)", () => {
    const { fs, led } = mkLedger();
    seed(led);
    const sc = sidecarPath(jsonlPath(fs));
    const recs = nonEmptyLines(fs, sc);
    fs.writeText(sc, `${recs.slice(0, -1).join("\n")}\n`); // drop the last record

    const report = led.verifyIntegrity();
    expect(report.ok).toBe(false);
    expect(report.months[0].issues.some((s) => /missing sidecar record/.test(s))).toBe(true);
  });

  it("deleting a JSONL line → ok:false (broken chain / extra sidecar record)", () => {
    const { fs, led } = mkLedger();
    seed(led);
    const path = jsonlPath(fs);
    const lines = nonEmptyLines(fs, path);
    fs.writeText(path, `${[lines[0], lines[2]].join("\n")}\n`); // drop the middle line
    expect(led.verifyIntegrity().ok).toBe(false);
  });

  it("mints the key lazily on first append (fake fs ignores mode) and verifies clean", () => {
    const { fs, led } = mkLedger();
    expect(fs.files.has(integrityKeyPath("/d"))).toBe(false);
    led.append(makeReceipt({ receiptId: "r-1", ts: NOV, outcome: "free" }));
    expect(fs.files.has(integrityKeyPath("/d"))).toBe(true);
    expect(led.verifyIntegrity().ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Real-fs integration (mkdtemp): lockfile O_EXCL + rotation naming
// ---------------------------------------------------------------------------

describe("Ledger — real-fs lockfile + rotation (SPEC §8.1)", () => {
  const dirs: string[] = [];
  const mkdir = (): string => {
    const d = mkdtempSync(join(tmpdir(), "payfetch-ledger-"));
    dirs.push(d);
    return d;
  };
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("a second live instance refuses (O_EXCL), and a stale lock is taken over", () => {
    const dir = mkdir();
    const t0 = Date.now();
    const l1 = new Ledger(realFs, dir, () => t0, { isPidAlive: () => true });
    l1.acquireLock(1234);
    // Second live instance (fresh lock, pid alive) → refuse.
    const l2 = new Ledger(realFs, dir, () => t0, { isPidAlive: () => true });
    expect(() => l2.acquireLock(5678)).toThrow(LedgerLockedError);
    // A much later instance sees a stale lock (age > LOCK_STALE_S) → takes over.
    const l3 = new Ledger(realFs, dir, () => t0 + 400_000, { isPidAlive: () => true });
    expect(() => l3.acquireLock(9999)).not.toThrow();
    l3.releaseLock();
  });

  it("rotates ledger files by yyyy-mm filename", () => {
    const dir = mkdir();
    const led = new Ledger(realFs, dir, () => NOV);
    led.append(makeReceipt({ receiptId: "nov", ts: Date.UTC(2023, 10, 5), outcome: "free" }));
    led.append(makeReceipt({ receiptId: "dec", ts: Date.UTC(2023, 11, 5), outcome: "free" }));
    // JSONL files rotate by month; the L14 integrity sidecars (`*.jsonl.integrity`)
    // live alongside them and are excluded here (the ledger money-format is the
    // set of `.jsonl` files).
    const files = readdirSync(join(dir, "ledger"))
      .filter((f) => f.endsWith(".jsonl"))
      .sort();
    expect(files).toEqual(["2023-11.jsonl", "2023-12.jsonl"]);
  });
});
