/**
 * P3′ payfetch — append-only receipts ledger + rebuildable state cache (SPEC §8).
 *
 * Purpose: the operator's local, immutable audit trail. Every paying-fetch
 * outcome (attempted, denied, unknown, free) lands as ONE JSONL line in
 * `{dataDir}/ledger/{yyyy-mm}.jsonl`; corrections/releases append `p3f.adjust.v1`
 * records referencing the original `receiptId` (SPEC §8.1 — nothing is ever
 * rewritten). `{dataDir}/state.json` is a DISPOSABLE cache (counters/holds/
 * auto-deny/approvals/installId) reconstructible from the ledger.
 *
 * Invariants:
 *  - Append-only, enforced (SPEC §8/§14): appending a receipt whose `receiptId`
 *    was already written throws — the writer's contract, under test with both the
 *    real and in-memory fs.
 *  - `fsync` after every payment-class record and every adjust (SPEC §8.1); also
 *    after any receipt carrying a hold (`payment != null`) so a crash can never
 *    silently drop money-in-motion (degrade toward over-counting, SPEC §0/§13).
 *  - Single-writer: `{dataDir}/lock` is an O_EXCL lockfile carrying `{pid, ts}`;
 *    a second LIVE instance refuses to start; a STALE lock (age > LOCK_STALE_S, or
 *    a dead pid) is taken over (SPEC §8.1). The lock ts is refreshed on writes so
 *    an active long-lived instance is never mistaken for stale.
 *  - Rotation is by filename (monthly); `readEntries` scans the current + previous
 *    month for state rebuild (SPEC §8.2). Rebuild reproduces counters/holds/
 *    auto-deny from the receipt stream; the approval queue is NOT ledger-derived
 *    (grants aren't ledger events) and resets on corruption — the safe direction
 *    (lost grant ⇒ re-approval required).
 */

import { join } from "node:path";

import {
  AUTO_DENY_STRIKES,
  AUTO_DENY_TTL_DAYS,
  AUTO_DENY_UNKNOWN_ONLY_STRIKES,
  AUTO_DENY_WINDOW_DAYS,
  LOCK_STALE_S,
} from "./constants.js";
import type { PayfetchFs } from "./fs.js";
import {
  defaultRandom,
  genesisMac,
  lineHash,
  loadOrCreateKey,
  nextMac,
  readSidecarRecords,
  sidecarPath,
  verifyMonth,
  type MonthIntegrity,
} from "./integrity.js";
import type { PaymentQuote } from "../payer/types.js";
import type { GuardResult } from "../guards/types.js";

// ---------------------------------------------------------------------------
// Receipt / Adjust schemas (SPEC §8.3 — verbatim)
// ---------------------------------------------------------------------------

/**
 * Why a `guard_blocked` outcome fired (P3 review §3 — block legibility). Lets the
 * agent tell a RETRYABLE fail-close from a genuinely dangerous host:
 *  - `danger`      → a real verdict-block (P1 `danger` token / `serial_rugger`
 *                    deployer, or a P2 `unreliable` enforce block). Do NOT retry.
 *  - `degraded`    → an enforce degraded-screen fail-close (`onDegraded: block`).
 *                    A warm re-screen may clear it (retryable).
 *  - `timeout`     → the guard's mode-scoped budget elapsed on a cold screen.
 *                    Retryable (a warm screen is faster).
 *  - `unavailable` → the guard was otherwise dead (P1 down / 402 / malformed /
 *                    crash) and `onUnavailable: block` fired. Retryable once P1 is up.
 * Only set when `outcome === "guard_blocked"` (else absent/null).
 */
export type GuardBlockReason = "danger" | "degraded" | "timeout" | "unavailable";

/** Every paying-fetch outcome type (SPEC §8.3). */
export type Outcome =
  | "free"
  | "dry_run"
  | "policy_denied"
  | "guard_blocked"
  | "approval_denied"
  | "approval_queued"
  | "approval_timeout"
  | "paid_delivered"
  | "paid_not_delivered"
  | "payment_rejected"
  | "unknown_settlement"
  | "fetch_error";

export type Receipt = {
  schema: "p3f.receipt.v1";
  receiptId: string; // uuid4 hex
  ts: number; // epoch ms, deps.now()
  clientVersion: string; // "p3f-1.0.0"
  policyVersion: "p3f-policy-1.5.0";
  test: boolean; // PAYFETCH_TEST_MODE — excluded from all metrics
  url: string;
  method: string;
  host: string; // full URL incl. query (operator's own disk)
  outcome: Outcome;
  denyCode: string | null; // D-step code when policy_denied (§4.2)
  /** Set only on `guard_blocked` — WHY the block fired (P3 review §3; optional so
   *  pre-1.4.0 receipts still typecheck as this schema-compatible extension). */
  guardBlockReason?: GuardBlockReason | null;
  verdictPath: string[]; // pipeline steps traversed, in order
  quote: PaymentQuote | null; // selected quote (null when none)
  rejectedQuotes: Record<string, number> | null; // filter tally (§3.2)
  guards: GuardResult[]; // includes unavailable
  approval: { mode: string; approvedBy: "elicit" | "queue" | "config" | null } | null;
  payment: {
    payerAddress: string;
    nonce: string;
    validBeforeTs: number;
    settledAmountUsd: number | null;
    txRef: string | null;
    settlementConfirmed: boolean;
  } | null;
  budgets: {
    dayRemainingUsd: number;
    hostRemainingUsd: number;
    totalRemainingUsd: number | null;
  }; // AT decision time
  http: {
    status: number | null;
    contentType: string | null;
    bodyBytes: number | null;
    bodySha256: string | null;
    truncated: boolean;
    totalMs: number;
  } | null;
  notes: string[]; // §13 codes
};

export type AdjustKind =
  | "hold_released_expiry"
  | "hold_settled_expiry" // signed hold expired unobserved → counted as spend (fix M2, §5.2)
  | "autodeny_set"
  | "autodeny_cleared"
  | "manual_note";

export type Adjust = {
  schema: "p3f.adjust.v1";
  receiptId: string;
  ts: number;
  kind: AdjustKind;
  detail: Record<string, unknown>;
};

export type LedgerEntry = Receipt | Adjust;

export function isReceipt(e: LedgerEntry): e is Receipt {
  return e.schema === "p3f.receipt.v1";
}
export function isAdjust(e: LedgerEntry): e is Adjust {
  return e.schema === "p3f.adjust.v1";
}

// ---------------------------------------------------------------------------
// State (SPEC §8.2) — the disposable, rebuildable cache
// ---------------------------------------------------------------------------

export type StrikeClass = "confirmed" | "soft";
export type StrikeRecord = { ts: number; class: StrikeClass };
export type HostAutoDeny = { strikes: StrikeRecord[]; deniedUntilTs: number | null };

/** A live budget reservation (SPEC §5.1/§5.2). `holdId === receiptId`. */
export type Hold = {
  holdId: string; // === the receiptId of the payment that created it
  amountUsd: number;
  host: string;
  validBeforeTs: number; // epoch SECONDS — drives lazy expiry release (§5.2)
  createdTs: number; // epoch ms
  counterKeys: string[]; // counters this hold reserves against (§5.1)
  /**
   * true once buildPayment produced a signed EIP-3009 authorization for this hold
   * (setHoldValidBefore); a signed hold that expires unobserved is SETTLED, not
   * released — the authorization is in the wild and may have moved money (SPEC
   * §5.2, fix M2). Optional so legacy state/test fixtures still typecheck; absence
   * is treated as signed (safe over-count).
   */
  signed?: boolean;
};

/** A queue-mode approval (SPEC §6). A grant is a re-run permission, not a payment. */
export type ApprovalGrant = {
  approvalId: string;
  host: string;
  amountUsd: number; // quoted amount matched on (host, amountUsd ± 0)
  createdTs: number; // epoch ms; TTL from here (APPROVAL_QUEUE_TTL_S)
  resource: string | null;
  status: "pending" | "granted";
};

export type State = {
  schema: "p3f.state.v1";
  installId: string; // 32 hex (SPEC §12)
  counters: Record<string, number>; // counter-key → spent USD (§5.1)
  holds: Hold[];
  autoDeny: Record<string, HostAutoDeny>; // host → strike history + denial (§5.4)
  approvals: ApprovalGrant[]; // queue-mode grants (§6)
};

// ---------------------------------------------------------------------------
// Counter-key + UTC-date helpers (SPEC §5.1) — shared with budget/pipeline
// ---------------------------------------------------------------------------

/** UTC calendar date "YYYY-MM-DD" for an epoch-ms instant (SPEC §5.1 UTC day). */
export function utcDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** "yyyy-mm" ledger rotation key for an epoch-ms instant (SPEC §8.1). */
export function monthKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 7);
}

export const TOTAL_KEY = "total";
export function dayKey(date: string): string {
  return `day:${date}`;
}
export function hostDayKey(host: string, date: string): string {
  return `host:${host}:${date}`;
}
export function guardDayKey(guardId: string, date: string): string {
  return `guard:${guardId}:${date}`;
}

/** The three main-payment counters a spend on `host` at `ms` contributes to. */
export function mainCounterKeys(host: string, ms: number): string[] {
  const d = utcDate(ms);
  return [dayKey(d), hostDayKey(host, d), TOTAL_KEY];
}

// ---------------------------------------------------------------------------
// Outcome → state-derivation classification (SPEC §5.2, §5.4)
// ---------------------------------------------------------------------------

/** Outcomes whose record is fsync'd (SPEC §8.1 payment-class). */
const FSYNC_OUTCOMES: ReadonlySet<Outcome> = new Set<Outcome>([
  "paid_delivered",
  "paid_not_delivered",
  "payment_rejected",
  "unknown_settlement",
]);

/** A payment either SETTLED (spent) or KEPT ITS HOLD (live), per the §5.2 table. */
export function isSettledOutcome(o: Outcome): boolean {
  return o === "paid_delivered" || o === "paid_not_delivered";
}
export function isHoldKeptOutcome(o: Outcome): boolean {
  return (
    o === "payment_rejected" || o === "unknown_settlement" || o === "fetch_error"
  );
}

/** Strike class an outcome contributes to the host circuit breaker (SPEC §5.4). */
export function strikeClassForOutcome(o: Outcome): StrikeClass | null {
  if (o === "paid_not_delivered" || o === "payment_rejected") return "confirmed";
  if (o === "unknown_settlement") return "soft";
  return null; // fetch_error never strikes; success never strikes
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

export type LedgerOptions = {
  /** Liveness probe for lock-holder pids (real fs: process.kill(pid,0)). */
  isPidAlive?: (pid: number) => boolean;
  /**
   * 32-byte source for the integrity key (L14 tamper-evidence sidecar). Injected
   * in hermetic tests; defaults to `node:crypto` randomBytes(32). Only consulted
   * the first time a key must be MINTED (an existing key file is reused).
   */
  random?: () => Uint8Array;
};

export class LedgerLockedError extends Error {
  constructor(pid: number) {
    super(
      `payfetch: another live instance holds the ledger lock (pid ${pid}); refusing to start (SPEC §8.1).`,
    );
    this.name = "LedgerLockedError";
  }
}

export class LedgerAppendConflictError extends Error {
  constructor(receiptId: string) {
    super(
      `payfetch: refusing to re-append receiptId ${receiptId} — the ledger is append-only (SPEC §8/§14).`,
    );
    this.name = "LedgerAppendConflictError";
  }
}

export class Ledger {
  readonly #fs: PayfetchFs;
  readonly #dataDir: string;
  readonly #now: () => number;
  readonly #isPidAlive: (pid: number) => boolean;
  readonly #random: () => Uint8Array;
  readonly #seenReceiptIds = new Set<string>();
  #holdsLock = false;
  // --- L14 integrity sidecar (advisory; the JSONL is the source of truth) ---
  #integrityKey: Uint8Array | null = null;
  /** Per-month running chain head + next seq, seeded lazily from the sidecar. */
  readonly #integrityByMonth = new Map<string, { prevMac: string; nextSeq: number }>();

  constructor(
    fs: PayfetchFs,
    dataDir: string,
    now: () => number,
    opts: LedgerOptions = {},
  ) {
    this.#fs = fs;
    this.#dataDir = dataDir;
    this.#now = now;
    this.#random = opts.random ?? defaultRandom;
    this.#isPidAlive =
      opts.isPidAlive ??
      ((pid) => {
        try {
          process.kill(pid, 0);
          return true;
        } catch (err) {
          // ESRCH ⇒ dead; EPERM ⇒ alive but not ours.
          return (err as { code?: string }).code === "EPERM";
        }
      });
  }

  // --- paths -------------------------------------------------------------
  private ledgerDir(): string {
    return join(this.#dataDir, "ledger");
  }
  private monthFile(ms: number): string {
    return join(this.ledgerDir(), `${monthKey(ms)}.jsonl`);
  }
  private statePath(): string {
    return join(this.#dataDir, "state.json");
  }
  private lockPath(): string {
    return join(this.#dataDir, "lock");
  }
  downloadPath(receiptId: string): string {
    return join(this.#dataDir, "downloads", receiptId);
  }

  // --- lockfile (SPEC §8.1) ---------------------------------------------

  /** Acquire the single-writer lock; take over a stale lock; else refuse. */
  acquireLock(pid = process.pid): void {
    this.#fs.ensureDir(this.#dataDir);
    const path = this.lockPath();
    const contents = JSON.stringify({ pid, ts: this.#now() });
    if (this.#fs.tryCreateExclusive(path, contents)) {
      this.#holdsLock = true;
      return;
    }
    // Exists — evaluate staleness.
    const raw = this.#fs.readText(path);
    const holder = this.parseLock(raw);
    const stale =
      holder === null ||
      this.#now() - holder.ts > LOCK_STALE_S * 1000 ||
      !this.#isPidAlive(holder.pid);
    if (!stale) throw new LedgerLockedError(holder.pid);
    // Take over: remove + recreate. If the recreate races and loses, refuse.
    this.#fs.remove(path);
    if (!this.#fs.tryCreateExclusive(path, contents)) {
      const now2 = this.parseLock(this.#fs.readText(path));
      throw new LedgerLockedError(now2?.pid ?? -1);
    }
    this.#holdsLock = true;
  }

  private parseLock(raw: string | null): { pid: number; ts: number } | null {
    if (raw === null) return null;
    try {
      const o = JSON.parse(raw) as { pid?: unknown; ts?: unknown };
      if (typeof o.pid === "number" && typeof o.ts === "number") {
        return { pid: o.pid, ts: o.ts };
      }
    } catch {
      /* corrupt lock ⇒ treat as stale */
    }
    return null;
  }

  private refreshLock(pid = process.pid): void {
    if (!this.#holdsLock) return;
    this.#fs.writeText(this.lockPath(), JSON.stringify({ pid, ts: this.#now() }));
  }

  releaseLock(): void {
    if (!this.#holdsLock) return;
    this.#fs.remove(this.lockPath());
    this.#holdsLock = false;
  }

  // --- append (SPEC §8.1, §8.3) -----------------------------------------

  /** Append a receipt. Enforces append-only; fsyncs payment-class / holds. */
  append(receipt: Receipt): void {
    if (this.#seenReceiptIds.has(receipt.receiptId)) {
      throw new LedgerAppendConflictError(receipt.receiptId);
    }
    const fsync = FSYNC_OUTCOMES.has(receipt.outcome) || receipt.payment !== null;
    const json = JSON.stringify(receipt);
    this.#fs.appendLine(this.monthFile(receipt.ts), json, { fsync });
    this.#seenReceiptIds.add(receipt.receiptId);
    this.recordIntegrity(receipt.ts, json, receipt.receiptId, fsync);
    this.refreshLock();
  }

  /** Append an adjust record (always fsync'd — corrections are money-relevant). */
  appendAdjust(adjust: Adjust): void {
    const json = JSON.stringify(adjust);
    this.#fs.appendLine(this.monthFile(adjust.ts), json, { fsync: true });
    this.recordIntegrity(adjust.ts, json, adjust.receiptId, true);
    this.refreshLock();
  }

  // --- integrity sidecar (SPEC §8/§14, fix L14) -------------------------

  /**
   * Append the keyed hash-chain sidecar record for a just-written JSONL line.
   * NON-FATAL by contract: the JSONL is the source of truth; this is advisory
   * tamper-evidence. ANY failure here (key load, hashing, sidecar write) is
   * swallowed — a money-record write must NEVER fail because integrity logging
   * failed. Rebuild/read paths ignore the sidecar entirely.
   */
  private recordIntegrity(
    ts: number,
    json: string,
    receiptId: string,
    fsync: boolean,
  ): void {
    try {
      const key = this.integrityKey();
      const mk = monthKey(ts);
      const mf = this.monthFile(ts);
      let st = this.#integrityByMonth.get(mf);
      if (st === undefined) {
        // Seed the chain head + seq from the existing sidecar (or genesis if none)
        // so a fresh in-process Ledger continues a prior process's chain.
        const records = readSidecarRecords(this.#fs, sidecarPath(mf));
        const prevMac =
          records.length > 0 ? records[records.length - 1].mac : genesisMac(key, mk);
        st = { prevMac, nextSeq: records.length };
        this.#integrityByMonth.set(mf, st);
      }
      const sha256 = lineHash(json);
      const mac = nextMac(key, st.prevMac, sha256);
      const record = { seq: st.nextSeq, receiptId, sha256, mac };
      this.#fs.appendLine(sidecarPath(mf), JSON.stringify(record), { fsync });
      st.prevMac = mac;
      st.nextSeq += 1;
    } catch {
      /* advisory only — never fail a money write because tamper-evidence failed */
    }
  }

  /** Lazily load-or-mint the mode-600 integrity key (cached per instance). */
  private integrityKey(): Uint8Array {
    if (this.#integrityKey === null) {
      this.#integrityKey = loadOrCreateKey(this.#fs, this.#dataDir, this.#random);
    }
    return this.#integrityKey;
  }

  /**
   * Verify the integrity sidecar across every stored month file (L14). Reads only;
   * recomputes each month's hash-chain from genesis and diffs against the sidecar.
   * `ok` is false iff any month reports issues. Purely diagnostic — never consulted
   * by rebuild/read.
   */
  verifyIntegrity(): {
    ok: boolean;
    months: Array<{ month: string } & MonthIntegrity>;
  } {
    const key = this.integrityKey();
    const files = this.#fs
      .listDir(this.ledgerDir())
      .filter((f) => f.endsWith(".jsonl"));
    files.sort();
    const months = files.map((f) => {
      const res = verifyMonth(this.#fs, this.#dataDir, key, join(this.ledgerDir(), f));
      return { month: f.replace(/\.jsonl$/, ""), ...res };
    });
    return { ok: months.every((m) => m.ok), months };
  }

  // --- read --------------------------------------------------------------

  /** Parse all entries from a single month file (skipping unparseable lines). */
  private readMonth(ms: number): LedgerEntry[] {
    const raw = this.#fs.readText(this.monthFile(ms));
    if (raw === null) return [];
    const out: LedgerEntry[] = [];
    for (const line of raw.split("\n")) {
      const s = line.trim();
      if (s.length === 0) continue;
      try {
        const o = JSON.parse(s) as LedgerEntry;
        if (o && (o.schema === "p3f.receipt.v1" || o.schema === "p3f.adjust.v1")) {
          out.push(o);
        }
      } catch {
        /* skip a torn tail line — never let one bad line lose the file */
      }
    }
    return out;
  }

  /** Current + previous month entries, in file order (SPEC §8.2 rebuild scope). */
  readEntries(): LedgerEntry[] {
    const now = this.#now();
    const prevMs = new Date(now);
    prevMs.setUTCDate(0); // last day of previous month
    const cur = this.monthFile(now);
    const prev = this.monthFile(prevMs.getTime());
    if (cur === prev) return this.readMonth(now);
    return [...this.readMonth(prevMs.getTime()), ...this.readMonth(now)];
  }

  /** All receipts across every stored month file, newest-first not guaranteed. */
  readAllReceipts(): Receipt[] {
    const files = this.#fs.listDir(this.ledgerDir()).filter((f) => f.endsWith(".jsonl"));
    files.sort();
    const out: Receipt[] = [];
    for (const f of files) {
      const raw = this.#fs.readText(join(this.ledgerDir(), f));
      if (raw === null) continue;
      for (const line of raw.split("\n")) {
        const s = line.trim();
        if (s.length === 0) continue;
        try {
          const o = JSON.parse(s) as LedgerEntry;
          if (o && o.schema === "p3f.receipt.v1") out.push(o as Receipt);
        } catch {
          /* skip */
        }
      }
    }
    return out;
  }

  // --- state.json (SPEC §8.2) -------------------------------------------

  /** Parse state.json; null if missing or corrupt (⇒ caller rebuilds). */
  loadStateRaw(): State | null {
    const raw = this.#fs.readText(this.statePath());
    if (raw === null) return null;
    try {
      const o = JSON.parse(raw) as State;
      if (
        o &&
        o.schema === "p3f.state.v1" &&
        typeof o.installId === "string" &&
        o.counters &&
        Array.isArray(o.holds) &&
        o.autoDeny &&
        Array.isArray(o.approvals)
      ) {
        return o;
      }
    } catch {
      /* corrupt ⇒ rebuild */
    }
    return null;
  }

  saveState(state: State): void {
    this.#fs.writeText(this.statePath(), JSON.stringify(state));
    this.refreshLock();
  }

  /**
   * Reconstruct counters/holds/auto-deny from the ledger (SPEC §8.2). Replays
   * receipts in ts order; settled payments credit their counters, hold-kept
   * payments become live holds (unless a `hold_released_expiry` adjust released
   * them, or a `hold_settled_expiry` adjust counted them as spend on expiry — fix
   * M2, §5.2), and strike history is replayed to re-derive auto-deny. `installId`
   * is regenerated by the caller (deleting state regenerates it — SPEC §12).
   *
   * state.json is a disposable cache rebuildable from the ledger, so the expiry
   * SETTLEMENT (fix M2) MUST survive a rebuild — otherwise a rebuild would drop
   * the money a signed, unobserved-then-expired authorization moved on-chain and
   * we would UNDER-count (violating SPEC §0/§5.2).
   */
  rebuildState(installId: string): State {
    const entries = this.readEntries();
    // Adjusts referencing a hold-kept receipt: released (no spend, drop the hold)
    // vs settled-on-expiry (fix M2 — the signed authorization expired unobserved
    // and was counted as SPEND, not released).
    const released = new Set<string>();
    const settledOnExpiry = new Set<string>();
    for (const e of entries) {
      if (!isAdjust(e)) continue;
      if (e.kind === "hold_released_expiry") released.add(e.receiptId);
      else if (e.kind === "hold_settled_expiry") settledOnExpiry.add(e.receiptId);
    }
    const counters: Record<string, number> = {};
    const holds: Hold[] = [];
    const autoDeny: Record<string, HostAutoDeny> = {};

    const receipts = entries.filter(isReceipt).sort((a, b) => a.ts - b.ts);
    for (const r of receipts) {
      // --- counters / holds (only receipts that actually built a payment) ---
      if (r.payment !== null) {
        const keys = mainCounterKeys(r.host, r.ts);
        if (isSettledOutcome(r.outcome)) {
          const amt = r.payment.settledAmountUsd ?? r.quote?.amountUsd ?? 0;
          for (const k of keys) counters[k] = (counters[k] ?? 0) + amt;
        } else if (isHoldKeptOutcome(r.outcome)) {
          // Precedence: settledOnExpiry beats released beats live-hold — a hold-kept
          // receipt is credited AT MOST once (fix M2, SPEC §5.2).
          if (settledOnExpiry.has(r.receiptId)) {
            // Signed hold expired unobserved → sweepExpired counted it as spend.
            // Credit the counters; do NOT re-create a live hold.
            const amt = r.payment.settledAmountUsd ?? r.quote?.amountUsd ?? 0;
            for (const k of keys) counters[k] = (counters[k] ?? 0) + amt;
          } else if (released.has(r.receiptId)) {
            // Provably-unsigned/expired release — no spend, no hold (unchanged).
          } else {
            holds.push({
              holdId: r.receiptId,
              amountUsd: r.quote?.amountUsd ?? 0,
              host: r.host,
              validBeforeTs: r.payment.validBeforeTs,
              createdTs: r.ts,
              counterKeys: keys,
              signed: true, // it carried a payment — a signature existed (fix M2)
            });
          }
        }
      }
      // --- auto-deny strike replay (SPEC §5.4) ---
      const cls = strikeClassForOutcome(r.outcome);
      if (cls !== null) applyStrike(autoDeny, r.host, r.ts, cls);
    }

    return { schema: "p3f.state.v1", installId, counters, holds, autoDeny, approvals: [] };
  }
}

// ---------------------------------------------------------------------------
// Auto-deny strike engine (SPEC §5.4) — shared by rebuild + budget
// ---------------------------------------------------------------------------

const DAY_MS = 86_400_000;

/**
 * Record a strike for `host` at `ts` and (re)evaluate the circuit breaker.
 * Mutates `autoDeny` in place. Returns the new strike count within the window
 * and whether auto-deny is (now) engaged. SPEC §5.4:
 *  - engage iff, within AUTO_DENY_WINDOW_DAYS, total ≥ AUTO_DENY_STRIKES AND
 *    ≥1 confirmed, OR soft-only ≥ AUTO_DENY_UNKNOWN_ONLY_STRIKES.
 *  - engaged until lastStrikeTs + AUTO_DENY_TTL_DAYS.
 */
export function applyStrike(
  autoDeny: Record<string, HostAutoDeny>,
  host: string,
  ts: number,
  cls: StrikeClass,
): { strikeCount: number; engaged: boolean } {
  const entry = autoDeny[host] ?? { strikes: [], deniedUntilTs: null };
  const windowStart = ts - AUTO_DENY_WINDOW_DAYS * DAY_MS;
  // Prune strikes outside the window, then add this one.
  entry.strikes = entry.strikes.filter((s) => s.ts >= windowStart);
  entry.strikes.push({ ts, class: cls });
  entry.strikes.sort((a, b) => a.ts - b.ts);

  const total = entry.strikes.length;
  const confirmed = entry.strikes.filter((s) => s.class === "confirmed").length;
  const soft = total - confirmed;
  const engage =
    (total >= AUTO_DENY_STRIKES && confirmed >= 1) ||
    soft >= AUTO_DENY_UNKNOWN_ONLY_STRIKES;
  if (engage) {
    const lastTs = entry.strikes[entry.strikes.length - 1].ts;
    entry.deniedUntilTs = lastTs + AUTO_DENY_TTL_DAYS * DAY_MS;
  }
  autoDeny[host] = entry;
  return { strikeCount: total, engaged: engage };
}

/** Whether `host` is currently auto-denied at `now` (SPEC §5.4). */
export function isHostAutoDenied(
  autoDeny: Record<string, HostAutoDeny>,
  host: string,
  now: number,
): boolean {
  const e = autoDeny[host];
  return e != null && e.deniedUntilTs != null && now < e.deniedUntilTs;
}
