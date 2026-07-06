/**
 * P3′ payfetch — tamper-EVIDENT ledger sidecar (SPEC §8/§14, fix L14).
 *
 * Purpose: make tampering with the append-only receipts ledger DETECTABLE. Each
 * ledger line (receipt or adjust) gets one sidecar record `{seq, receiptId,
 * sha256, mac}` in a parallel `{yyyy-mm}.jsonl.integrity` file. The `mac` field
 * is a keyed HMAC hash-chain: `mac[i] = HMAC(key, mac[i-1] + ":" + sha256(line))`,
 * seeded from a per-month genesis. Recomputing the chain from genesis and diffing
 * against the recorded sidecar surfaces edited/removed/inserted lines with the
 * offending seq/receiptId.
 *
 * HONEST SCOPE — tamper-EVIDENCE, not tamper-PREVENTION. A process that can read
 * the integrity key can forge a valid chain. The value is asymmetric access: the
 * `~/.payfetch` data dir is created world-readable-by-default, but the key file is
 * created mode-600, so other local processes/users can read the ledger yet cannot
 * forge a valid chain; and accidental corruption / edits / insertions / mid-stream
 * deletions are caught. RESIDUAL (inherent to a self-consistent keyed chain with
 * no external tip): truncating the TAIL — dropping the most recent line together
 * with its sidecar record — leaves a shorter but valid chain and is NOT detected
 * here; closing it would need a keyed per-month tip (count + head MAC) the attacker
 * cannot forge without the key. This is advisory: the JSONL is the source of truth,
 * the sidecar is advisory evidence, and rebuild/read paths IGNORE it entirely.
 *
 * This module is pure functions over the injected `PayfetchFs` (SPEC §8 seam) —
 * the ONLY node builtins it touches are `node:crypto` (hashing, as elsewhere in
 * the core, e.g. transport.ts/parse402.ts) and `node:path` (path math).
 */

import { createHash, createHmac, randomBytes } from "node:crypto";
import { basename, join } from "node:path";

import type { PayfetchFs } from "./fs.js";

/** HMAC domain-separation prefix for the per-month genesis MAC. */
const GENESIS_PREFIX = "p3f-integrity-genesis:";
/** Integrity key size (bytes) — a 256-bit HMAC-SHA256 key. */
export const INTEGRITY_KEY_BYTES = 32;
/** Key file permission bits — owner read/write only (L14 asymmetric access). */
export const INTEGRITY_KEY_MODE = 0o600;
const JSONL_SUFFIX = ".jsonl";
const SIDECAR_SUFFIX = ".integrity";

/** One sidecar record — parallels exactly one ledger JSONL line. */
export type SidecarRecord = {
  seq: number; // 0-based line index within the month file
  receiptId: string; // the ledger line's receiptId (receipt or adjust)
  sha256: string; // sha256 hex of the exact JSONL line (no trailing newline)
  mac: string; // keyed hash-chain MAC (hex)
};

/** Per-month verify result. `checked` counts the JSONL lines examined. */
export type MonthIntegrity = { ok: boolean; checked: number; issues: string[] };

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** The mode-600 integrity key file lives at `{dataDir}/integrity.key`. */
export function integrityKeyPath(dataDir: string): string {
  return join(dataDir, "integrity.key");
}

/** The sidecar for a month file: `{yyyy-mm}.jsonl` → `{yyyy-mm}.jsonl.integrity`. */
export function sidecarPath(monthFile: string): string {
  return `${monthFile}${SIDECAR_SUFFIX}`;
}

/** The month key ("yyyy-mm") a month file encodes, from its filename. */
function monthKeyOfFile(monthFile: string): string {
  const base = basename(monthFile);
  return base.endsWith(JSONL_SUFFIX) ? base.slice(0, -JSONL_SUFFIX.length) : base;
}

// ---------------------------------------------------------------------------
// hex <-> bytes (the key is stored as hex text so it round-trips through readText)
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function hexToBytes(hex: string): Uint8Array | null {
  const h = hex.trim();
  if (h.length === 0 || h.length % 2 !== 0) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Chain math (keyed HMAC-SHA256 hash-chain)
// ---------------------------------------------------------------------------

/** sha256 hex of the exact JSONL line string (WITHOUT the trailing newline). */
export function lineHash(lineString: string): string {
  return createHash("sha256").update(lineString).digest("hex");
}

/** Genesis MAC for a month — the chain's seed before any line. */
export function genesisMac(key: Uint8Array, monthKey: string): string {
  return createHmac("sha256", key).update(GENESIS_PREFIX + monthKey).digest("hex");
}

/** Next MAC in the chain: HMAC(key, prevMac + ":" + sha256(line)). */
export function nextMac(key: Uint8Array, prevMacHex: string, lineSha256Hex: string): string {
  return createHmac("sha256", key)
    .update(`${prevMacHex}:${lineSha256Hex}`)
    .digest("hex");
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/**
 * Load the integrity key, or create it (mode-600) if absent. Stored as hex text.
 * On an exclusive-create race (another instance wrote it first) re-read the file.
 * NEVER logs the key. The `random` source is injected for hermetic tests.
 */
export function loadOrCreateKey(
  fs: PayfetchFs,
  dataDir: string,
  random: () => Uint8Array,
): Uint8Array {
  const path = integrityKeyPath(dataDir);
  const existing = fs.readText(path);
  if (existing !== null) {
    const bytes = hexToBytes(existing);
    if (bytes !== null) return bytes;
    // Corrupt key file — fall through and try to create (loses the race → re-read).
  }
  const fresh = random();
  const hex = bytesToHex(fresh);
  if (fs.tryCreateExclusive(path, hex, INTEGRITY_KEY_MODE)) return fresh;
  // Lost the race (or the file already existed) — re-read the authoritative key.
  const raced = fs.readText(path);
  const bytes = raced !== null ? hexToBytes(raced) : null;
  return bytes ?? fresh;
}

/** node:crypto-backed 32-byte random (production default for the Ledger). */
export function defaultRandom(): Uint8Array {
  return new Uint8Array(randomBytes(INTEGRITY_KEY_BYTES));
}

// ---------------------------------------------------------------------------
// Sidecar read / verify
// ---------------------------------------------------------------------------

function isSidecarRecord(o: unknown): o is SidecarRecord {
  if (o == null || typeof o !== "object") return false;
  const r = o as Record<string, unknown>;
  return (
    typeof r.seq === "number" &&
    typeof r.receiptId === "string" &&
    typeof r.sha256 === "string" &&
    typeof r.mac === "string"
  );
}

/** Parse all sidecar records for a month (well-formed records only, in order). */
export function readSidecarRecords(fs: PayfetchFs, sidecar: string): SidecarRecord[] {
  const raw = fs.readText(sidecar);
  if (raw === null) return [];
  const out: SidecarRecord[] = [];
  for (const seg of raw.split("\n")) {
    if (seg.trim().length === 0) continue;
    try {
      const o = JSON.parse(seg) as unknown;
      if (isSidecarRecord(o)) out.push(o);
    } catch {
      /* a torn/garbage sidecar line — the count mismatch is reported by verify */
    }
  }
  return out;
}

/** The exact JSONL line strings of a month file (no trailing-newline segments). */
function readLedgerLines(fs: PayfetchFs, monthFile: string): string[] {
  const raw = fs.readText(monthFile);
  if (raw === null) return [];
  const out: string[] = [];
  for (const seg of raw.split("\n")) {
    if (seg.trim().length === 0) continue;
    out.push(seg); // exact bytes between newlines — what lineHash must see
  }
  return out;
}

/** Best-effort `receiptId` of a JSONL line, for issue messages (null if unparseable). */
function lineReceiptId(line: string): string | null {
  try {
    const o = JSON.parse(line) as { receiptId?: unknown };
    return typeof o.receiptId === "string" ? o.receiptId : null;
  } catch {
    return null;
  }
}

/**
 * Recompute the chain from genesis over a month's JSONL lines and diff against
 * its sidecar records. Reports every discrepancy — tampered/edited line (hash
 * mismatch), missing/extra sidecar record, or broken chain (MAC mismatch) — with
 * the offending seq/receiptId. Nothing is skipped silently: gaps are REPORTED.
 *
 * The chain advances from each sidecar's RECORDED mac (not the recomputed one) so
 * a single tampered line surfaces as ONE issue rather than cascading through every
 * later line; a deletion still breaks the chain because each recorded mac binds
 * its predecessor's recorded mac.
 */
export function verifyMonth(
  fs: PayfetchFs,
  _dataDir: string,
  key: Uint8Array,
  monthFile: string,
): MonthIntegrity {
  const issues: string[] = [];
  const monthKey = monthKeyOfFile(monthFile);
  const lines = readLedgerLines(fs, monthFile);
  const records = readSidecarRecords(fs, sidecarPath(monthFile));

  let prev = genesisMac(key, monthKey);
  const n = Math.max(lines.length, records.length);
  for (let i = 0; i < n; i++) {
    const line = i < lines.length ? lines[i] : null;
    const rec = i < records.length ? records[i] : null;

    if (line === null && rec !== null) {
      issues.push(
        `seq ${i} (receiptId ${rec.receiptId}): sidecar record has no matching ledger line (extra sidecar record / deleted ledger line)`,
      );
      prev = rec.mac; // advance from the recorded mac so later lines still verify
      continue;
    }
    if (line !== null && rec === null) {
      issues.push(
        `seq ${i} (receiptId ${lineReceiptId(line) ?? "?"}): ledger line has no sidecar record (missing sidecar record)`,
      );
      prev = nextMac(key, prev, lineHash(line)); // best-effort chain continuation
      continue;
    }
    // Both present.
    const sha = lineHash(line!);
    const expectedMac = nextMac(key, prev, sha);
    const rid = lineReceiptId(line!) ?? rec!.receiptId;
    if (rec!.sha256 !== sha) {
      issues.push(
        `seq ${i} (receiptId ${rid}): ledger line hash mismatch — line was edited or corrupted`,
      );
    }
    if (rec!.mac !== expectedMac) {
      issues.push(
        `seq ${i} (receiptId ${rid}): MAC mismatch — broken hash-chain (tampered, reordered, or deleted line)`,
      );
    }
    if (rec!.seq !== i) {
      issues.push(`seq ${i} (receiptId ${rid}): sidecar record has out-of-order seq ${rec!.seq}`);
    }
    prev = rec!.mac; // chain continues from the RECORDED mac (see doc comment)
  }

  return { ok: issues.length === 0, checked: lines.length, issues };
}
