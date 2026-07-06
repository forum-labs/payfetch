/**
 * P3′ payfetch — narrow filesystem seam (SPEC §8 testability directive).
 *
 * Purpose: the ledger (§8), budget state (§8.2), policy config (§4.1), and
 * transport file-mode downloads (§11) all touch disk. Per the SPEC §8 build
 * directive ("filesystem behind a narrow injected interface so tests use an
 * in-memory fs"), every disk touch in the core goes through THIS interface. The
 * real (node:fs) implementation lives here; the in-memory implementation used by
 * hermetic tests lives in test/fakes.ts.
 *
 * Invariants:
 *  - `appendLine` NEVER rewrites existing bytes — it opens in append mode only
 *    (SPEC §8.1 "no record is ever rewritten"). `fsync: true` forces a durable
 *    write for payment-class records (SPEC §8.1).
 *  - `writeText`/`writeBytes` are the ONLY overwrite paths, used for the mutable
 *    state cache / config / downloads — NEVER the append-only ledger.
 *  - `tryCreateExclusive` is O_EXCL (the `wx` open flag): it creates iff the path
 *    does not exist, returning false otherwise — the lockfile primitive (§8.1).
 *  - Every accessor returns a typed "absent" value (null / []) rather than
 *    throwing on ENOENT — corruption/absence is an inconvenience, never a crash
 *    (SPEC §8.2).
 */

import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

/** The narrow disk contract the core depends on. Injected everywhere. */
export interface PayfetchFs {
  /** Create `dir` (and parents) if absent. Idempotent. */
  ensureDir(dir: string): void;
  /** UTF-8 file contents, or null if the file does not exist. */
  readText(path: string): string | null;
  /** Overwrite `path` atomically (tmp + rename). Creates parent dirs. */
  writeText(path: string, data: string): void;
  /** Overwrite `path` with raw bytes atomically. Creates parent dirs. */
  writeBytes(path: string, data: Uint8Array): void;
  /** Append one line (a trailing "\n" is added). fsync when requested. */
  appendLine(path: string, line: string, opts: { fsync: boolean }): void;
  /** Last-modified epoch-ms, or null if absent. */
  statMtimeMs(path: string): number | null;
  /** Entry names in `dir` (not recursive); [] if the dir is absent. */
  listDir(dir: string): string[];
  /**
   * O_EXCL create: writes `contents` iff `path` is absent; false if it exists.
   * `mode` sets the created file's permission bits (default 0o666 minus umask);
   * the integrity key uses 0o600 so it is meaningfully harder to read than the
   * world-readable ledger (L14). Ignored by the in-memory fs.
   */
  tryCreateExclusive(path: string, contents: string, mode?: number): boolean;
  /** Remove `path` if present (no error if absent). */
  remove(path: string): void;
}

function isEnoent(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === "ENOENT";
}
function isEexist(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === "EEXIST";
}

/** node:fs-backed PayfetchFs (production). Synchronous — local, small, ordered. */
export const realFs: PayfetchFs = {
  ensureDir(dir: string): void {
    mkdirSync(dir, { recursive: true });
  },

  readText(path: string): string | null {
    try {
      return readFileSync(path, "utf8");
    } catch (err) {
      if (isEnoent(err)) return null;
      throw err;
    }
  },

  writeText(path: string, data: string): void {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.tmp.${process.pid}`;
    const fd = openSync(tmp, "w");
    try {
      writeSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  },

  writeBytes(path: string, data: Uint8Array): void {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.tmp.${process.pid}`;
    const fd = openSync(tmp, "w");
    try {
      writeSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  },

  appendLine(path: string, line: string, opts: { fsync: boolean }): void {
    mkdirSync(dirname(path), { recursive: true });
    const fd = openSync(path, "a");
    try {
      writeSync(fd, line.endsWith("\n") ? line : `${line}\n`);
      if (opts.fsync) fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  },

  statMtimeMs(path: string): number | null {
    try {
      return statSync(path).mtimeMs;
    } catch (err) {
      if (isEnoent(err)) return null;
      throw err;
    }
  },

  listDir(dir: string): string[] {
    try {
      return readdirSync(dir);
    } catch (err) {
      if (isEnoent(err)) return [];
      throw err;
    }
  },

  tryCreateExclusive(path: string, contents: string, mode?: number): boolean {
    mkdirSync(dirname(path), { recursive: true });
    let fd: number;
    try {
      fd = openSync(path, "wx", mode ?? 0o666); // O_CREAT | O_EXCL | O_WRONLY, perm bits (L14)
    } catch (err) {
      if (isEexist(err)) return false;
      throw err;
    }
    try {
      writeSync(fd, contents);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return true;
  },

  remove(path: string): void {
    rmSync(path, { force: true });
  },
};
