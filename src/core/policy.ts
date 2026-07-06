/**
 * P3′ payfetch — policy schema, frozen defaults, host matching, loading (SPEC §4.1).
 *
 * Purpose: the operator-owned spending policy (`{dataDir}/config.json`, schema
 * `p3f.policy.v1`) — the ONLY source of spending authority. The agent can never
 * expand it (SPEC §0 second invariant); agent-supplied params only tighten.
 *
 * Invariants (SPEC §4.1):
 *  - Defaults are built from the frozen constants (§15) and returned FROZEN.
 *  - Host patterns match HOST ONLY (never scheme/path), case-insensitively;
 *    "*.example.com" matches subdomains but NOT the apex; otherwise exact match.
 *  - `deny` always enforced and wins over `allow` (enforced in the pipeline, §4.2).
 *  - Loading: MISSING file → effective defaults, written back (the operator can
 *    see/edit what runs). INVALID file → FAIL CLOSED: a PolicyLoadError the
 *    pipeline surfaces as `policy_config_invalid` — NEVER a silent fallback to
 *    defaults (a typo must not restore caps the operator lowered).
 *  - The config FILE wins over programmatic overrides (SPEC §10 "config file wins
 *    in MCP mode"); a mid-request evaluation always uses ONE immutable snapshot.
 */

import { join } from "node:path";

import {
  APPROVAL_PREAPPROVED_UP_TO_DEFAULT_USD,
  APPROVAL_THRESHOLD_DEFAULT_USD,
  DAILY_CAP_DEFAULT_USD,
  PER_CALL_CAP_DEFAULT_USD,
  PER_HOST_DAILY_CAP_DEFAULT_USD,
  TOTAL_CAP_DEFAULT_USD,
} from "./constants.js";
import type { PayfetchFs } from "./fs.js";
import {
  DEFAULT_SAFETY_GUARD_CONFIG,
  DEFAULT_TRUST_GUARD_CONFIG,
} from "../guards/types.js";
import type { SafetyGuardConfig, TrustGuardConfig } from "../guards/types.js";

// ---------------------------------------------------------------------------
// Guard config types (SPEC §7.5 single source of truth)
// ---------------------------------------------------------------------------
/**
 * Per SPEC §7.5, the §4.1 `guards.trust`/`guards.safety` config blocks are
 * defined ONCE in `src/guards/types.ts`; `Policy.guards` imports them so config
 * never drifts between the policy engine and the guards that consume it. We
 * re-export for a single core-side import point.
 */
export type { TrustGuardConfig, SafetyGuardConfig };

// ---------------------------------------------------------------------------
// Policy schema (SPEC §4.1)
// ---------------------------------------------------------------------------

/** Exact host ("api.example.com") or wildcard ("*.example.com"). SPEC §4.1. */
export type HostPattern = string;

export type Policy = {
  schema: "p3f.policy.v1";
  mode: "open" | "allowlist";
  allow: HostPattern[];
  deny: HostPattern[];
  caps: {
    perCallUsd: number;
    dailyUsd: number;
    perHostDailyUsd: number;
    totalUsd: number | null;
  };
  approval: {
    thresholdUsd: number;
    mode: "elicit" | "queue" | "deny";
    elicitFallback: "queue" | "deny";
    /**
     * NON-elicitation pre-approval ceiling (USD). `null` (default) ⇒ OFF. When set
     * > 0, an above-threshold payment whose amount is ≤ this ceiling is approved via
     * CONFIG — the explicit-config path for a client that cannot elicit a human
     * (SPEC §6, P3 review). Never bypasses caps (D7/D11) or guards (D8); never an
     * agent action (config.json is operator-owned).
     */
    preApprovedUpToUsd: number | null;
    /**
     * Hosts pre-approved to auto-pay ABOVE threshold without a dialog (still within
     * every cap + guard). Same host-pattern grammar as `allow`/`deny`
     * ("*.x.com" matches subdomains, not the apex). Default `[]`.
     */
    preApprovedHosts: HostPattern[];
  };
  guards: {
    trust: TrustGuardConfig;
    safety: SafetyGuardConfig;
  };
  allowPrivateTargets: boolean;
  autoDeny: { enabled: boolean };
};

// ---------------------------------------------------------------------------
// Frozen defaults (SPEC §4.1 defaults, from §15 constants)
// ---------------------------------------------------------------------------

/** Build the frozen default policy from the §15 constants (SPEC §4.1). */
export function defaultPolicy(): Policy {
  return Object.freeze({
    schema: "p3f.policy.v1",
    mode: "open",
    allow: [] as HostPattern[],
    deny: [] as HostPattern[],
    caps: Object.freeze({
      perCallUsd: PER_CALL_CAP_DEFAULT_USD,
      dailyUsd: DAILY_CAP_DEFAULT_USD,
      perHostDailyUsd: PER_HOST_DAILY_CAP_DEFAULT_USD,
      totalUsd: TOTAL_CAP_DEFAULT_USD,
    }),
    approval: Object.freeze({
      thresholdUsd: APPROVAL_THRESHOLD_DEFAULT_USD,
      mode: "elicit",
      elicitFallback: "deny",
      preApprovedUpToUsd: APPROVAL_PREAPPROVED_UP_TO_DEFAULT_USD,
      preApprovedHosts: [] as HostPattern[],
    }),
    guards: Object.freeze({
      // Single-source guard defaults (SPEC §7.5) — deep-copied so Policy stays
      // mutable-mergeable and the frozen source is never touched.
      trust: {
        ...DEFAULT_TRUST_GUARD_CONFIG,
        blockVerdicts: [...DEFAULT_TRUST_GUARD_CONFIG.blockVerdicts],
      },
      safety: {
        ...DEFAULT_SAFETY_GUARD_CONFIG,
        blockVerdicts: [...DEFAULT_SAFETY_GUARD_CONFIG.blockVerdicts],
        blockDeployerVerdicts: [...DEFAULT_SAFETY_GUARD_CONFIG.blockDeployerVerdicts],
      },
    }),
    allowPrivateTargets: false,
    autoDeny: { enabled: true },
  }) as Policy;
}

// ---------------------------------------------------------------------------
// Host-pattern matching (SPEC §4.1)
// ---------------------------------------------------------------------------

/**
 * Does `host` match `pattern`? Case-insensitive, host-only. "*.example.com"
 * matches subdomains (any depth) but NOT the apex; otherwise exact equality.
 */
export function matchHostPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

/** True iff `host` matches ANY pattern in the list. */
export function matchesAnyHost(host: string, patterns: readonly HostPattern[]): boolean {
  return patterns.some((p) => matchHostPattern(host, p));
}

// ---------------------------------------------------------------------------
// Merge (programmatic overrides) + validate (config file) — SPEC §4.1, §10
// ---------------------------------------------------------------------------

/** Deep-merge a `Partial<Policy>` over a base (programmatic overrides, SPEC §10). */
export function mergePolicy(base: Policy, over?: DeepPartial<Policy>): Policy {
  if (!over) return base;
  return {
    schema: "p3f.policy.v1",
    mode: over.mode ?? base.mode,
    allow: over.allow ? [...over.allow] : [...base.allow],
    deny: over.deny ? [...over.deny] : [...base.deny],
    caps: { ...base.caps, ...(over.caps ?? {}) },
    approval: {
      ...base.approval,
      ...(over.approval ?? {}),
      // Array field: replace-if-provided, else copy the base (never share the frozen ref).
      preApprovedHosts: over.approval?.preApprovedHosts
        ? [...over.approval.preApprovedHosts]
        : [...base.approval.preApprovedHosts],
    },
    guards: {
      trust: { ...base.guards.trust, ...(over.guards?.trust ?? {}) },
      safety: { ...base.guards.safety, ...(over.guards?.safety ?? {}) },
    },
    allowPrivateTargets: over.allowPrivateTargets ?? base.allowPrivateTargets,
    autoDeny: { ...base.autoDeny, ...(over.autoDeny ?? {}) },
  };
}

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends readonly (infer U)[]
    ? U[]
    : T[K] extends object
      ? DeepPartial<T[K]>
      : T[K];
};

/** Thrown-in-spirit marker: an invalid config file (SPEC §4.1 fail-closed). */
export class PolicyLoadError extends Error {
  constructor(public readonly reason: string) {
    super(`payfetch: invalid ${"config.json"} — ${reason} (SPEC §4.1: fail closed).`);
    this.name = "PolicyLoadError";
  }
}

export type PolicyLoad =
  | { ok: true; policy: Policy; mtimeMs: number | null }
  | { ok: false; error: string };

// --- config validation: present fields must be well-typed; absent → base ---

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v != null && typeof v === "object" && !Array.isArray(v);
}
function fail(reason: string): never {
  throw new PolicyLoadError(reason);
}
function reqEnum<T extends string>(
  v: unknown,
  allowed: readonly T[],
  base: T,
  field: string,
): T {
  if (v === undefined) return base;
  if (typeof v === "string" && (allowed as readonly string[]).includes(v)) return v as T;
  fail(`${field} must be one of ${allowed.join("|")}`);
}
function reqNumber(v: unknown, base: number, field: string): number {
  if (v === undefined) return base;
  if (typeof v === "number" && Number.isFinite(v) && v >= 0) return v;
  fail(`${field} must be a non-negative number`);
}
function reqNumberOrNull(v: unknown, base: number | null, field: string): number | null {
  if (v === undefined) return base;
  if (v === null) return null;
  if (typeof v === "number" && Number.isFinite(v) && v >= 0) return v;
  fail(`${field} must be a non-negative number or null`);
}
function reqBool(v: unknown, base: boolean, field: string): boolean {
  if (v === undefined) return base;
  if (typeof v === "boolean") return v;
  fail(`${field} must be a boolean`);
}
function reqStringArray(v: unknown, base: string[], field: string): string[] {
  if (v === undefined) return [...base];
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) return [...v];
  fail(`${field} must be an array of strings`);
}

/**
 * Validate a parsed config object, defaulting absent fields from `base`. A
 * hard type/enum/schema error FAILS CLOSED (throws PolicyLoadError); a
 * merely-suspicious-but-valid config is surfaced through the optional `warn`
 * sink (a WARNING, never an error — it can only mislead, not move money).
 */
export function validateConfig(
  parsed: unknown,
  base: Policy,
  warn?: (msg: string) => void,
): Policy {
  if (!isPlainObject(parsed)) fail("root must be a JSON object");
  const root = parsed;
  if (root.schema !== undefined && root.schema !== "p3f.policy.v1") {
    fail(`schema must be "p3f.policy.v1"`);
  }
  const caps = root.caps === undefined ? {} : isPlainObject(root.caps) ? root.caps : fail("caps must be an object");
  const approval =
    root.approval === undefined ? {} : isPlainObject(root.approval) ? root.approval : fail("approval must be an object");
  const guards =
    root.guards === undefined ? {} : isPlainObject(root.guards) ? root.guards : fail("guards must be an object");
  const trust =
    (guards as Record<string, unknown>).trust === undefined
      ? {}
      : isPlainObject((guards as Record<string, unknown>).trust)
        ? ((guards as Record<string, unknown>).trust as Record<string, unknown>)
        : fail("guards.trust must be an object");
  const safety =
    (guards as Record<string, unknown>).safety === undefined
      ? {}
      : isPlainObject((guards as Record<string, unknown>).safety)
        ? ((guards as Record<string, unknown>).safety as Record<string, unknown>)
        : fail("guards.safety must be an object");
  const autoDeny =
    root.autoDeny === undefined ? {} : isPlainObject(root.autoDeny) ? root.autoDeny : fail("autoDeny must be an object");

  const policy: Policy = {
    schema: "p3f.policy.v1",
    mode: reqEnum(root.mode, ["open", "allowlist"] as const, base.mode, "mode"),
    allow: reqStringArray(root.allow, base.allow, "allow"),
    deny: reqStringArray(root.deny, base.deny, "deny"),
    caps: {
      perCallUsd: reqNumber((caps as Record<string, unknown>).perCallUsd, base.caps.perCallUsd, "caps.perCallUsd"),
      dailyUsd: reqNumber((caps as Record<string, unknown>).dailyUsd, base.caps.dailyUsd, "caps.dailyUsd"),
      perHostDailyUsd: reqNumber(
        (caps as Record<string, unknown>).perHostDailyUsd,
        base.caps.perHostDailyUsd,
        "caps.perHostDailyUsd",
      ),
      totalUsd: reqNumberOrNull((caps as Record<string, unknown>).totalUsd, base.caps.totalUsd, "caps.totalUsd"),
    },
    approval: {
      thresholdUsd: reqNumber(
        (approval as Record<string, unknown>).thresholdUsd,
        base.approval.thresholdUsd,
        "approval.thresholdUsd",
      ),
      mode: reqEnum(
        (approval as Record<string, unknown>).mode,
        ["elicit", "queue", "deny"] as const,
        base.approval.mode,
        "approval.mode",
      ),
      elicitFallback: reqEnum(
        (approval as Record<string, unknown>).elicitFallback,
        ["queue", "deny"] as const,
        base.approval.elicitFallback,
        "approval.elicitFallback",
      ),
      preApprovedUpToUsd: reqNumberOrNull(
        (approval as Record<string, unknown>).preApprovedUpToUsd,
        base.approval.preApprovedUpToUsd,
        "approval.preApprovedUpToUsd",
      ),
      preApprovedHosts: reqStringArray(
        (approval as Record<string, unknown>).preApprovedHosts,
        base.approval.preApprovedHosts,
        "approval.preApprovedHosts",
      ),
    },
    guards: {
      trust: {
        enabled: reqBool(trust.enabled, base.guards.trust.enabled, "guards.trust.enabled"),
        mode: reqEnum(trust.mode, ["advisory", "enforce"] as const, base.guards.trust.mode, "guards.trust.mode"),
        minScore: reqNumberOrNull(trust.minScore, base.guards.trust.minScore, "guards.trust.minScore"),
        blockVerdicts: reqStringArray(trust.blockVerdicts, base.guards.trust.blockVerdicts, "guards.trust.blockVerdicts"),
        blockUnrated: reqBool(trust.blockUnrated, base.guards.trust.blockUnrated, "guards.trust.blockUnrated"),
        onUnavailable: reqEnum(
          trust.onUnavailable,
          ["proceed", "block"] as const,
          base.guards.trust.onUnavailable,
          "guards.trust.onUnavailable",
        ),
        dailyBudgetUsd: reqNumber(trust.dailyBudgetUsd, base.guards.trust.dailyBudgetUsd, "guards.trust.dailyBudgetUsd"),
      },
      safety: {
        enabled: reqBool(safety.enabled, base.guards.safety.enabled, "guards.safety.enabled"),
        mode: reqEnum(safety.mode, ["advisory", "enforce"] as const, base.guards.safety.mode, "guards.safety.mode"),
        depth: reqEnum(safety.depth, ["basic", "deep"] as const, base.guards.safety.depth, "guards.safety.depth"),
        blockVerdicts: reqStringArray(
          safety.blockVerdicts,
          base.guards.safety.blockVerdicts,
          "guards.safety.blockVerdicts",
        ),
        blockDeployerVerdicts: reqStringArray(
          safety.blockDeployerVerdicts,
          base.guards.safety.blockDeployerVerdicts,
          "guards.safety.blockDeployerVerdicts",
        ),
        onUnavailable: reqEnum(
          safety.onUnavailable,
          ["proceed", "block"] as const,
          base.guards.safety.onUnavailable,
          "guards.safety.onUnavailable",
        ),
        onDegraded: reqEnum(
          safety.onDegraded,
          ["block", "warn", "proceed"] as const,
          base.guards.safety.onDegraded,
          "guards.safety.onDegraded",
        ),
        dailyBudgetUsd: reqNumber(
          safety.dailyBudgetUsd,
          base.guards.safety.dailyBudgetUsd,
          "guards.safety.dailyBudgetUsd",
        ),
      },
    },
    allowPrivateTargets: reqBool(root.allowPrivateTargets, base.allowPrivateTargets, "allowPrivateTargets"),
    autoDeny: {
      enabled: reqBool((autoDeny as Record<string, unknown>).enabled, base.autoDeny.enabled, "autoDeny.enabled"),
    },
  };

  // NIT sanity bound (P3 review): a `preApprovedUpToUsd` above the per-call cap is
  // almost certainly a fat-finger — the per-call cap (D7) clips every payment first,
  // so the excess ceiling can NEVER auto-approve more than `perCallUsd`. WARN (not a
  // hard error): the config is well-typed and strictly SAFER than it reads, so
  // failing closed here would block a benign-if-confused policy. The operator likely
  // meant to raise the per-call cap too, or lower the ceiling.
  if (
    policy.approval.preApprovedUpToUsd !== null &&
    policy.approval.preApprovedUpToUsd > policy.caps.perCallUsd
  ) {
    warn?.(
      `approval.preApprovedUpToUsd (${policy.approval.preApprovedUpToUsd}) exceeds ` +
        `caps.perCallUsd (${policy.caps.perCallUsd}); the per-call cap clips every payment ` +
        `first, so the excess pre-approval ceiling has no effect.`,
    );
  }

  return policy;
}

// ---------------------------------------------------------------------------
// loadPolicy (SPEC §4.1) — the config-file lifecycle
// ---------------------------------------------------------------------------

export function configPath(dataDir: string): string {
  return join(dataDir, "config.json");
}

export type PolicyIo = {
  fs: PayfetchFs;
  log?: (msg: string, fields?: Record<string, unknown>) => void;
};

/**
 * Load `{dataDir}/config.json` (SPEC §4.1). `base` is defaults ⊕ programmatic
 * overrides (SPEC §10). Missing file → write `base` back and use it. Present +
 * valid → the file (config wins; absent fields default from `base`). Present +
 * invalid → fail closed ({ok:false}); NEVER silently defaults.
 */
export function loadPolicy(dataDir: string, io: PolicyIo, base: Policy): PolicyLoad {
  const path = configPath(dataDir);
  const raw = io.fs.readText(path);
  if (raw === null) {
    io.fs.writeText(path, JSON.stringify(base, null, 2));
    return { ok: true, policy: base, mtimeMs: io.fs.statMtimeMs(path) };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, error: `config.json is not valid JSON: ${(err as Error).message}` };
  }
  try {
    const policy = validateConfig(parsed, base, (msg) =>
      io.log?.("policy.config_warning", { message: msg }),
    );
    return { ok: true, policy, mtimeMs: io.fs.statMtimeMs(path) };
  } catch (err) {
    if (err instanceof PolicyLoadError) return { ok: false, error: err.reason };
    return { ok: false, error: (err as Error).message };
  }
}
