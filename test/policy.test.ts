/**
 * P3′ payfetch — policy engine tests (SPEC §4.1, §14 "Policy/pipeline").
 *
 * Covers: frozen defaults from constants; host-pattern matching (exact,
 * case-insensitive, wildcard apex-vs-subdomain, host-only); loadPolicy lifecycle
 * (missing → defaults written back; invalid → FAIL CLOSED, never silent
 * defaults; valid file wins; partial file defaults absent fields); programmatic
 * merge (config wins in MCP mode); mtime-change re-read seam.
 */

import { describe, expect, it } from "vitest";

import {
  APPROVAL_THRESHOLD_DEFAULT_USD,
  DAILY_CAP_DEFAULT_USD,
  PER_CALL_CAP_DEFAULT_USD,
} from "../src/core/constants.js";
import {
  configPath,
  defaultPolicy,
  loadPolicy,
  matchHostPattern,
  matchesAnyHost,
  mergePolicy,
  validateConfig,
} from "../src/core/policy.js";
import { inMemoryFs } from "./fakes.js";

describe("defaultPolicy — frozen defaults from §15 constants", () => {
  it("mirrors the SPEC §4.1 defaults", () => {
    const p = defaultPolicy();
    expect(p.mode).toBe("open");
    expect(p.caps.perCallUsd).toBe(PER_CALL_CAP_DEFAULT_USD);
    expect(p.caps.dailyUsd).toBe(DAILY_CAP_DEFAULT_USD);
    expect(p.caps.totalUsd).toBeNull();
    expect(p.approval.thresholdUsd).toBe(APPROVAL_THRESHOLD_DEFAULT_USD);
    expect(p.approval.mode).toBe("elicit");
    expect(p.approval.elicitFallback).toBe("deny");
    expect(p.guards.trust.enabled).toBe(true);
    expect(p.guards.trust.mode).toBe("advisory");
    expect(p.guards.safety.enabled).toBe(false);
    expect(p.allowPrivateTargets).toBe(false);
    expect(p.autoDeny.enabled).toBe(true);
  });
});

describe("matchHostPattern — SPEC §4.1", () => {
  it("exact match, case-insensitive", () => {
    expect(matchHostPattern("api.example.com", "api.example.com")).toBe(true);
    expect(matchHostPattern("API.Example.COM", "api.example.com")).toBe(true);
    expect(matchHostPattern("other.example.com", "api.example.com")).toBe(false);
  });

  it("wildcard matches subdomains but NOT the apex", () => {
    expect(matchHostPattern("api.example.com", "*.example.com")).toBe(true);
    expect(matchHostPattern("a.b.example.com", "*.example.com")).toBe(true);
    expect(matchHostPattern("example.com", "*.example.com")).toBe(false); // apex excluded
  });

  it("wildcard does not match a look-alike suffix (no dot boundary)", () => {
    expect(matchHostPattern("notexample.com", "*.example.com")).toBe(false);
    expect(matchHostPattern("evil-example.com", "*.example.com")).toBe(false);
  });

  it("matchesAnyHost across a list", () => {
    expect(matchesAnyHost("x.foo.com", ["bar.com", "*.foo.com"])).toBe(true);
    expect(matchesAnyHost("foo.com", ["*.foo.com"])).toBe(false);
    expect(matchesAnyHost("foo.com", [])).toBe(false);
  });
});

describe("loadPolicy — config-file lifecycle (SPEC §4.1)", () => {
  const dataDir = "/data";

  it("missing file → defaults, written back to config.json", () => {
    const fs = inMemoryFs();
    const base = defaultPolicy();
    const res = loadPolicy(dataDir, { fs }, base);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.policy.caps.dailyUsd).toBe(DAILY_CAP_DEFAULT_USD);
    // written back so the operator can see/edit it
    const written = fs.readText(configPath(dataDir));
    expect(written).not.toBeNull();
    expect(JSON.parse(written!).schema).toBe("p3f.policy.v1");
  });

  it("invalid JSON → FAIL CLOSED (never silent defaults)", () => {
    const fs = inMemoryFs();
    fs.writeText(configPath(dataDir), "{ this is not json ");
    const res = loadPolicy(dataDir, { fs }, defaultPolicy());
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/not valid JSON/i);
  });

  it("a lowered cap the operator set is honored (present field wins)", () => {
    const fs = inMemoryFs();
    fs.writeText(
      configPath(dataDir),
      JSON.stringify({ schema: "p3f.policy.v1", caps: { dailyUsd: 0.5 } }),
    );
    const res = loadPolicy(dataDir, { fs }, defaultPolicy());
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.policy.caps.dailyUsd).toBe(0.5); // operator value
      expect(res.policy.caps.perCallUsd).toBe(PER_CALL_CAP_DEFAULT_USD); // absent → default
    }
  });

  it("a wrong-typed field → FAIL CLOSED (a typo must not restore defaults)", () => {
    const fs = inMemoryFs();
    fs.writeText(
      configPath(dataDir),
      JSON.stringify({ schema: "p3f.policy.v1", caps: { dailyUsd: "lots" } }),
    );
    const res = loadPolicy(dataDir, { fs }, defaultPolicy());
    expect(res.ok).toBe(false);
  });

  it("wrong schema tag → fail closed", () => {
    expect(() => validateConfig({ schema: "wrong" }, defaultPolicy())).toThrow();
  });
});

describe("validateConfig — P3 pre-approval + onDegraded fields (SPEC §6/§7.3)", () => {
  it("defaults are OFF / block — pre-approval null/[], onDegraded 'block'", () => {
    const p = defaultPolicy();
    expect(p.approval.preApprovedUpToUsd).toBeNull();
    expect(p.approval.preApprovedHosts).toEqual([]);
    expect(p.guards.safety.onDegraded).toBe("block");
  });

  it("accepts valid pre-approval + onDegraded values", () => {
    const v = validateConfig(
      {
        schema: "p3f.policy.v1",
        approval: { preApprovedUpToUsd: 0.5, preApprovedHosts: ["*.vendor.com"] },
        guards: { safety: { onDegraded: "warn" } },
      },
      defaultPolicy(),
    );
    expect(v.approval.preApprovedUpToUsd).toBe(0.5);
    expect(v.approval.preApprovedHosts).toEqual(["*.vendor.com"]);
    expect(v.guards.safety.onDegraded).toBe("warn");
  });

  it("preApprovedUpToUsd null is honored (explicit OFF)", () => {
    const v = validateConfig(
      { schema: "p3f.policy.v1", approval: { preApprovedUpToUsd: null } },
      defaultPolicy(),
    );
    expect(v.approval.preApprovedUpToUsd).toBeNull();
  });

  it("a negative preApprovedUpToUsd → FAIL CLOSED", () => {
    expect(() =>
      validateConfig(
        { schema: "p3f.policy.v1", approval: { preApprovedUpToUsd: -1 } },
        defaultPolicy(),
      ),
    ).toThrow();
  });

  it("an unknown onDegraded enum → FAIL CLOSED", () => {
    expect(() =>
      validateConfig(
        { schema: "p3f.policy.v1", guards: { safety: { onDegraded: "sometimes" } } },
        defaultPolicy(),
      ),
    ).toThrow();
  });

  it("WARNS (does not throw) when preApprovedUpToUsd exceeds perCallUsd — a no-op fat-finger", () => {
    const warnings: string[] = [];
    const v = validateConfig(
      {
        schema: "p3f.policy.v1",
        caps: { perCallUsd: 1 },
        approval: { preApprovedUpToUsd: 5 }, // > per-call cap ⇒ the excess never fires
      },
      defaultPolicy(),
      (m) => warnings.push(m),
    );
    // Still a valid policy (not fail-closed) — the config is strictly SAFER than it reads.
    expect(v.approval.preApprovedUpToUsd).toBe(5);
    expect(v.caps.perCallUsd).toBe(1);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/preApprovedUpToUsd/);
    expect(warnings[0]).toMatch(/perCallUsd/);
  });

  it("does NOT warn when preApprovedUpToUsd is within perCallUsd (or OFF)", () => {
    const warnings: string[] = [];
    validateConfig(
      {
        schema: "p3f.policy.v1",
        caps: { perCallUsd: 5 },
        approval: { preApprovedUpToUsd: 1 }, // ≤ per-call cap ⇒ meaningful
      },
      defaultPolicy(),
      (m) => warnings.push(m),
    );
    // Default (preApprovedUpToUsd = null ⇒ OFF) never warns either.
    validateConfig({ schema: "p3f.policy.v1" }, defaultPolicy(), (m) => warnings.push(m));
    expect(warnings).toHaveLength(0);
  });

  it("mergePolicy carries pre-approval + onDegraded, copying the host array (not the frozen ref)", () => {
    const merged = mergePolicy(defaultPolicy(), {
      approval: { preApprovedHosts: ["a.com"] },
      guards: { safety: { onDegraded: "proceed" } },
    });
    expect(merged.approval.preApprovedHosts).toEqual(["a.com"]);
    expect(merged.guards.safety.onDegraded).toBe("proceed");
    expect(merged.approval.preApprovedHosts).not.toBe(defaultPolicy().approval.preApprovedHosts);
  });
});

describe("mergePolicy — programmatic overrides over defaults (SPEC §10)", () => {
  it("deep-merges caps and lists without dropping other defaults", () => {
    const merged = mergePolicy(defaultPolicy(), {
      mode: "allowlist",
      allow: ["*.foo.com"],
      caps: { dailyUsd: 5 },
    });
    expect(merged.mode).toBe("allowlist");
    expect(merged.allow).toEqual(["*.foo.com"]);
    expect(merged.caps.dailyUsd).toBe(5);
    expect(merged.caps.perCallUsd).toBe(PER_CALL_CAP_DEFAULT_USD);
    expect(merged.guards.trust.enabled).toBe(true);
  });
});
