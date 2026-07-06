/**
 * P3′ payfetch — guard suite (SPEC §14 guard scope, IN FULL). Hermetic: no
 * network; a `ScriptedGuardFetch` serves real-shape P2/P1 bodies.
 *
 * Coverage (SPEC §14 "Guards"):
 *  - {advisory, enforce} × {pass, warn, block, unavailable(402/timeout/5xx/
 *    network/malformed/crash)} for BOTH guards.
 *  - unrated pass + blockUnrated flip; minScore boundary (== passes, below
 *    warns/blocks, null score ⇒ minScore ignored).
 *  - Integration header EXACT format (with/without via); Accept header.
 *  - query stripped from the trust guard URL (GUARD_SEND_QUERY frozen note).
 *  - baseUrl null ⇒ unavailable with ZERO guardFetch calls (count-asserted).
 *  - safety depth default "basic" (basic route, mint in the GET query); deployer
 *    mapping ONLY at deep; applies() false without tokenAddress.
 *  - a guard NEVER throws (crash ⇒ unavailable, check() resolves).
 *  - advisory NEVER returns "block" (property over the matrix).
 */

import { describe, expect, it, vi } from "vitest";

import {
  FETCH_TIMEOUT_MS,
  GUARD_ADVISORY_BUDGET_MS,
  GUARD_SCREEN_BUDGET_MS,
  GUARD_SEND_QUERY,
  INTEGRATION_HEADER,
} from "../src/core/constants.js";
import { createSafetyGuard, createTrustGuard } from "../src/guards/index.js";
import { integrationHeaderValue } from "../src/guards/internal.js";
import type { GuardResult, PrePayGuard } from "../src/guards/types.js";
import { fakeDeps } from "./fakes.js";
import {
  FakeP1,
  P1_SCREEN_DEEP_PATH,
  P1_SCREEN_PATH,
  ScriptedGuardFetch,
  gAbort,
  gDelayJson,
  gHang,
  gJson,
  gMalformed,
  gNetwork,
  gStatus,
  gThrow,
  guardInput,
  guardRuntime,
  safetyBasic,
  safetyConfig,
  safetyDeep,
  safetyDegraded,
  safetyPayload,
  scaffoldEnvelope,
  trustConfig,
  trustMixed,
  trustPayload,
  trustReliable,
  trustScore,
  trustUnrated,
  trustUnreliable,
} from "./fakes_guards.js";

const DEPS = fakeDeps();
const HEADER_KEY = INTEGRATION_HEADER.toLowerCase(); // Web Headers lowercases keys

/** Run a guard's check() (the PrePayGuard interface requires a deps arg the guard ignores). */
function run(guard: PrePayGuard, input = guardInput()): Promise<GuardResult> {
  return guard.check(input, DEPS);
}

// ===========================================================================
// Integration header (THESIS §7 instrument) — EXACT format
// ===========================================================================

describe("integration header", () => {
  it("emits payfetch/1;i={installId8} without via", () => {
    expect(integrationHeaderValue("abcd1234", null)).toBe("payfetch/1;i=abcd1234");
  });

  it("appends ;via={slug} when via is set", () => {
    expect(integrationHeaderValue("abcd1234", "langchain")).toBe(
      "payfetch/1;i=abcd1234;via=langchain",
    );
  });

  it("omits ;via for an empty slug (treated as unset)", () => {
    expect(integrationHeaderValue("abcd1234", "")).toBe("payfetch/1;i=abcd1234");
  });

  it("trust guard sends the exact header + Accept: application/json", async () => {
    const fetch = new ScriptedGuardFetch(gJson(trustReliable()));
    const guard = createTrustGuard(trustConfig(), guardRuntime({ guardFetch: fetch.fetch }));
    await run(guard);
    const req = fetch.requests[0];
    expect(req.headers[HEADER_KEY]).toBe("payfetch/1;i=abcd1234");
    expect(req.headers["accept"]).toBe("application/json");
  });

  it("trust guard appends via when the runtime carries one", async () => {
    const fetch = new ScriptedGuardFetch(gJson(trustReliable()));
    const guard = createTrustGuard(
      trustConfig(),
      guardRuntime({ guardFetch: fetch.fetch, installId8: "deadbeef", via: "crewai" }),
    );
    await run(guard);
    expect(fetch.requests[0].headers[HEADER_KEY]).toBe("payfetch/1;i=deadbeef;via=crewai");
  });

  it("safety guard sends the header + Accept on its GET (no body, no Content-Type)", async () => {
    const p1 = new FakeP1(); // contract-enforcing: a wrong request would 4xx here
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true }),
      guardRuntime({ guardFetch: p1.fetch }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtoken" } }));
    expect(r.verdict).toBe("pass"); // the hardened fake ACCEPTED the request
    const req = p1.requests[0];
    expect(req.method).toBe("GET");
    expect(req.body).toBeNull(); // no request body on a GET
    expect(req.headers[HEADER_KEY]).toBe("payfetch/1;i=abcd1234");
    expect(req.headers["accept"]).toBe("application/json");
    expect(req.headers["content-type"]).toBeUndefined(); // no body ⇒ no Content-Type
  });
});

// ===========================================================================
// Query stripping (THESIS §9) — trust guard target URL
// ===========================================================================

describe("query stripping (trust guard target)", () => {
  it("strips the query string from the ?url= target", async () => {
    const fetch = new ScriptedGuardFetch(gJson(trustReliable()));
    const guard = createTrustGuard(trustConfig(), guardRuntime({ guardFetch: fetch.fetch }));
    await run(guard, guardInput({ url: "https://api.example.com/data?secret=shhh&page=2" }));

    const sent = new URL(fetch.requests[0].url);
    const target = sent.searchParams.get("url");
    expect(target).toBe("https://api.example.com/data");
    expect(fetch.requests[0].url).not.toContain("secret");
  });

  it("GUARD_SEND_QUERY is the frozen `false` that drives stripping", () => {
    // The "not stripped" branch is only reachable by mutating a FROZEN constant
    // (SPEC §15) — untestable without violating the freeze, so we assert the
    // constant's value and the stripping behavior above instead (task note).
    expect(GUARD_SEND_QUERY).toBe(false);
  });
});

// ===========================================================================
// baseUrl null ⇒ unavailable WITHOUT fetching (count-asserted, SPEC §7.5)
// ===========================================================================

describe("baseUrl null ⇒ unavailable, zero guardFetch calls", () => {
  it("trust", async () => {
    const fetch = new ScriptedGuardFetch(gJson(trustReliable()));
    const guard = createTrustGuard(
      trustConfig({ mode: "enforce" }),
      guardRuntime({ guardFetch: fetch.fetch, baseUrls: { trust: null } }),
    );
    const r = await run(guard);
    expect(r.verdict).toBe("unavailable");
    expect(fetch.callCount).toBe(0);
  });

  it("safety", async () => {
    const fetch = new ScriptedGuardFetch(gJson(safetyBasic("safe")));
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: fetch.fetch, baseUrls: { safety: null } }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtoken" } }));
    expect(r.verdict).toBe("unavailable");
    expect(fetch.callCount).toBe(0);
  });
});

// ===========================================================================
// Trust guard — applies() + verdict mapping (SPEC §7.2)
// ===========================================================================

describe("trust guard — applies()", () => {
  it("always applies (even without a token)", () => {
    const guard = createTrustGuard(trustConfig(), guardRuntime());
    expect(guard.applies(guardInput({ context: {} }))).toBe(true);
    expect(guard.id).toBe("trust");
  });
});

describe("trust guard — verdict mapping (advisory)", () => {
  const mk = (body: unknown): PrePayGuard =>
    createTrustGuard(
      trustConfig({ mode: "advisory" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
    );

  it("reliable ⇒ pass, detail carries {score, verdict, counts}", async () => {
    const r = await run(mk(trustReliable()));
    expect(r.verdict).toBe("pass");
    expect(r.detail.score).toBe(88);
    expect(r.detail.verdict).toBe("reliable");
    expect(r.detail.counts).toBeTypeOf("object");
    expect(r.costUsd).toBe(0);
    expect(r.id).toBe("trust");
  });

  it("mixed ⇒ pass", async () => {
    expect((await run(mk(trustMixed()))).verdict).toBe("pass");
  });

  it("unreliable ⇒ warn (advisory NEVER blocks)", async () => {
    expect((await run(mk(trustUnreliable()))).verdict).toBe("warn");
  });

  it("unrated ⇒ pass + guard_unrated note in detail", async () => {
    const r = await run(mk(trustUnrated()));
    expect(r.verdict).toBe("pass");
    expect(r.detail.notes).toEqual(["guard_unrated"]);
  });
});

describe("trust guard — verdict mapping (enforce)", () => {
  const mk = (body: unknown, over = {}): PrePayGuard =>
    createTrustGuard(
      trustConfig({ mode: "enforce", ...over }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
    );

  it("unreliable ⇒ block", async () => {
    expect((await run(mk(trustUnreliable()))).verdict).toBe("block");
  });

  it("reliable ⇒ pass", async () => {
    expect((await run(mk(trustReliable()))).verdict).toBe("pass");
  });

  it("unrated ⇒ pass by default (honest-unknown)", async () => {
    expect((await run(mk(trustUnrated()))).verdict).toBe("pass");
  });

  it("unrated + blockUnrated ⇒ block (enforce)", async () => {
    expect((await run(mk(trustUnrated(), { blockUnrated: true }))).verdict).toBe("block");
  });

  it("custom blockVerdicts flips mixed ⇒ block", async () => {
    expect((await run(mk(trustMixed(), { blockVerdicts: ["mixed"] }))).verdict).toBe("block");
  });
});

it("trust unrated + blockUnrated in advisory ⇒ warn (not block)", async () => {
  const guard = createTrustGuard(
    trustConfig({ mode: "advisory", blockUnrated: true }),
    guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(trustUnrated())).fetch }),
  );
  expect((await run(guard)).verdict).toBe("warn");
});

// ===========================================================================
// Trust guard — minScore boundary (SPEC §7.2)
// ===========================================================================

describe("trust guard — minScore boundary", () => {
  const mkEnforce = (score: number | null, minScore: number | null, verdict = "mixed") =>
    createTrustGuard(
      trustConfig({ mode: "enforce", minScore, blockVerdicts: [] }),
      guardRuntime({
        guardFetch: new ScriptedGuardFetch(gJson(trustScore({ verdict, score }))).fetch,
      }),
    );

  it("score exactly at minScore ⇒ pass", async () => {
    expect((await run(mkEnforce(80, 80))).verdict).toBe("pass");
  });

  it("score below minScore ⇒ block (enforce)", async () => {
    expect((await run(mkEnforce(79, 80))).verdict).toBe("block");
  });

  it("score below minScore ⇒ warn (advisory)", async () => {
    const guard = createTrustGuard(
      trustConfig({ mode: "advisory", minScore: 80, blockVerdicts: [] }),
      guardRuntime({
        guardFetch: new ScriptedGuardFetch(gJson(trustScore({ verdict: "mixed", score: 79 }))).fetch,
      }),
    );
    expect((await run(guard)).verdict).toBe("warn");
  });

  it("score null ⇒ minScore ignored (unrated ⇒ pass)", async () => {
    // unrated carries score:null; minScore must NOT fire on a null score.
    const guard = createTrustGuard(
      trustConfig({ mode: "enforce", minScore: 80 }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(trustUnrated())).fetch }),
    );
    expect((await run(guard)).verdict).toBe("pass");
  });
});

// ===========================================================================
// Trust guard — unavailable matrix (SPEC §7.2), advisory + enforce
// ===========================================================================

describe("trust guard — unavailable matrix (verdict is mode-agnostic)", () => {
  const cases: Array<[string, ScriptedGuardFetch]> = [
    ["402", new ScriptedGuardFetch(gStatus(402))],
    ["5xx", new ScriptedGuardFetch(gStatus(500))],
    ["network", new ScriptedGuardFetch(gNetwork())],
    ["malformed JSON", new ScriptedGuardFetch(gMalformed())],
    ["timeout (abort)", new ScriptedGuardFetch(gAbort())],
    ["crash (sync throw)", new ScriptedGuardFetch(gThrow())],
    ["malformed body (no verdict)", new ScriptedGuardFetch(gJson({ ok: true }))],
  ];

  for (const mode of ["advisory", "enforce"] as const) {
    for (const [label, fetch] of cases) {
      it(`${mode}: ${label} ⇒ unavailable`, async () => {
        const guard = createTrustGuard(
          trustConfig({ mode }),
          guardRuntime({ guardFetch: fetch.fetch }),
        );
        const r = await run(guard);
        expect(r.verdict).toBe("unavailable"); // guard NEVER resolves proceed/block
      });
    }
  }
});

// ===========================================================================
// Safety guard — applies() (SPEC §7.3)
// ===========================================================================

describe("safety guard — applies()", () => {
  const guard = createSafetyGuard(safetyConfig({ enabled: true }), guardRuntime());

  it("false without tokenAddress", () => {
    expect(guard.applies(guardInput({ context: {} }))).toBe(false);
  });

  it("false for an empty tokenAddress", () => {
    expect(guard.applies(guardInput({ context: { tokenAddress: "" } }))).toBe(false);
  });

  it("true with a tokenAddress", () => {
    expect(guard.applies(guardInput({ context: { tokenAddress: "0xtok" } }))).toBe(true);
    expect(guard.id).toBe("safety");
  });
});

// ===========================================================================
// Safety guard — request contract (SPEC §7.3, P1's REAL contract): GET with
// ?mint=&chain= in the QUERY — NEVER `token`, NEVER a `depth` param; the ROUTE
// carries the tier; NO request body. Driven through the contract-enforcing
// FakeP1 (a drift back to POST/body 4xxs → the suite fails).
// ===========================================================================

describe("safety guard — request contract (mint query + tier routes)", () => {
  it("basic: GET /v1/safety/screen?mint=…&chain=solana (chain defaulted), no body", async () => {
    const p1 = new FakeP1();
    const guard = createSafetyGuard(safetyConfig({ enabled: true }), guardRuntime({ guardFetch: p1.fetch }));
    const r = await run(guard, guardInput({ context: { tokenAddress: "MintAddr111" } }));

    expect(r.verdict).toBe("pass"); // hardened fake accepted the request
    const req = p1.requests[0];
    expect(req.method).toBe("GET");
    expect(req.body).toBeNull(); // GET carries no body
    const sent = new URL(req.url);
    expect(sent.pathname).toBe(P1_SCREEN_PATH);
    expect(sent.searchParams.get("mint")).toBe("MintAddr111");
    expect(sent.searchParams.get("chain")).toBe("solana"); // default
    // exact query — mint + chain only, no token, no depth param
    expect([...sent.searchParams.keys()].sort()).toEqual(["chain", "mint"]);
  });

  it("deep: GET /v1/safety/screen/deep?mint=…&chain=… (explicit chain), no body", async () => {
    const p1 = new FakeP1();
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, depth: "deep" }),
      guardRuntime({ guardFetch: p1.fetch }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xToken", chain: "base" } }));

    expect(r.verdict).toBe("pass");
    const req = p1.requests[0];
    expect(req.method).toBe("GET");
    expect(req.body).toBeNull();
    const sent = new URL(req.url);
    expect(sent.pathname).toBe(P1_SCREEN_DEEP_PATH);
    expect(sent.searchParams.get("mint")).toBe("0xToken");
    expect(sent.searchParams.get("chain")).toBe("base"); // explicit chain honored
    expect([...sent.searchParams.keys()].sort()).toEqual(["chain", "mint"]);
  });

  it("REGRESSION TRIPWIRE (fake level): a legacy POST+body call is rejected 405", async () => {
    // The OLD contract was POST {mint,chain} as a JSON body. The fake now
    // enforces GET+query, so a POST is a 405 (method_not_allowed) before any
    // field check — a guard drifting back to POST is caught here, not live.
    const p1 = new FakeP1();
    const res = await p1.fetch(`https://safety.p1.example${P1_SCREEN_PATH}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mint: "MintAddr111", chain: "solana" }),
    });
    expect(res.status).toBe(405);
    expect(await res.json()).toEqual({ error: "method_not_allowed" });
  });

  it("REGRESSION TRIPWIRE (fake level): a GET missing the `mint` query is rejected 400 (zod-style)", async () => {
    // e.g. a legacy call that put the address in a body rather than the query.
    const p1 = new FakeP1();
    const res = await p1.fetch(`https://safety.p1.example${P1_SCREEN_PATH}?chain=solana`, {
      method: "GET",
    });
    expect(res.status).toBe(400);
    const err = (await res.json()) as { error: string; issues: Array<{ path: string[] }> };
    expect(err.error).toBe("invalid_request");
    expect(err.issues[0].path).toEqual(["mint"]);
  });

  it("REGRESSION TRIPWIRE (guard level): a guard drifting back to POST+body goes 405 → unavailable", async () => {
    // Simulate the OLD buggy guard by rewriting the outgoing GET+query into a
    // POST+JSON-body call before it reaches the contract-enforcing fake. If the
    // real guard ever regresses this way, every FakeP1-driven test above fails.
    const p1 = new FakeP1();
    const legacyRewrite: typeof p1.fetch = (url, init) => {
      const u = new URL(url);
      const body = JSON.stringify({
        mint: u.searchParams.get("mint"),
        chain: u.searchParams.get("chain"),
      });
      return p1.fetch(`${u.origin}${u.pathname}`, {
        method: "POST",
        headers: { ...(init?.headers as Record<string, string>), "content-type": "application/json" },
        body,
      });
    };
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: legacyRewrite }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "MintAddr111" } }));
    expect(r.verdict).toBe("unavailable"); // 405 → unavailable, never a guess
    expect(r.detail.reason).toBe("http_405");
  });

  it("basic route ignores any depth hint and never returns a deployer block", async () => {
    // Even a fake configured with a blockable deployer verdict serves NO
    // deployer on the basic route — so a basic-depth guard passes.
    const p1 = new FakeP1({ deployerVerdict: "serial_rugger" });
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce", depth: "basic" }),
      guardRuntime({ guardFetch: p1.fetch }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtok" } }));
    expect(r.verdict).toBe("pass");
    expect(r.detail.deployer).toBeNull();
  });
});

// ===========================================================================
// Safety guard — verdict mapping (SPEC §7.3), incl. deployer-only-at-deep
// ===========================================================================

describe("safety guard — verdict mapping (driven through the contract-enforcing FakeP1)", () => {
  const withToken = guardInput({ context: { tokenAddress: "0xtok" } });
  const mkP1 = (
    p1: ConstructorParameters<typeof FakeP1>[0],
    over: Parameters<typeof safetyConfig>[0] = {},
  ): PrePayGuard =>
    createSafetyGuard(
      safetyConfig({ enabled: true, ...over }),
      guardRuntime({ guardFetch: new FakeP1(p1).fetch }),
    );

  it("basic safe ⇒ pass; detail carries {verdict, score, deployer:null}", async () => {
    const r = await run(mkP1({ verdict: "safe" }), withToken);
    expect(r.verdict).toBe("pass");
    expect(r.detail.verdict).toBe("safe");
    expect(r.detail.score).toBe(90);
    expect(r.detail.deployer).toBeNull();
  });

  it("basic danger ⇒ block (enforce)", async () => {
    expect((await run(mkP1({ verdict: "danger" }), withToken)).verdict).toBe("block");
  });

  it("basic danger ⇒ warn (advisory NEVER blocks)", async () => {
    expect((await run(mkP1({ verdict: "danger" }, { mode: "advisory" }), withToken)).verdict).toBe(
      "warn",
    );
  });

  it("basic unknown ⇒ pass + guard_unrated note", async () => {
    const r = await run(mkP1({ verdict: "unknown" }), withToken);
    expect(r.verdict).toBe("pass");
    expect(r.detail.notes).toEqual(["guard_unrated"]);
  });

  it("deep: safe token + serial_rugger deployer ⇒ block (enforce)", async () => {
    const r = await run(
      mkP1({ verdict: "safe", deployerVerdict: "serial_rugger" }, { depth: "deep" }),
      withToken,
    );
    expect(r.verdict).toBe("block");
  });

  it("deep: safe token + clean deployer ⇒ pass", async () => {
    const r = await run(
      mkP1({ verdict: "safe", deployerVerdict: "clean" }, { depth: "deep" }),
      withToken,
    );
    expect(r.verdict).toBe("pass");
  });

  it("deep: insufficient_history deployer ⇒ pass + guard_unrated note", async () => {
    const r = await run(
      mkP1({ verdict: "safe", deployerVerdict: "insufficient_history" }, { depth: "deep" }),
      withToken,
    );
    expect(r.verdict).toBe("pass");
    expect(r.detail.notes).toEqual(["guard_unrated"]);
  });

  it("token danger wins even when deployer is clean (deep)", async () => {
    const r = await run(
      mkP1({ verdict: "danger", deployerVerdict: "clean" }, { depth: "deep" }),
      withToken,
    );
    expect(r.verdict).toBe("block");
  });

  it("defensive mapping: a deployer block in a response is IGNORED at basic depth", async () => {
    // Guard-internal defense (hostile/mismatched server): even if a basic-depth
    // call somehow received a deployer block, the mapping must not fire it
    // (SPEC §7.3: deployer applies at deep only). Scripted fake on purpose —
    // the real P1 basic route never serves this shape (asserted above).
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce", depth: "basic" }),
      guardRuntime({
        guardFetch: new ScriptedGuardFetch(gJson(safetyDeep("safe", "serial_rugger"))).fetch,
      }),
    );
    expect((await run(guard, withToken)).verdict).toBe("pass");
  });
});

// ===========================================================================
// Safety guard — dim5-MED: fail-closed on a DEGRADED screen (SPEC §7.3, the
// cross-product contract). P1's basic screen sets `degraded: true` when a
// danger-relevant upstream was capped/absent; an inconclusive verdict
// (unknown/caution) may then be UNDER-calling danger. In ENFORCE mode the guard
// surfaces it as "unavailable" so the pipeline fails closed; advisory keeps
// proceeding (nothing to fail closed); a conclusive/blocked verdict is unaffected.
// ===========================================================================

describe("safety guard — degraded-screen fail-closed (dim5-MED)", () => {
  const withToken = guardInput({ context: { tokenAddress: "0xtok" } });
  const mk = (body: unknown, mode: "advisory" | "enforce", depth: "basic" | "deep" = "basic"): PrePayGuard =>
    createSafetyGuard(
      safetyConfig({ enabled: true, mode, depth }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
    );

  it("enforce + degraded unknown ⇒ unavailable (reason degraded_screen)", async () => {
    const r = await run(mk(safetyDegraded("unknown"), "enforce"), withToken);
    expect(r.verdict).toBe("unavailable");
    expect(r.detail.reason).toBe("degraded_screen");
  });

  it("enforce + degraded caution ⇒ unavailable", async () => {
    expect((await run(mk(safetyDegraded("caution"), "enforce"), withToken)).verdict).toBe("unavailable");
  });

  it("enforce + degraded SAFE ⇒ pass (a conclusive verdict is not fail-closed)", async () => {
    expect((await run(mk(safetyDegraded("safe"), "enforce"), withToken)).verdict).toBe("pass");
  });

  it("enforce + degraded DANGER ⇒ block (a real danger still blocks; degrade never downgrades it)", async () => {
    expect((await run(mk(safetyDegraded("danger"), "enforce"), withToken)).verdict).toBe("block");
  });

  it("enforce + CLEAN (non-degraded) unknown ⇒ pass + guard_unrated (honest unknown unaffected)", async () => {
    const r = await run(mk(safetyBasic("unknown"), "enforce"), withToken);
    expect(r.verdict).toBe("pass");
    expect(r.detail.notes).toEqual(["guard_unrated"]);
  });

  it("advisory + degraded unknown ⇒ pass (advisory never blocks — nothing to fail closed)", async () => {
    expect((await run(mk(safetyDegraded("unknown"), "advisory"), withToken)).verdict).toBe("pass");
  });

  it("HOT-RELOAD: a guard BUILT advisory fails a degraded unknown closed when the LIVE config is enforce", async () => {
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "advisory" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(safetyDegraded("unknown"))).fetch }),
    );
    const liveEnforce = safetyConfig({ enabled: true, mode: "enforce" });
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtok" }, config: liveEnforce }));
    expect(r.verdict).toBe("unavailable"); // live enforce ⇒ fail-closed; captured advisory ⇒ pass
  });
});

// ===========================================================================
// Safety guard — unavailable matrix (SPEC §7.3)
// ===========================================================================

describe("safety guard — unavailable matrix", () => {
  const withToken = guardInput({ context: { tokenAddress: "0xtok" } });
  const cases: Array<[string, () => ScriptedGuardFetch]> = [
    ["402", () => new ScriptedGuardFetch(gStatus(402))],
    ["5xx", () => new ScriptedGuardFetch(gStatus(503))],
    ["network", () => new ScriptedGuardFetch(gNetwork())],
    ["malformed JSON", () => new ScriptedGuardFetch(gMalformed())],
    ["timeout (abort)", () => new ScriptedGuardFetch(gAbort())],
    ["crash (sync throw)", () => new ScriptedGuardFetch(gThrow())],
  ];

  for (const mode of ["advisory", "enforce"] as const) {
    for (const [label, make] of cases) {
      it(`${mode}: ${label} ⇒ unavailable`, async () => {
        const guard = createSafetyGuard(
          safetyConfig({ enabled: true, mode }),
          guardRuntime({ guardFetch: make().fetch }),
        );
        expect((await run(guard, withToken)).verdict).toBe("unavailable");
      });
    }
  }
});

// ===========================================================================
// Scaffold response envelope (SPEC §7.2) — guards unwrap `.data`; tolerant of
// a bare payload. Regression: a flat fake hid this; live P2/P1 wrap the payload.
// ===========================================================================

describe("scaffold envelope unwrap", () => {
  it("trust: a LIVE-shaped enveloped unrated body ⇒ pass + guard_unrated (not unavailable)", async () => {
    // The exact live P2 shape: {data:{verdict,score,known,notes,thresholdsVersion},freshnessTs,disclaimer}.
    const live = scaffoldEnvelope({
      verdict: "unrated",
      score: null,
      known: false,
      notes: ["insufficient_history"],
      thresholdsVersion: "p2t-score-1.0.0",
    });
    const guard = createTrustGuard(
      trustConfig({ mode: "advisory" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(live)).fetch }),
    );
    const r = await run(guard);
    expect(r.verdict).toBe("pass");
    expect(r.detail.verdict).toBe("unrated");
    expect(r.detail.notes).toEqual(["guard_unrated"]);
  });

  it("trust: enveloped unreliable ⇒ block (enforce) — the score/verdict come from .data", async () => {
    const guard = createTrustGuard(
      trustConfig({ mode: "enforce" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(trustUnreliable())).fetch }),
    );
    expect((await run(guard)).verdict).toBe("block");
  });

  it("trust: a BARE (un-enveloped) payload STILL parses (tolerant fallback)", async () => {
    const guard = createTrustGuard(
      trustConfig({ mode: "advisory" }),
      guardRuntime({
        guardFetch: new ScriptedGuardFetch(gJson(trustPayload({ verdict: "unrated", score: null }))).fetch,
      }),
    );
    const r = await run(guard);
    expect(r.verdict).toBe("pass");
    expect(r.detail.notes).toEqual(["guard_unrated"]);
  });

  it("safety: an enveloped deep response ⇒ deployer block read from .data.deployer", async () => {
    // FakeP1 serves the enveloped wire shape; the deployer block lives in .data.
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce", depth: "deep" }),
      guardRuntime({
        guardFetch: new FakeP1({ verdict: "safe", deployerVerdict: "serial_rugger" }).fetch,
      }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtok" } }));
    expect(r.verdict).toBe("block");
    expect((r.detail.deployer as { verdict: string }).verdict).toBe("serial_rugger");
  });

  it("safety: a BARE (un-enveloped) payload STILL parses (tolerant fallback)", async () => {
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({
        guardFetch: new ScriptedGuardFetch(gJson(safetyPayload({ verdict: "danger", deployer: null }))).fetch,
      }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtok" } }));
    expect(r.verdict).toBe("block");
    expect(r.detail.verdict).toBe("danger");
  });
});

// ===========================================================================
// A guard NEVER throws (SPEC §7.4) — check() resolves, never rejects
// ===========================================================================

describe("a guard never throws", () => {
  it("trust: a throwing guardFetch ⇒ resolves unavailable", async () => {
    const guard = createTrustGuard(
      trustConfig({ mode: "enforce" }),
      guardRuntime({
        guardFetch: () => {
          throw new Error("boom");
        },
      }),
    );
    await expect(run(guard)).resolves.toMatchObject({ verdict: "unavailable" });
  });

  it("safety: a throwing guardFetch ⇒ resolves unavailable", async () => {
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({
        guardFetch: () => {
          throw new Error("boom");
        },
      }),
    );
    await expect(
      run(guard, guardInput({ context: { tokenAddress: "0xtok" } })),
    ).resolves.toMatchObject({ verdict: "unavailable" });
  });
});

// ===========================================================================
// Mode-scoped guard budget (SPEC §7.1/§7.5) — the cold-screen timeout fix.
//
// The confirmed go-live blocker: a cache-cold FIRST-TOUCH P1 screen genuinely
// computes past the retired 2000ms box (re-measured ESCALATED cold p99 ~10.7s on
// quiet Helius — the v1.3.x recall escalation fans out extra cold Helius work), so
// the enforce safety guard timed out and fail-closed on every novel token — it could
// never actually GET `danger` and block. The fix: enforce gets the generous
// GUARD_SCREEN_BUDGET_MS (13000ms), advisory proceeds fast at
// GUARD_ADVISORY_BUDGET_MS (2000ms), and a genuinely dead host still fails fast.
// ===========================================================================

// Re-measured ESCALATED cold P1 screen near-p99 (~10.7s, quiet Helius, incl. the
// v1.3.x escalation class: S1 create-filter + ALGO-1 aged walk + S2 curve batch) —
// the realistic cold latency a legit first-touch token takes. Sits comfortably INSIDE
// the 13000ms enforce budget (proving it covers the p99) and far OUTSIDE the 2000ms
// advisory budget.
const COLD_SCREEN_MS = 10_700;

describe("mode-scoped guard budget (cold-screen timeout fix)", () => {
  it("enforce safety: a slow-but-progressing COLD screen (~10.7s) completes inside the 13s budget ⇒ real danger BLOCKS", async () => {
    vi.useFakeTimers();
    try {
      // The primary blocker case: a novel (cache-cold) token whose screen returns
      // `danger` only after ~10.7s (re-measured escalated cold p99). With the 2000ms
      // box this timed out → unavailable (fail-closed, never a true detection). With
      // the 13000ms enforce budget it runs to completion and the guard BLOCKS on danger.
      const guard = createSafetyGuard(
        safetyConfig({ enabled: true, mode: "enforce" }),
        guardRuntime({
          guardFetch: new ScriptedGuardFetch(gDelayJson(COLD_SCREEN_MS, safetyBasic("danger"))).fetch,
        }),
      );
      const p = run(guard, guardInput({ context: { tokenAddress: "0xtok" } }));
      await vi.advanceTimersByTimeAsync(COLD_SCREEN_MS);
      const r = await p;
      expect(r.verdict).toBe("block"); // cold `danger` DETECTED + blocked — not a timeout
      expect(r.detail).toMatchObject({ verdict: "danger" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("enforce: a hung host is NOT cut at the old 2s box — it tolerates a slow screen up to the 13s budget, then aborts ⇒ unavailable", async () => {
    vi.useFakeTimers();
    try {
      const guard = createSafetyGuard(
        safetyConfig({ enabled: true, mode: "enforce" }),
        guardRuntime({ guardFetch: new ScriptedGuardFetch(gHang()).fetch }),
      );
      const p = run(guard, guardInput({ context: { tokenAddress: "0xtok" } }));
      let settled = false;
      void p.then(() => {
        settled = true;
      });
      // At the RETIRED 2000ms box the enforce guard must still be waiting (else we
      // would be re-cutting cold screens — the blocker).
      await vi.advanceTimersByTimeAsync(GUARD_ADVISORY_BUDGET_MS);
      expect(settled).toBe(false);
      // The generous screen budget is the backstop for a genuinely wedged host.
      await vi.advanceTimersByTimeAsync(GUARD_SCREEN_BUDGET_MS - GUARD_ADVISORY_BUDGET_MS);
      expect((await p).verdict).toBe("unavailable");
    } finally {
      vi.useRealTimers();
    }
  });

  it("advisory trust: a slow screen is abandoned fast (2s), the payment is NOT stalled ~13s ⇒ unavailable (pipeline proceeds)", async () => {
    vi.useFakeTimers();
    try {
      // The default-ON trust guard is advisory: on unavailable it PROCEEDS, so it
      // must not hold a first-touch payment for the full enforce budget. A screen
      // that would answer at ~10.7s is cut at the 2000ms advisory budget.
      const guard = createTrustGuard(
        trustConfig({ mode: "advisory" }),
        guardRuntime({
          guardFetch: new ScriptedGuardFetch(gDelayJson(COLD_SCREEN_MS, trustReliable())).fetch,
        }),
      );
      const p = run(guard);
      await vi.advanceTimersByTimeAsync(GUARD_ADVISORY_BUDGET_MS);
      expect((await p).verdict).toBe("unavailable"); // aborted at 2s, did NOT wait ~10.7s
    } finally {
      vi.useRealTimers();
    }
  });

  it("enforce: a genuinely dead host (connection refused / network error) fails fast — never waits the 13s budget", async () => {
    // A rejecting host surfaces "unavailable" the instant guardFetch rejects; the
    // generous overall budget never delays it. No fake timers ⇒ this resolves on
    // microtasks; if the budget gated it, the test would hang.
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gNetwork()).fetch }),
    );
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtok" } }));
    expect(r.verdict).toBe("unavailable");
  });

  it("the enforce screen budget is sized to the measured cold distribution (pin: cold p99 < budget < per-leg cap)", () => {
    // F3: the hung/complete tests advance by GUARD_SCREEN_BUDGET_MS itself, so
    // they can't PIN the value — a mutation to 3000/6000 would still pass them.
    // This pins the sane range against the measured data + the transport cap.
    expect(GUARD_SCREEN_BUDGET_MS).toBeGreaterThan(COLD_SCREEN_MS); // > re-measured escalated cold p99 ~10.7s (won't cut real cold screens)
    expect(GUARD_SCREEN_BUDGET_MS).toBeLessThan(FETCH_TIMEOUT_MS); // < 30000 per-leg cap (and < P1's 29s Lambda ceiling)
    expect(GUARD_ADVISORY_BUDGET_MS).toBeLessThan(GUARD_SCREEN_BUDGET_MS); // advisory proceeds strictly faster
  });
});

// ===========================================================================
// Hot-reload: the guard uses the LIVE per-request config (SPEC §4.1/§7.5), not
// the config captured at build time — closing the drift between the guard's own
// socket-abort/verdict-mapping and the pipeline's runGuard race. A guard is built
// ONCE but `guards.<id>` is hot-reloadable; an operator flipping advisory→enforce
// with no restart must NOT leave the guard on the stale (advisory) budget/verdict.
// ===========================================================================

describe("hot-reload — guard reads the LIVE config threaded by the pipeline (no drift)", () => {
  it("BUDGET: a guard BUILT advisory (2s box) runs a cold ~10.7s screen to completion when the LIVE config is enforce ⇒ real danger BLOCKS", async () => {
    vi.useFakeTimers();
    try {
      // Captured build-time cfg = advisory (would abort the cold screen at 2000ms
      // → unavailable, and map danger→warn). The pipeline threads a LIVE enforce
      // snapshot; the guard must use IT for the socket-abort budget.
      const guard = createSafetyGuard(
        safetyConfig({ enabled: true, mode: "advisory" }),
        guardRuntime({
          guardFetch: new ScriptedGuardFetch(gDelayJson(COLD_SCREEN_MS, safetyBasic("danger"))).fetch,
        }),
      );
      const liveEnforce = safetyConfig({ enabled: true, mode: "enforce" });
      const p = run(guard, guardInput({ context: { tokenAddress: "0xtok" }, config: liveEnforce }));
      await vi.advanceTimersByTimeAsync(COLD_SCREEN_MS);
      const r = await p;
      // Live enforce ⇒ 13000ms budget tolerates the ~10.7s screen AND blockOrWarn=block.
      // A guard on the captured advisory cfg would be cut at 2000ms ⇒ unavailable.
      expect(r.verdict).toBe("block");
      expect(r.detail).toMatchObject({ verdict: "danger" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("VERDICT: a guard BUILT advisory maps a real danger to BLOCK (not warn) when the LIVE config is enforce", async () => {
    // Fast screen (no timeout in play) isolates the blockOrWarn(mode) drift: on the
    // captured advisory cfg a danger would map to WARN; the live enforce cfg blocks.
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "advisory" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(safetyBasic("danger"))).fetch }),
    );
    const liveEnforce = safetyConfig({ enabled: true, mode: "enforce" });
    const r = await run(guard, guardInput({ context: { tokenAddress: "0xtok" }, config: liveEnforce }));
    expect(r.verdict).toBe("block"); // live enforce ⇒ block; captured advisory ⇒ warn
  });

  it("trust VERDICT: a guard BUILT advisory maps an unreliable score to BLOCK when the LIVE config is enforce", async () => {
    const guard = createTrustGuard(
      trustConfig({ mode: "advisory" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(trustUnreliable())).fetch }),
    );
    const liveEnforce = trustConfig({ mode: "enforce" });
    const r = await run(guard, guardInput({ config: liveEnforce }));
    expect(r.verdict).toBe("block"); // live enforce ⇒ block; captured advisory ⇒ warn
  });
});

// ===========================================================================
// Property: advisory mode NEVER returns "block" (SPEC §7.2/§7.3)
// ===========================================================================

describe("property — advisory never blocks", () => {
  it("trust: every block-triggering input yields warn (not block) in advisory", async () => {
    const bodies = [
      trustUnreliable(),
      trustScore({ verdict: "mixed", score: 10 }), // below any minScore
      trustUnrated(),
    ];
    for (const body of bodies) {
      const guard = createTrustGuard(
        trustConfig({ mode: "advisory", minScore: 50, blockUnrated: true }),
        guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
      );
      const r = await run(guard);
      expect(r.verdict).not.toBe("block");
    }
  });

  it("safety: every block-triggering input yields warn (not block) in advisory", async () => {
    const withToken = guardInput({ context: { tokenAddress: "0xtok" } });
    const scenarios: Array<[unknown, "basic" | "deep"]> = [
      [safetyBasic("danger"), "basic"],
      [safetyDeep("safe", "serial_rugger"), "deep"],
      [safetyDeep("danger", "serial_rugger"), "deep"],
    ];
    for (const [body, depth] of scenarios) {
      const guard = createSafetyGuard(
        safetyConfig({ enabled: true, mode: "advisory", depth }),
        guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
      );
      const r = await run(guard, withToken);
      expect(r.verdict).not.toBe("block");
    }
  });
});

// ===========================================================================
// costUsd invariant (SPEC §7.1/§7.5)
// ===========================================================================

describe("costUsd is always 0 (paying happens inside guardFetch, core's concern)", () => {
  it("trust + safety across pass/warn/unavailable", async () => {
    const t1 = await run(
      createTrustGuard(trustConfig(), guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(trustReliable())).fetch })),
    );
    const t2 = await run(
      createTrustGuard(trustConfig(), guardRuntime({ guardFetch: new ScriptedGuardFetch(gStatus(402)).fetch })),
    );
    const s1 = await run(
      createSafetyGuard(safetyConfig({ enabled: true }), guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(safetyBasic("safe"))).fetch })),
      guardInput({ context: { tokenAddress: "0xtok" } }),
    );
    for (const r of [t1, t2, s1]) expect(r.costUsd).toBe(0);
  });
});
