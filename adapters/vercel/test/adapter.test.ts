/**
 * @forum-labs/payfetch-vercel — hermetic adapter tests (NO network, NO money).
 *
 * Reuses payfetch's own test fakes/testMode seams (test/fakes.ts). Asserts:
 *  - exactly four tools, correctly named/ordered, no self-approval or
 *    policy-mutating tool exists (mirrors payfetch's M6 discipline);
 *  - each tool's execute wires to the intended Payfetch method (spy — mutation-checkable);
 *  - the from-env factory forces `via: "vercel-ai-sdk"`, overriding PAYFETCH_VIA;
 *  - testMode keeps everything money-free (no signature is ever produced);
 *  - the AI SDK can consume each tool (asSchema(inputSchema) → JSON Schema — the
 *    exact step generateText/streamText run before calling the model);
 *  - denials/would-deny carry the policy-lock notice (agent cannot widen policy);
 *  - the module source references no self-approval / policy-mutation API;
 *  - the agent-facing descriptions are character-identical to the AgentKit adapter.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { asSchema, tool, type Tool } from "ai";
import { z } from "zod";
import { describe, expect, it } from "vitest";

import {
  PAYFETCH_ACTION_DESCRIPTIONS,
  PAYFETCH_TOOL_NAMES,
  VERCEL_VIA,
  buildPayfetchToolSet,
  buildVercelPayfetchOpts,
  payfetchTools,
} from "../src/index.js";

import { createPayfetch, type Payfetch } from "../../../src/index.js";
import type { ConfigIo, EnvRecord } from "../../../src/config.js";
import { adaptFetch } from "../../../src/core/transport.js";
import {
  FakeFetch,
  FakeSigner,
  challenge402,
  hostResolver,
  immediateDelay,
  inMemoryFs,
  fakeDeps,
  settlementResponse,
} from "../../../test/fakes.js";

const NOW = Date.UTC(2023, 10, 14, 12, 0, 0);
const URL1 = "https://api.example.com/data";
const DATA_DIR = "/data";
const PAID_OK = settlementResponse({ success: true, transaction: "0xtx" });

// A well-known PUBLIC test private key (hardhat account #0). No real funds; used
// only so config.ts can construct a LocalKeySigner (pure viem, no network).
const TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// A minimal ToolExecutionOptions stub — our tools ignore it. The AI SDK supplies
// the real one at runtime; a direct .execute() call in a test does not.
const EXEC_OPTS = { toolCallId: "test-call", messages: [] } as unknown;

/** Invoke a tool's execute (the AI SDK's serialize-the-return contract). */
async function runTool(t: Tool, args: unknown): Promise<Record<string, unknown>> {
  const exec = t.execute as ((input: unknown, options: unknown) => unknown) | undefined;
  if (!exec) throw new Error("tool has no execute function");
  return (await exec(args, EXEC_OPTS)) as Record<string, unknown>;
}

function buildPayfetch(over: {
  fetch: FakeFetch;
  signer?: FakeSigner;
  testMode?: boolean;
  policy?: Parameters<typeof createPayfetch>[0]["policy"];
}): { pf: Payfetch; signer: FakeSigner } {
  const signer = over.signer ?? new FakeSigner();
  const deps = fakeDeps({ fetch: over.fetch.fetch, now: () => NOW, signer, dataDir: DATA_DIR });
  const pf = createPayfetch({
    deps,
    fs: inMemoryFs(),
    httpClient: adaptFetch(over.fetch.fetch),
    resolve: hostResolver(),
    delay: immediateDelay,
    testMode: over.testMode ?? false,
    guards: [],
    policy: over.policy,
    via: VERCEL_VIA,
  });
  return { pf, signer };
}

/** Wrap a Payfetch, counting which method each tool drives. */
function spyPayfetch(pf: Payfetch): { spy: Payfetch; calls: Record<string, number> } {
  const calls = { fetch: 0, quote: 0, status: 0, receipts: 0 };
  const spy: Payfetch = {
    fetch: (u, i, o) => {
      calls.fetch++;
      return pf.fetch(u, i, o);
    },
    quote: (u, i) => {
      calls.quote++;
      return pf.quote(u, i);
    },
    status: () => {
      calls.status++;
      return pf.status();
    },
    receipts: (q) => {
      calls.receipts++;
      return pf.receipts(q);
    },
    close: () => pf.close(),
    engine: pf.engine,
  };
  return { spy, calls };
}

function toolsOf(pf: Payfetch) {
  return buildPayfetchToolSet({ payfetch: pf, dataDir: DATA_DIR });
}

// ---------------------------------------------------------------------------
// Tool surface — exactly four, no self-approval / policy-mutation tool
// ---------------------------------------------------------------------------

describe("tool surface", () => {
  it("exposes exactly the four safe tools, in order", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const tools = toolsOf(pf);
    expect(Object.keys(tools)).toEqual([
      "payfetch_fetch",
      "payfetch_quote",
      "payfetch_spend_status",
      "payfetch_list_receipts",
    ]);
    expect(PAYFETCH_TOOL_NAMES).toEqual([
      "payfetch_fetch",
      "payfetch_quote",
      "payfetch_spend_status",
      "payfetch_list_receipts",
    ]);
  });

  it("exposes NO approve / policy-mutating tool", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const names = Object.keys(toolsOf(pf));
    for (const forbidden of ["approve_pending", "payfetch_approve", "approve", "set_policy", "clear_autodeny"]) {
      expect(names).not.toContain(forbidden);
    }
  });

  it("every tool has a Zod inputSchema and a non-hype description", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const hype = /\b(guaranteed|first|best-in-class|#1|world['’]?s best)\b/i;
    for (const t of Object.values(toolsOf(pf))) {
      expect(t.inputSchema instanceof z.ZodType).toBe(true);
      expect(typeof t.description).toBe("string");
      expect((t.description as string).length).toBeGreaterThan(20);
      expect(hype.test(t.description as string)).toBe(false);
    }
  });

  it("the fetch description states caps are operator-owned and unchangeable here", () => {
    const d = PAYFETCH_ACTION_DESCRIPTIONS.payfetch_fetch;
    expect(d).toMatch(/operator/i);
    expect(d).toMatch(/cannot be raised|cannot be raised or bypassed|cannot be changed/i);
    // Honest about the unattended posture: no in-session human-approval prompt.
    expect(d).toMatch(/no in-session human-approval prompt/i);
  });
});

// ---------------------------------------------------------------------------
// Wiring — each tool drives the intended Payfetch method (mutation-checkable)
// ---------------------------------------------------------------------------

describe("method wiring", () => {
  it("payfetch_fetch → Payfetch.fetch()", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "hello" });
    const { pf } = buildPayfetch({ fetch });
    const { spy, calls } = spyPayfetch(pf);
    await runTool(toolsOf(spy).payfetch_fetch, { url: URL1 });
    expect(calls).toEqual({ fetch: 1, quote: 0, status: 0, receipts: 0 });
  });

  it("payfetch_quote → Payfetch.quote() (never fetch)", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { pf } = buildPayfetch({ fetch });
    const { spy, calls } = spyPayfetch(pf);
    await runTool(toolsOf(spy).payfetch_quote, { url: URL1 });
    expect(calls).toEqual({ fetch: 0, quote: 1, status: 0, receipts: 0 });
  });

  it("payfetch_spend_status → Payfetch.status()", async () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { spy, calls } = spyPayfetch(pf);
    await runTool(toolsOf(spy).payfetch_spend_status, {});
    expect(calls).toEqual({ fetch: 0, quote: 0, status: 1, receipts: 0 });
  });

  it("payfetch_list_receipts → Payfetch.receipts()", async () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { spy, calls } = spyPayfetch(pf);
    const out = await runTool(toolsOf(spy).payfetch_list_receipts, { limit: 10 });
    expect(calls).toEqual({ fetch: 0, quote: 0, status: 0, receipts: 1 });
    expect(out).toHaveProperty("count");
    expect(out).toHaveProperty("receipts");
  });
});

// ---------------------------------------------------------------------------
// via: "vercel-ai-sdk" attribution (the go/no-go instrument)
// ---------------------------------------------------------------------------

describe('via: "vercel-ai-sdk" attribution', () => {
  function fakeIo(): ConfigIo {
    return {
      readText: () => {
        throw new Error("no fs in test");
      },
      statMode: () => null,
      homedir: () => "/home/test",
      fetch: (async () => {
        throw new Error("no network in test");
      }) as unknown as typeof fetch,
      now: () => 0,
      random: () => new Uint8Array(32),
      log: () => {},
    };
  }
  const baseEnv: EnvRecord = {
    PAYFETCH_PRIVATE_KEY: TEST_PRIVATE_KEY,
    PAYFETCH_DATA_DIR: DATA_DIR,
    PAYFETCH_TEST_MODE: "1",
  };

  it("forces via to vercel-ai-sdk", () => {
    const opts = buildVercelPayfetchOpts(baseEnv, fakeIo());
    expect(opts.via).toBe("vercel-ai-sdk");
    expect(VERCEL_VIA).toBe("vercel-ai-sdk");
  });

  it("OVERRIDES any operator PAYFETCH_VIA", () => {
    const opts = buildVercelPayfetchOpts({ ...baseEnv, PAYFETCH_VIA: "somethingelse" }, fakeIo());
    expect(opts.via).toBe("vercel-ai-sdk");
  });

  it("still resolves the operator's signer from env (non-custodial)", () => {
    const opts = buildVercelPayfetchOpts(baseEnv, fakeIo());
    expect(opts.deps.signer).toBeTruthy();
    expect(opts.deps.dataDir).toBe(DATA_DIR);
  });
});

// ---------------------------------------------------------------------------
// Money-free (testMode) — no signature is ever produced
// ---------------------------------------------------------------------------

describe("money-free in testMode", () => {
  it("a paid (402) fetch produces NO signature and a test receipt", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { pf, signer } = buildPayfetch({ fetch, testMode: true });
    const out = await runTool(toolsOf(pf).payfetch_fetch, { url: URL1 });
    expect(signer.signCount).toBe(0); // no on-chain payment attempted
    expect(out.test).toBe(true);
    expect(out.outcome).not.toBe("paid_delivered");
  });

  it("a free (200) fetch delivers a body, still money-free", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "free-body" });
    const { pf, signer } = buildPayfetch({ fetch, testMode: true });
    const out = await runTool(toolsOf(pf).payfetch_fetch, { url: URL1 });
    expect(signer.signCount).toBe(0);
    expect(out.test).toBe(true);
    expect(out.body).toBe("free-body");
  });
});

// ---------------------------------------------------------------------------
// AI SDK consumption — the SDK turns each inputSchema into JSON Schema (the exact
// step generateText/streamText run before sending tool definitions to the model)
// ---------------------------------------------------------------------------

describe("AI SDK tool consumption", () => {
  it("payfetchTools({payfetch,dataDir}) is a spreadable ToolSet with the four keys", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const tools = { ...payfetchTools({ payfetch: pf, dataDir: DATA_DIR }) };
    expect(Object.keys(tools).sort()).toEqual(
      ["payfetch_fetch", "payfetch_list_receipts", "payfetch_quote", "payfetch_spend_status"].sort(),
    );
    for (const t of Object.values(tools)) expect(typeof (t as Tool).execute).toBe("function");
  });

  it("asSchema(inputSchema) resolves to a JSON Schema for every tool", async () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const tools = toolsOf(pf);
    for (const t of Object.values(tools)) {
      const js = await asSchema((t as Tool).inputSchema).jsonSchema;
      expect(js).toBeTruthy();
      expect((js as { type?: string }).type).toBe("object");
    }
    // fetch's schema exposes the documented `url` property to the model.
    const fetchJs = (await asSchema(tools.payfetch_fetch.inputSchema).jsonSchema) as {
      properties?: Record<string, unknown>;
    };
    expect(Object.keys(fetchJs.properties ?? {})).toContain("url");
  });

  it("tools built via the AI SDK expose inputSchema (v5+) — NOT parameters (pre-v5)", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    for (const t of Object.values(toolsOf(pf))) {
      expect(t).toHaveProperty("inputSchema");
      expect(t).not.toHaveProperty("parameters");
    }
    // Sanity: this is the shape a bare ai `tool()` yields, so the mirror is honest.
    const bare = tool({ description: "d", inputSchema: z.object({}), execute: async () => ({}) });
    expect(bare).toHaveProperty("inputSchema");
    expect(bare).not.toHaveProperty("parameters");
  });
});

// ---------------------------------------------------------------------------
// Policy-lock notice — the agent is told it cannot widen policy
// ---------------------------------------------------------------------------

describe("policy-lock notice", () => {
  it("a denied fetch carries the policy-lock notice with the data dir", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { pf } = buildPayfetch({ fetch, policy: { deny: ["api.example.com"] } });
    const out = await runTool(toolsOf(pf).payfetch_fetch, { url: URL1 });
    expect(out.outcome).toBe("policy_denied");
    expect(out.policyNotice).toContain(DATA_DIR);
    expect(out.policyNotice).toMatch(/cannot be changed from this session/i);
  });

  it("a would_deny quote carries the policy-lock notice", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { pf } = buildPayfetch({ fetch, policy: { deny: ["api.example.com"] } });
    const out = await runTool(toolsOf(pf).payfetch_quote, { url: URL1 });
    expect(out.decision).toBe("would_deny");
    expect(out.policyNotice).toContain(DATA_DIR);
  });
});

// ---------------------------------------------------------------------------
// Static invariant — the module references no self-approval / policy-mutation API
// ---------------------------------------------------------------------------

describe("static invariant: no self-approval / policy-mutation API", () => {
  it("the adapter source references no widening symbol", () => {
    const src = readFileSync(fileURLToPath(new URL("../src/index.ts", import.meta.url)), "utf8");
    for (const forbidden of [
      "resolveApproval",
      "listApprovals",
      "clearAutoDeny",
      "recordStrike",
      "approve_pending",
      "saveState",
    ]) {
      expect(src.includes(forbidden)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Description parity — identical honest copy to the AgentKit adapter
// ---------------------------------------------------------------------------

describe("description parity with the AgentKit adapter", () => {
  it("every agent-facing description string is character-identical to agentkit", () => {
    // Read the sibling adapter's SOURCE (do not import it — that would pull in
    // @coinbase/agentkit). Each description literal must appear verbatim there.
    const agentkitSrc = readFileSync(
      fileURLToPath(new URL("../../agentkit/src/index.ts", import.meta.url)),
      "utf8",
    );
    for (const [name, desc] of Object.entries(PAYFETCH_ACTION_DESCRIPTIONS)) {
      expect(agentkitSrc.includes(desc), `agentkit source is missing the ${name} description`).toBe(true);
    }
  });
});
