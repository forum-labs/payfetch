/**
 * @forum-labs/payfetch-agentkit — hermetic adapter tests (NO network, NO money).
 *
 * Reuses payfetch's own test fakes/testMode seams (test/fakes.ts). Asserts:
 *  - exactly four actions, correctly named/ordered, no self-approval or
 *    policy-mutating action exists (mirrors payfetch's M6 discipline);
 *  - each action wires to the intended Payfetch method (spy — mutation-checkable);
 *  - the from-env factory forces `via: "agentkit"`, overriding PAYFETCH_VIA;
 *  - testMode keeps everything money-free (no signature is ever produced);
 *  - the provider registers with a real AgentKit instance;
 *  - denials/would-deny carry the policy-lock notice (agent cannot widen policy);
 *  - the module source references no self-approval / policy-mutation API.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { AgentKit, type WalletProvider } from "@coinbase/agentkit";
import { z } from "zod";
import { describe, expect, it } from "vitest";

import {
  AGENTKIT_VIA,
  PAYFETCH_ACTION_DESCRIPTIONS,
  PAYFETCH_ACTION_NAMES,
  PayfetchActionProvider,
  buildAgentKitPayfetchOpts,
  payfetchActionProvider,
} from "../src/index.js";

// payfetch's PUBLIC surface is imported from the built package (proving the
// published entry, not source). The hermetic test fakes (test/fakes.ts) are
// payfetch's internal, unpublished test seams, so they stay a source import.
import {
  adaptFetch,
  createPayfetch,
  type ConfigIo,
  type EnvRecord,
  type Payfetch,
} from "@forum-labs/payfetch";
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

// A minimal fake WalletProvider — getActions ignores it (non-custodial); only
// AgentKit.getActions() calls getNetwork().
const fakeWallet = {
  getNetwork: () => ({ protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" }),
  getName: () => "fake",
  getAddress: () => "0x0000000000000000000000000000000000000000",
  getBalance: async () => 0n,
  nativeTransfer: async () => "0xdeadbeef",
} as unknown as WalletProvider;

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
    via: AGENTKIT_VIA,
  });
  return { pf, signer };
}

/** Wrap a Payfetch, counting which method each action drives. */
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

function actionsOf(pf: Payfetch) {
  const provider = new PayfetchActionProvider({ payfetch: pf, dataDir: DATA_DIR });
  const actions = provider.getActions(fakeWallet);
  const byName = (name: string) => {
    const a = actions.find((x) => x.name === name);
    if (!a) throw new Error(`no action ${name}`);
    return a;
  };
  return { provider, actions, byName };
}

// ---------------------------------------------------------------------------
// Action surface — exactly four, no self-approval / policy-mutation action
// ---------------------------------------------------------------------------

describe("action surface", () => {
  it("exposes exactly the four safe actions, in order", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { actions } = actionsOf(pf);
    expect(actions.map((a) => a.name)).toEqual([
      "payfetch_fetch",
      "payfetch_quote",
      "payfetch_spend_status",
      "payfetch_list_receipts",
    ]);
    expect(actions).toHaveLength(4);
    expect(PAYFETCH_ACTION_NAMES).toEqual([
      "payfetch_fetch",
      "payfetch_quote",
      "payfetch_spend_status",
      "payfetch_list_receipts",
    ]);
  });

  it("exposes NO approve / policy-mutating action", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { actions } = actionsOf(pf);
    const names = actions.map((a) => a.name);
    for (const forbidden of ["approve_pending", "payfetch_approve", "approve", "set_policy", "clear_autodeny"]) {
      expect(names).not.toContain(forbidden);
    }
  });

  it("every action has a Zod object schema and a non-hype description", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { actions } = actionsOf(pf);
    const hype = /\b(guaranteed|first|best-in-class|#1|world['’]?s best)\b/i;
    for (const a of actions) {
      expect(a.schema instanceof z.ZodType).toBe(true);
      expect(typeof a.description).toBe("string");
      expect(a.description.length).toBeGreaterThan(20);
      expect(hype.test(a.description)).toBe(false);
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
// Wiring — each action drives the intended Payfetch method (mutation-checkable)
// ---------------------------------------------------------------------------

describe("method wiring", () => {
  it("payfetch_fetch → Payfetch.fetch()", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "hello" });
    const { pf } = buildPayfetch({ fetch });
    const { spy, calls } = spyPayfetch(pf);
    const { byName } = actionsOf(spy);
    await byName("payfetch_fetch").invoke({ url: URL1 });
    expect(calls).toEqual({ fetch: 1, quote: 0, status: 0, receipts: 0 });
  });

  it("payfetch_quote → Payfetch.quote() (never fetch)", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { pf } = buildPayfetch({ fetch });
    const { spy, calls } = spyPayfetch(pf);
    const { byName } = actionsOf(spy);
    await byName("payfetch_quote").invoke({ url: URL1 });
    expect(calls).toEqual({ fetch: 0, quote: 1, status: 0, receipts: 0 });
  });

  it("payfetch_spend_status → Payfetch.status()", async () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { spy, calls } = spyPayfetch(pf);
    const { byName } = actionsOf(spy);
    await byName("payfetch_spend_status").invoke({});
    expect(calls).toEqual({ fetch: 0, quote: 0, status: 1, receipts: 0 });
  });

  it("payfetch_list_receipts → Payfetch.receipts()", async () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const { spy, calls } = spyPayfetch(pf);
    const { byName } = actionsOf(spy);
    const out = JSON.parse(await byName("payfetch_list_receipts").invoke({ limit: 10 }));
    expect(calls).toEqual({ fetch: 0, quote: 0, status: 0, receipts: 1 });
    expect(out).toHaveProperty("count");
    expect(out).toHaveProperty("receipts");
  });
});

// ---------------------------------------------------------------------------
// via: "agentkit" attribution (the go/no-go instrument)
// ---------------------------------------------------------------------------

describe('via: "agentkit" attribution', () => {
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

  it("forces via to agentkit", () => {
    const opts = buildAgentKitPayfetchOpts(baseEnv, fakeIo());
    expect(opts.via).toBe("agentkit");
    expect(AGENTKIT_VIA).toBe("agentkit");
  });

  it("OVERRIDES any operator PAYFETCH_VIA", () => {
    const opts = buildAgentKitPayfetchOpts({ ...baseEnv, PAYFETCH_VIA: "somethingelse" }, fakeIo());
    expect(opts.via).toBe("agentkit");
  });

  it("still resolves the operator's signer from env (non-custodial)", () => {
    const opts = buildAgentKitPayfetchOpts(baseEnv, fakeIo());
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
    const { byName } = actionsOf(pf);
    const out = JSON.parse(await byName("payfetch_fetch").invoke({ url: URL1 }));
    expect(signer.signCount).toBe(0); // no on-chain payment attempted
    expect(out.test).toBe(true);
    expect(out.outcome).not.toBe("paid_delivered");
  });

  it("a free (200) fetch delivers a body, still money-free", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "free-body" });
    const { pf, signer } = buildPayfetch({ fetch, testMode: true });
    const { byName } = actionsOf(pf);
    const out = JSON.parse(await byName("payfetch_fetch").invoke({ url: URL1 }));
    expect(signer.signCount).toBe(0);
    expect(out.test).toBe(true);
    expect(out.body).toBe("free-body");
  });
});

// ---------------------------------------------------------------------------
// Registration with a real AgentKit instance
// ---------------------------------------------------------------------------

describe("AgentKit registration", () => {
  it("registers and surfaces the four actions via AgentKit.getActions()", async () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const provider = payfetchActionProvider({ payfetch: pf, dataDir: DATA_DIR });
    const agentkit = await AgentKit.from({ walletProvider: fakeWallet, actionProviders: [provider] });
    const names = agentkit.getActions().map((a) => a.name);
    for (const n of PAYFETCH_ACTION_NAMES) expect(names).toContain(n);
  });

  it("supportsNetwork is true (actions do not depend on AgentKit's wallet)", () => {
    const { pf } = buildPayfetch({ fetch: new FakeFetch() });
    const provider = new PayfetchActionProvider({ payfetch: pf, dataDir: DATA_DIR });
    expect(provider.supportsNetwork({ protocolFamily: "evm" })).toBe(true);
    expect(provider.supportsNetwork({ protocolFamily: "svm" })).toBe(true);
    expect(provider.name).toBe("payfetch");
  });
});

// ---------------------------------------------------------------------------
// Policy-lock notice — the agent is told it cannot widen policy
// ---------------------------------------------------------------------------

describe("policy-lock notice", () => {
  it("a denied fetch carries the policy-lock notice with the data dir", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { pf } = buildPayfetch({ fetch, policy: { deny: ["api.example.com"] } });
    const { byName } = actionsOf(pf);
    const out = JSON.parse(await byName("payfetch_fetch").invoke({ url: URL1 }));
    expect(out.outcome).toBe("policy_denied");
    expect(out.policyNotice).toContain(DATA_DIR);
    expect(out.policyNotice).toMatch(/cannot be changed from this session/i);
  });

  it("a would_deny quote carries the policy-lock notice", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { pf } = buildPayfetch({ fetch, policy: { deny: ["api.example.com"] } });
    const { byName } = actionsOf(pf);
    const out = JSON.parse(await byName("payfetch_quote").invoke({ url: URL1 }));
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
