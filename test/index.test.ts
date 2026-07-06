/**
 * P3′ payfetch — library API tests (SPEC §10, §12, §14).
 *
 * Covers the createPayfetch contract: denials are RESULTS not exceptions; it
 * throws only on programmer error (missing deps/signer); PAYFETCH_TEST_MODE
 * receipts carry test:true; status()/receipts() read the ledger; clearAutoDeny
 * (the operator-only breaker reset) works and is not on the Payfetch surface.
 */

import { describe, expect, it } from "vitest";

import { clearAutoDeny, createPayfetch } from "../src/index.js";
import { adaptFetch } from "../src/core/transport.js";
import { Budget } from "../src/core/budget.js";
import { Ledger } from "../src/core/ledger.js";
import type { PayfetchDeps } from "../src/payer/types.js";
import {
  FakeFetch,
  FakeSigner,
  challenge402,
  fakeClock,
  fakeDeps,
  hostResolver,
  immediateDelay,
  inMemoryFs,
  settlementResponse,
} from "./fakes.js";

const NOW = Date.UTC(2023, 10, 14, 12, 0, 0);
const URL1 = "https://api.example.com/data";
const PAID_OK = settlementResponse({ success: true, transaction: "0xtx" });

function build(over: {
  fetch: FakeFetch;
  fs?: ReturnType<typeof inMemoryFs>;
  testMode?: boolean;
  policy?: Parameters<typeof createPayfetch>[0]["policy"];
  now?: () => number;
}) {
  const fs = over.fs ?? inMemoryFs();
  const signer = new FakeSigner();
  const deps = fakeDeps({
    fetch: over.fetch.fetch,
    now: over.now ?? (() => NOW),
    signer,
    dataDir: "/data",
  });
  const client = createPayfetch({
    deps,
    fs,
    httpClient: adaptFetch(over.fetch.fetch),
    resolve: hostResolver(),
    delay: immediateDelay,
    testMode: over.testMode ?? false,
    guards: [],
    policy: over.policy,
  });
  return { client, signer, fs };
}

describe("createPayfetch — programmer-error validation (SPEC §10)", () => {
  it("throws when deps is missing", () => {
    // @ts-expect-error intentional misuse
    expect(() => createPayfetch({})).toThrow(TypeError);
  });

  it("throws when the signer is missing", () => {
    const deps = { ...fakeDeps(), signer: undefined } as unknown as PayfetchDeps;
    expect(() => createPayfetch({ deps, fs: inMemoryFs(), guards: [] })).toThrow(/signer/);
  });
});

describe("createPayfetch — denials are results, not exceptions (SPEC §10)", () => {
  it("a policy denial returns { response: null, receipt } without throwing", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client } = build({ fetch, policy: { deny: ["api.example.com"] } });
    const { response, receipt } = await client.fetch(URL1);
    expect(response).toBeNull();
    expect(receipt.outcome).toBe("policy_denied");
    expect(receipt.denyCode).toBe("host_denied");
  });

  it("an invalid config surfaces policy_config_invalid (fail closed), not a throw", async () => {
    const fs = inMemoryFs();
    fs.writeText("/data/config.json", "{ broken json ");
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client } = build({ fetch, fs });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("policy_denied");
    expect(receipt.denyCode).toBe("policy_config_invalid");
  });
});

describe("createPayfetch — test mode (SPEC §12)", () => {
  it("stamps receipts with test:true", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "x" });
    const { client } = build({ fetch, testMode: true });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.test).toBe(true);
    expect(receipt.notes).toContain("test_mode");
  });
});

describe("createPayfetch — status/receipts read the ledger (SPEC §10)", () => {
  it("reflects a paid call in status() and receipts()", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client } = build({ fetch });
    await client.fetch(URL1);
    const status = await client.status();
    expect(status.day.spentUsd).toBeCloseTo(0.01, 9);
    expect(status.recentPayments).toHaveLength(1);
    const recs = await client.receipts({ outcome: "paid_delivered" });
    expect(recs).toHaveLength(1);
    // close() releases the single-writer lock cleanly.
    expect(() => client.close()).not.toThrow();
  });
});

describe("clearAutoDeny — operator-only breaker reset (SPEC §5.4)", () => {
  it("clears an engaged auto-deny in the persisted state", async () => {
    const clock = fakeClock(NOW);
    const fs = inMemoryFs();
    // Engage auto-deny directly in a persisted state (two confirmed strikes).
    const led = new Ledger(fs, "/data", clock.now);
    const state = led.rebuildState("f".repeat(32));
    led.saveState(state);
    const budget = new Budget(state, led, clock.now);
    budget.recordStrike("bad.com", "confirmed");
    budget.recordStrike("bad.com", "confirmed");
    expect(budget.isAutoDenied("bad.com")).toBe(true);

    // Operator clears it out of band.
    expect(clearAutoDeny("/data", "bad.com", { fs, now: clock.now })).toBe(true);
    const reloaded = new Ledger(fs, "/data", clock.now).loadStateRaw();
    expect(reloaded?.autoDeny["bad.com"]).toBeUndefined();
  });
});
