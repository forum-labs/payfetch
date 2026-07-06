/**
 * report.test.ts — R8 Stage 0 (MVR8) buy-side outcome reporting, Option C.
 *
 * Covers: mechanical receipt→payload derivation (query stripped, amount banded, day
 * granularity, privacy "never" list), rejection of non-reportable receipts, the
 * wallet-signature round-trip (the scaffold verifier's exact check), submission, and
 * the `payfetch report` CLI core (happy path, abort, not-found, not-reportable).
 */
import { describe, it, expect } from "vitest";
import { recoverTypedDataAddress } from "viem";

import { makeQuote, makeReceipt } from "./fakes.js";
import { LocalKeySigner } from "../src/payer/signer_local.js";
import type { Receipt } from "../src/core/ledger.js";
import {
  NotReportableError,
  OUTCOME_REPORT_DOMAIN,
  OUTCOME_REPORT_TYPES,
  buildReportFromReceipt,
  outcomeReportMessage,
  runReport,
  signReport,
  submitReport,
  type OutcomeReport,
} from "../src/report/report.js";

// Well-known anvil test key → address 0xf39F…2266 (never a real wallet).
const TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const signer = new LocalKeySigner(TEST_KEY);

/** A settled, not-delivered receipt with a query string in the URL. */
function reportableReceipt(over: Partial<Receipt> = {}): Receipt {
  return makeReceipt({
    receiptId: "rid-1",
    outcome: "paid_not_delivered",
    url: "https://api.example.com/data?secret=hunter2&k=v",
    method: "GET",
    ts: Date.parse("2026-07-03T12:00:00.000Z"),
    quote: makeQuote(0.005, {
      payTo: "0x000000000000000000000000000000000000beef",
      mimeType: "application/json",
    }),
    payment: {
      payerAddress: "0x000000000000000000000000000000000000f00d",
      nonce: "0xabcdef",
      validBeforeTs: 1_800_000_000,
      settledAmountUsd: 0.005,
      txRef: "0xdeadbeef",
      settlementConfirmed: true,
    },
    http: {
      status: 502,
      contentType: "text/html",
      bodyBytes: 0,
      bodySha256: null,
      truncated: false,
      totalMs: 100,
    },
    ...over,
  });
}

/** A fetch stub that records the last POST body and returns a scripted status. */
function captureFetch(status = 202): {
  fetchImpl: typeof fetch;
  bodies: string[];
  calls: () => number;
} {
  const bodies: string[] = [];
  const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
    bodies.push(String(init?.body ?? ""));
    return new Response(JSON.stringify({ accepted: true, written: true }), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { fetchImpl, bodies, calls: () => bodies.length };
}

describe("R8 buildReportFromReceipt", () => {
  it("derives the payload mechanically: query stripped, amount banded, day-granular", () => {
    const r = buildReportFromReceipt(reportableReceipt());
    expect(r.schema).toBe("p3f.outcome-report.v1");
    expect(r.endpoint).toEqual({ method: "GET", url: "https://api.example.com/data" });
    expect(r.outcome).toBe("paid_not_delivered");
    expect(r.checks).toEqual({
      settlementConfirmed: true,
      httpStatusClass: "5xx",
      contentTypeOk: false, // advertised application/json, got text/html
      nonEmpty: false,
    });
    expect(r.amountBand).toBe("lt_0.01");
    expect(r.utcDay).toBe("2026-07-03");
    expect(r.payTo).toBe("0x000000000000000000000000000000000000beef");
    expect(r.termsHash).toMatch(/^[0-9a-f]{16}$/);
    expect(r.test).toBe(false);
    expect(r.anchor).toEqual({ kind: "tx", txRef: "0xdeadbeef", network: "base" });

    // PRIVACY: the payload carries NO query string, secret, exact amount, or receiptId.
    const dump = JSON.stringify(r);
    expect(dump).not.toContain("hunter2");
    expect(dump).not.toContain("secret");
    expect(dump).not.toContain("0.005");
    expect(dump).not.toContain("rid-1");
  });

  it("rejects every non-settled-payment outcome (NotReportableError)", () => {
    for (const outcome of [
      "free",
      "dry_run",
      "guard_blocked",
      "policy_denied",
      "payment_rejected", // phase-2 class, not reportable in Stage 0
      "unknown_settlement",
    ] as const) {
      expect(() => buildReportFromReceipt(makeReceipt({ outcome }))).toThrow(NotReportableError);
    }
    // A reportable outcome with no payment block is also refused (defensive).
    expect(() =>
      buildReportFromReceipt(makeReceipt({ outcome: "paid_delivered", payment: null })),
    ).toThrow(NotReportableError);
  });
});

describe("R8 Option-C signature round-trip", () => {
  it("signReport produces a payload the scaffold verifier accepts (recover === payer)", async () => {
    const report = await signReport(buildReportFromReceipt(reportableReceipt()), signer);
    expect(report.payer).toBe((await signer.address()).toLowerCase());
    expect(report.sig).toMatch(/^0x[0-9a-f]{130}$/);

    // The EXACT check scaffold/src/outcomes/verify.ts performs.
    const recovered = await recoverTypedDataAddress({
      domain: OUTCOME_REPORT_DOMAIN,
      types: OUTCOME_REPORT_TYPES,
      primaryType: "OutcomeReport",
      message: outcomeReportMessage(report),
      signature: report.sig as `0x${string}`,
    });
    expect(recovered.toLowerCase()).toBe(report.payer);
  });

  it("binds test/clientVersion/anchor into the signed struct (anti-malleability, R8 review #6)", async () => {
    const report = await signReport(buildReportFromReceipt(reportableReceipt()), signer);

    // The canonical message carries the newly-bound fields...
    const msg = outcomeReportMessage(report);
    expect(msg.test).toBe(report.test);
    expect(msg.clientVersion).toBe(report.clientVersion);
    expect(msg.anchorKind).toBe("tx"); // reportableReceipt has a tx anchor
    expect(msg.anchorNetwork).toBe("base");
    expect(msg.anchorTxRef).toBe("0xdeadbeef");

    // ...and flipping ANY of them after signing changes the recovered signer, so the
    // scaffold verifier's `recover === payer` check fails (the row is dropped).
    async function recoverOf(m: ReturnType<typeof outcomeReportMessage>): Promise<string> {
      return (
        await recoverTypedDataAddress({
          domain: OUTCOME_REPORT_DOMAIN,
          types: OUTCOME_REPORT_TYPES,
          primaryType: "OutcomeReport",
          message: m,
          signature: report.sig as `0x${string}`,
        })
      ).toLowerCase();
    }
    expect(await recoverOf({ ...msg, test: !msg.test })).not.toBe(report.payer);
    expect(await recoverOf({ ...msg, clientVersion: "p3f-9.9.9" })).not.toBe(report.payer);
    expect(await recoverOf({ ...msg, anchorNetwork: "ethereum" })).not.toBe(report.payer);
    expect(await recoverOf({ ...msg, anchorKind: "" })).not.toBe(report.payer);
  });
});

describe("R8 submitReport", () => {
  it("POSTs the signed report and returns the route's response", async () => {
    const report = await signReport(buildReportFromReceipt(reportableReceipt()), signer);
    const { fetchImpl, bodies } = captureFetch(202);
    const res = await submitReport(report, "https://api.forum-labs.com", fetchImpl);
    expect(res.status).toBe(202);
    expect(res.ok).toBe(true);
    const sent = JSON.parse(bodies[0]!) as OutcomeReport;
    expect(sent.schema).toBe("p3f.outcome-report.v1");
    expect(sent.payer).toBe(report.payer);
  });
});

describe("payfetch report CLI core (runReport)", () => {
  it("happy path: builds, signs, previews, confirms, submits — payload is server-verifiable", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const { fetchImpl, bodies, calls } = captureFetch(202);

    const outcome = await runReport({
      readReceipts: () => [reportableReceipt()],
      receiptId: "rid-1",
      signer,
      fetchImpl,
      baseUrl: "https://api.forum-labs.com",
      confirm: async () => true,
      out: (l) => out.push(l),
      err: (l) => err.push(l),
    });

    expect(outcome.kind).toBe("submitted");
    expect(calls()).toBe(1);
    // The preview showed the exact payload.
    expect(out.join("\n")).toContain('"schema": "p3f.outcome-report.v1"');
    // The submitted body is a valid Option-C payload whose signature recovers.
    const sent = JSON.parse(bodies[0]!) as OutcomeReport;
    expect(sent.endpoint.url).toBe("https://api.example.com/data");
    const recovered = await recoverTypedDataAddress({
      domain: OUTCOME_REPORT_DOMAIN,
      types: OUTCOME_REPORT_TYPES,
      primaryType: "OutcomeReport",
      message: outcomeReportMessage(sent),
      signature: sent.sig as `0x${string}`,
    });
    expect(recovered.toLowerCase()).toBe(sent.payer);
    // PRIVACY on the wire: no query, no receiptId, no install-id.
    expect(bodies[0]!).not.toContain("hunter2");
    expect(bodies[0]!).not.toContain("rid-1");
    expect(bodies[0]!.toLowerCase()).not.toContain("installid");
  });

  it("aborts without submitting when the operator declines", async () => {
    const { fetchImpl, calls } = captureFetch();
    const outcome = await runReport({
      readReceipts: () => [reportableReceipt()],
      receiptId: "rid-1",
      signer,
      fetchImpl,
      baseUrl: "https://api.forum-labs.com",
      confirm: async () => false,
      out: () => {},
      err: () => {},
    });
    expect(outcome.kind).toBe("aborted");
    expect(calls()).toBe(0); // never submitted
  });

  it("reports not_found for an unknown receiptId; not_reportable for a non-payment receipt", async () => {
    const base = {
      signer,
      fetchImpl: captureFetch().fetchImpl,
      baseUrl: "https://api.forum-labs.com",
      confirm: async () => true,
      out: () => {},
      err: () => {},
    };
    const missing = await runReport({ ...base, readReceipts: () => [], receiptId: "nope" });
    expect(missing.kind).toBe("not_found");

    const free = await runReport({
      ...base,
      readReceipts: () => [makeReceipt({ receiptId: "free-1", outcome: "free" })],
      receiptId: "free-1",
    });
    expect(free.kind).toBe("not_reportable");
  });
});
