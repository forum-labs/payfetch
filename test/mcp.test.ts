/**
 * P3′ payfetch — MCP tool-surface tests (SPEC §9, §14 hygiene).
 *
 * Covers: the five tool names/order (exact); description strings VERBATIM from
 * §9 (static assertions); input schemas validate against the SDK's ToolSchema;
 * T5 approver gating (approve/deny → approver_not_enabled without the env; list
 * always works); the fixed anti-injection notice on a denied paid_fetch (with the
 * real dataDir substituted); happy-path per tool over the in-memory fakes; and
 * the static no-policy-mutation guarantee (the tools module imports/exports no
 * policy-writing or auto-deny-clearing symbol; the tool list is exactly five).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ToolSchema } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { createPayfetch, type Payfetch } from "../src/index.js";
import { adaptFetch } from "../src/core/transport.js";
import {
  PAID_FETCH_INPUT_SCHEMA,
  PAYFETCH_TOOLS,
  TOOL_DESCRIPTIONS,
  TOOL_NAMES,
  UnknownToolError,
  dispatchTool,
  paymentRejectedHint,
  policyLockNotice,
  type ToolContext,
} from "../src/mcp/tools.js";
import {
  FakeFetch,
  FakeSigner,
  acceptsEntry,
  challenge402,
  fakeDeps,
  fakeGuard,
  hostResolver,
  immediateDelay,
  inMemoryFs,
  settlementResponse,
} from "./fakes.js";
import { makeElicitBridge } from "../src/mcp/server.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { ElicitFn, ElicitRequest } from "../src/payer/types.js";
import type { PrePayGuard } from "../src/guards/types.js";

const NOW = Date.UTC(2023, 10, 14, 12, 0, 0);
const URL1 = "https://api.example.com/data";
const DATA_DIR = "/data";
const PAID_OK = settlementResponse({ success: true, transaction: "0xtx" });

function buildPf(
  fetch: FakeFetch,
  over: {
    policy?: Parameters<typeof createPayfetch>[0]["policy"];
    approver?: boolean;
    testMode?: boolean;
    guards?: PrePayGuard[];
    elicit?: ElicitFn | null;
  } = {},
): Payfetch {
  const deps = fakeDeps({
    fetch: fetch.fetch,
    now: () => NOW,
    signer: new FakeSigner(),
    dataDir: DATA_DIR,
    elicit: over.elicit ?? null,
  });
  return createPayfetch({
    deps,
    fs: inMemoryFs(),
    httpClient: adaptFetch(fetch.fetch),
    resolve: hostResolver(),
    delay: immediateDelay,
    testMode: over.testMode ?? false,
    approver: over.approver ?? false,
    guards: over.guards ?? [],
    policy: over.policy,
  });
}

const ctxOf = (pf: Payfetch): ToolContext => ({ pf, dataDir: DATA_DIR });

// ---------------------------------------------------------------------------
// Tool names, descriptions, schemas (SPEC §9 — normative surface)
// ---------------------------------------------------------------------------

describe("MCP tool surface — names & order (SPEC §9)", () => {
  it("is exactly the five §9 tools, in order", () => {
    expect(PAYFETCH_TOOLS.map((t) => t.name)).toEqual([
      "paid_fetch",
      "payment_quote",
      "spend_status",
      "list_receipts",
      "approve_pending",
    ]);
    expect(PAYFETCH_TOOLS).toHaveLength(5);
    expect(Object.values(TOOL_NAMES)).toEqual([
      "paid_fetch",
      "payment_quote",
      "spend_status",
      "list_receipts",
      "approve_pending",
    ]);
  });
});

describe("MCP tool surface — description strings VERBATIM (SPEC §9, 1.0.1 hardening)", () => {
  it("paid_fetch description matches §9 exactly (with the 1.0.1 policy-lock addendum)", () => {
    expect(TOOL_DESCRIPTIONS.paid_fetch).toBe(
      "Fetch a URL, automatically paying if it requires payment (HTTP 402, x402 protocol) — within the operator's spending policy. Free URLs are fetched normally at no cost. Use payment_quote first if you only want to know the price. Payments above the operator's approval threshold will ask the human for confirmation. Spending policy is operator-owned config; no tool can widen it.",
    );
  });
  it("payment_quote description matches §9 exactly (with the 1.0.1 policy-lock addendum)", () => {
    expect(TOOL_DESCRIPTIONS.payment_quote).toBe(
      "Check what a paid URL costs and whether the current spending policy would allow paying it, WITHOUT paying. Returns the price, payment terms, trust-check results, and the policy decision. Spending policy is operator-owned config; no tool can widen it.",
    );
  });
  it("spend_status description matches §9 exactly (with the 1.0.1 policy-lock addendum)", () => {
    expect(TOOL_DESCRIPTIONS.spend_status).toBe(
      "Show today's agent spending: totals, remaining budgets overall and per host, active holds, and recent payments. Spending policy is operator-owned config; no tool can widen it.",
    );
  });
  it("list_receipts description matches §9 exactly (with the 1.0.1 policy-lock addendum)", () => {
    expect(TOOL_DESCRIPTIONS.list_receipts).toBe(
      "Query the local payment receipt ledger (audit trail). Filter by time, host, or outcome. Spending policy is operator-owned config; no tool can widen it.",
    );
  });
  it("approve_pending description matches §9 exactly (with the 1.0.1 policy note)", () => {
    expect(TOOL_DESCRIPTIONS.approve_pending).toBe(
      "List or resolve payments waiting for human approval (queue mode). Approving grants a one-time re-run permission for that exact payment. It only resolves payments already queued for approval; it cannot change spending policy — no payfetch tool can widen operator-owned limits.",
    );
  });

  it("every tool description carries the operator-owned policy-lock invariant (1.0.1 §2c)", () => {
    // The descriptions ARE the agent's UI; each must make "an agent can widen its
    // own limits" impossible to infer (the demo hallucination that motivated 1.0.1).
    for (const [name, desc] of Object.entries(TOOL_DESCRIPTIONS)) {
      expect(desc, `${name} must state no tool can widen policy`).toMatch(
        /no (payfetch )?tool can widen/i,
      );
    }
  });

  it("maxAmountUsd is documented as LOWER-only, never raise (1.0.1 §2a)", () => {
    const props = PAID_FETCH_INPUT_SCHEMA.properties as Record<string, { description?: string }>;
    const d = props.maxAmountUsd.description ?? "";
    expect(d).toMatch(/lower/i);
    expect(d).toMatch(/never raise/i);
  });
});

describe("MCP tool surface — schemas validate against the SDK (SPEC §9, §14)", () => {
  it("every tool passes the SDK ToolSchema and has an object input schema", () => {
    for (const t of PAYFETCH_TOOLS) {
      expect(() => ToolSchema.parse(t)).not.toThrow();
      expect(t.inputSchema.type).toBe("object");
    }
  });

  it("paid_fetch requires url and enumerates methods/responseMode/chain", () => {
    const s = PAYFETCH_TOOLS[0].inputSchema;
    expect(s.required).toEqual(["url"]);
    const props = s.properties as Record<string, { enum?: string[] }>;
    expect(props.method.enum).toEqual(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]);
    expect(props.responseMode.enum).toEqual(["inline", "file"]);
    expect(props.chain.enum).toEqual(["solana", "base", "ethereum"]);
  });
});

// ---------------------------------------------------------------------------
// T5 approver gating (SPEC §9)
// ---------------------------------------------------------------------------

describe("approve_pending — approver gating (SPEC §9 T5)", () => {
  it("list is ALWAYS permitted (default session, no PAYFETCH_APPROVER)", async () => {
    const pf = buildPf(new FakeFetch(), { approver: false });
    const res = (await dispatchTool(ctxOf(pf), "approve_pending", { action: "list" })) as {
      approvals: unknown[];
    };
    expect(Array.isArray(res.approvals)).toBe(true);
    pf.close();
  });

  it("approve/deny WITHOUT PAYFETCH_APPROVER → approver_not_enabled", async () => {
    const pf = buildPf(new FakeFetch(), { approver: false });
    const ctx = ctxOf(pf);
    const approve = (await dispatchTool(ctx, "approve_pending", {
      action: "approve",
      approvalId: "x",
    })) as { ok: boolean; error: string };
    expect(approve).toMatchObject({ ok: false, error: "approver_not_enabled" });
    const deny = (await dispatchTool(ctx, "approve_pending", {
      action: "deny",
      approvalId: "x",
    })) as { ok: boolean; error: string };
    expect(deny).toMatchObject({ ok: false, error: "approver_not_enabled" });
    pf.close();
  });

  it("with PAYFETCH_APPROVER the gate passes (unknown id → approval_not_found)", async () => {
    const pf = buildPf(new FakeFetch(), { approver: true });
    const res = (await dispatchTool(ctxOf(pf), "approve_pending", {
      action: "approve",
      approvalId: "missing",
    })) as { ok: boolean; error?: string };
    expect(res.ok).toBe(false);
    expect(res.error).toBe("approval_not_found");
    pf.close();
  });

  it("approve/deny without an approvalId is an input error", async () => {
    const pf = buildPf(new FakeFetch(), { approver: true });
    await expect(
      dispatchTool(ctxOf(pf), "approve_pending", { action: "approve" }),
    ).rejects.toThrow(/approvalId/);
    pf.close();
  });
});

describe("approve_pending — M6 queue self-approval forbidden (SPEC §6)", () => {
  it("queue mode + approver: approve is refused (does not pay); deny + list still work", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const pf = buildPf(fetch, {
      approver: true,
      policy: { approval: { thresholdUsd: 0.005, mode: "queue", elicitFallback: "deny" } },
    });
    const ctx = ctxOf(pf);

    // The agent's own over-threshold ($0.01 > $0.005) payment queues.
    const queued = (await dispatchTool(ctx, "paid_fetch", { url: URL1 })) as {
      outcome: string;
      approvalId?: string;
    };
    expect(queued.outcome).toBe("approval_queued");
    const approvalId = queued.approvalId!;

    // The same session cannot self-approve it (no requester/approver separation).
    const approve = (await dispatchTool(ctx, "approve_pending", {
      action: "approve",
      approvalId,
    })) as { ok: boolean; error?: string };
    expect(approve).toMatchObject({ ok: false, error: "queue_self_approval_forbidden" });

    // list is always permitted, and the item is STILL pending (the grant failed).
    const list = (await dispatchTool(ctx, "approve_pending", { action: "list" })) as {
      approvals: unknown[];
    };
    expect(list.approvals).toHaveLength(1);

    // deny still works — it only REMOVES a pending item, it cannot authorize a pay.
    const deny = (await dispatchTool(ctx, "approve_pending", { action: "deny", approvalId })) as {
      ok: boolean;
    };
    expect(deny.ok).toBe(true);
    pf.close();
  });

  it("elicit + elicitFallback=queue is queue-capable ⇒ approve is refused too", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const pf = buildPf(fetch, {
      approver: true,
      policy: { approval: { thresholdUsd: 0.005, mode: "elicit", elicitFallback: "queue" } },
    });
    const ctx = ctxOf(pf);
    const queued = (await dispatchTool(ctx, "paid_fetch", { url: URL1 })) as {
      outcome: string;
      approvalId?: string;
    };
    expect(queued.outcome).toBe("approval_queued");
    const res = (await dispatchTool(ctx, "approve_pending", {
      action: "approve",
      approvalId: queued.approvalId!,
    })) as { ok: boolean; error?: string };
    expect(res).toMatchObject({ ok: false, error: "queue_self_approval_forbidden" });
    pf.close();
  });

  it("a SAFE config (elicit + fallback deny) is NOT queue-capable ⇒ approver resolves normally", async () => {
    const pf = buildPf(new FakeFetch(), {
      approver: true,
      policy: { approval: { thresholdUsd: 0.005, mode: "elicit", elicitFallback: "deny" } },
    });
    const res = (await dispatchTool(ctxOf(pf), "approve_pending", {
      action: "approve",
      approvalId: "missing",
    })) as { ok: boolean; error?: string };
    expect(res.ok).toBe(false);
    expect(res.error).toBe("approval_not_found"); // gate open; the item just doesn't exist
    pf.close();
  });
});

// ---------------------------------------------------------------------------
// Anti-injection notice on a denied paid_fetch (SPEC §9)
// ---------------------------------------------------------------------------

describe("paid_fetch — anti-prompt-injection notice on denial (SPEC §9)", () => {
  it("a denied call carries the fixed notice with the real dataDir", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const pf = buildPf(fetch, { policy: { deny: ["api.example.com"] } });
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      denyCode: string;
      policyNotice: string;
      quote: unknown;
      remainingBudgets: unknown;
    };
    expect(res.outcome).toBe("policy_denied");
    expect(res.denyCode).toBe("host_denied");
    expect(res.policyNotice).toBe(policyLockNotice(DATA_DIR));
    expect(res.policyNotice).toContain("/data/config.json");
    expect(res.policyNotice).toContain("cannot be changed from this session");
    expect(res.remainingBudgets).toBeTruthy();
    pf.close();
  });
});

// ---------------------------------------------------------------------------
// payment_rejected hint on a 4xx paid response (1.0.1 §1) — honest, no overclaim
// ---------------------------------------------------------------------------

describe("paid_fetch — payment_rejected 4xx hint (1.0.1)", () => {
  it("a 4xx on the paid leg surfaces an honest hint that does NOT claim settlement", async () => {
    // 402 challenge, then the PAID retry is rejected 400 (the $0.007-dies-on-a-
    // header shape). classifyFromParts → payment_rejected, hold kept, no txRef.
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402() },
      { status: 400, textBody: "bad request" },
    );
    const pf = buildPf(fetch);
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      status: number | null;
      hint?: string;
      payment: { txRef: string | null } | null;
    };
    expect(res.outcome).toBe("payment_rejected");
    expect(res.status).toBe(400);
    expect(res.hint).toBe(paymentRejectedHint(400));
    expect(res.hint).toContain("HTTP 400");
    expect(res.hint).toContain("does NOT confirm settlement");
    // Honesty: no settlement tx was recorded (charged only if a tx is shown).
    expect(res.payment?.txRef ?? null).toBeNull();
    pf.close();
  });

  it("a 2xx paid delivery carries NO rejection hint", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const pf = buildPf(fetch);
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      hint?: string;
    };
    expect(res.outcome).toBe("paid_delivered");
    expect(res.hint).toBeUndefined();
    pf.close();
  });
});

// ---------------------------------------------------------------------------
// Happy path per tool over the in-memory fakes (SPEC §9, §10)
// ---------------------------------------------------------------------------

describe("tool handlers — happy paths over fakes (SPEC §9)", () => {
  it("paid_fetch of a FREE url returns the body, no payment", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "hello" });
    const pf = buildPf(fetch);
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      status: number | null;
      body: string;
      payment: unknown;
      warnings: unknown[];
      receiptId: string;
    };
    expect(res.outcome).toBe("free");
    expect(res.status).toBe(200);
    expect(res.body).toBe("hello");
    expect(res.payment).toBeNull();
    expect(Array.isArray(res.warnings)).toBe(true);
    expect(typeof res.receiptId).toBe("string");
    pf.close();
  });

  it("payment_quote dry-runs a 402 and returns the selected quote + decision", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const pf = buildPf(fetch);
    const res = (await dispatchTool(ctxOf(pf), "payment_quote", { url: URL1 })) as {
      terms: unknown[];
      selectedQuote: { amountUsd: number } | null;
      decision: { outcome: string; decision: string };
      guards: unknown[];
      remainingBudgets: unknown;
      receiptId: string;
    };
    expect(res.decision.outcome).toBe("dry_run");
    expect(res.decision.decision).toBe("would_pay");
    expect(res.selectedQuote?.amountUsd).toBeCloseTo(0.01, 9);
    expect(res.terms).toHaveLength(1);
    expect(Array.isArray(res.guards)).toBe(true);
    expect(res.remainingBudgets).toBeTruthy();
    expect(typeof res.receiptId).toBe("string");
    pf.close();
  });

  it("spend_status reflects a paid call, and list_receipts filters by outcome", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402() },
      PAID_OK,
    );
    const pf = buildPf(fetch);
    const ctx = ctxOf(pf);

    const paid = (await dispatchTool(ctx, "paid_fetch", { url: URL1 })) as {
      outcome: string;
      payment: { amountUsd: number; txRef: string | null } | null;
    };
    expect(paid.outcome).toBe("paid_delivered");
    expect(paid.payment?.txRef).toBe("0xtx");

    const status = (await dispatchTool(ctx, "spend_status", {})) as {
      date: string;
      day: { spentUsd: number };
      total: unknown;
      perHost: unknown;
      holds: unknown[];
      autoDenied: unknown[];
      recentPayments: unknown[];
    };
    expect(typeof status.date).toBe("string");
    expect(status.day.spentUsd).toBeCloseTo(0.01, 9);
    expect(status.recentPayments).toHaveLength(1);
    expect(Array.isArray(status.holds)).toBe(true);
    expect(Array.isArray(status.autoDenied)).toBe(true);

    const filtered = (await dispatchTool(ctx, "list_receipts", {
      outcome: "paid_delivered",
    })) as { receipts: unknown[]; count: number };
    expect(filtered.count).toBe(1);
    expect(filtered.receipts).toHaveLength(1);

    const none = (await dispatchTool(ctx, "list_receipts", { outcome: "guard_blocked" })) as {
      count: number;
    };
    expect(none.count).toBe(0);
    pf.close();
  });

  it("an unknown tool name throws UnknownToolError", async () => {
    const pf = buildPf(new FakeFetch());
    await expect(dispatchTool(ctxOf(pf), "not_a_tool", {})).rejects.toBeInstanceOf(
      UnknownToolError,
    );
    pf.close();
  });
});

// ---------------------------------------------------------------------------
// Static no-policy-mutation guarantee (SPEC §0, §9, §14)
// ---------------------------------------------------------------------------

describe("tools module — no policy mutation / no auto-deny clear (SPEC §0)", () => {
  it("the source imports/references no policy-writing or breaker-clearing symbol", () => {
    const src = readFileSync(
      fileURLToPath(new URL("../src/mcp/tools.ts", import.meta.url)),
      "utf8",
    );
    const forbidden = [
      "clearAutoDeny",
      "recordStrike",
      "saveState",
      "writeText",
      "appendAdjust",
      "mergePolicy",
      "loadPolicy",
      "validateConfig",
      "applyStrike",
      "addPendingApproval",
    ];
    for (const symbol of forbidden) {
      expect(src, `tools.ts must not reference ${symbol}`).not.toContain(symbol);
    }
    // And it does not import the budget or policy modules at all.
    expect(src).not.toContain('from "../core/policy');
    expect(src).not.toContain('from "../core/budget');
  });

  it("exposes exactly the five §9 tool names", () => {
    expect(PAYFETCH_TOOLS.map((t) => t.name).sort()).toEqual(
      ["approve_pending", "list_receipts", "paid_fetch", "payment_quote", "spend_status"].sort(),
    );
  });
});

// ---------------------------------------------------------------------------
// P3 review — tool-surface legibility: the CLEAR elicit-unavailable guidance,
// and the guard-block reason + retry-vs-abandon guidance (SPEC §6/§7, §9).
// ---------------------------------------------------------------------------

describe("paid_fetch — elicit-unavailable clear guidance (P3 review §2)", () => {
  const pricey = () =>
    challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "300000" })] }); // $0.30

  it("above-threshold + non-eliciting client + fallback deny ⇒ approvalGuidance names the config escapes", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const pf = buildPf(fetch, {
      elicit: null, // no elicitation channel (e.g. non-eliciting client)
      policy: { approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny" } },
    });
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      approvalGuidance?: string;
    };
    expect(res.outcome).toBe("approval_denied");
    expect(typeof res.approvalGuidance).toBe("string");
    expect(res.approvalGuidance).toContain("cannot prompt a human");
    expect(res.approvalGuidance).toContain("preApprovedUpToUsd");
    expect(res.approvalGuidance).toContain(DATA_DIR);
    pf.close();
  });

  it("config pre-approval lets a NON-eliciting client pay above threshold (no guidance, real body)", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const pf = buildPf(fetch, {
      elicit: null,
      policy: {
        approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny", preApprovedUpToUsd: 0.5 },
      },
    });
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      approvalGuidance?: string;
    };
    expect(res.outcome).toBe("paid_delivered");
    expect(res.approvalGuidance).toBeUndefined();
    pf.close();
  });
});

describe("paid_fetch — guard-block reason + guidance (P3 review §3)", () => {
  it("a guard_blocked result surfaces guardBlockReason + retry-vs-abandon guidance", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const pf = buildPf(fetch, { guards: [fakeGuard("trust", { verdict: "block" })] });
    const res = (await dispatchTool(ctxOf(pf), "paid_fetch", { url: URL1 })) as {
      outcome: string;
      guardBlockReason?: string;
      guardBlockGuidance?: string;
      policyNotice?: string;
    };
    expect(res.outcome).toBe("guard_blocked");
    expect(res.guardBlockReason).toBe("danger");
    expect(res.guardBlockGuidance).toContain("do NOT retry");
    expect(typeof res.policyNotice).toBe("string"); // the §9 anti-injection notice stays
    pf.close();
  });
});

// ---------------------------------------------------------------------------
// P3 review — the elicitation bridge action mapping (the Desktop-cancel linchpin).
// A client's `cancel` (Claude Desktop) must map to cancelled:true (NOT a denial);
// only accept+approve:false / decline are genuine human denials.
// ---------------------------------------------------------------------------

describe("makeElicitBridge — action → ElicitDecision (P3 desktop fallback)", () => {
  const fakeServer = (elicitInput: (req: unknown) => Promise<unknown>): Server =>
    ({ elicitInput } as unknown as Server);
  const req: ElicitRequest = {
    host: "api.example.com",
    resource: null,
    amountUsd: 0.3,
    networkLabel: "base",
    assetLabel: "USDC",
    guards: [],
    remainingBudgets: { dayRemainingUsd: 1, hostRemainingUsd: 1, totalRemainingUsd: null },
  };

  it("accept + approve:true → approved (not cancelled)", async () => {
    const b = makeElicitBridge(fakeServer(async () => ({ action: "accept", content: { approve: true } })));
    expect(await b(req)).toEqual({ approved: true, cancelled: false });
  });

  it("accept + approve:false → a GENUINE human deny (not cancelled)", async () => {
    const b = makeElicitBridge(fakeServer(async () => ({ action: "accept", content: { approve: false } })));
    expect(await b(req)).toEqual({ approved: false, cancelled: false });
  });

  it("decline → a GENUINE human deny (not cancelled)", async () => {
    const b = makeElicitBridge(fakeServer(async () => ({ action: "decline" })));
    expect(await b(req)).toEqual({ approved: false, cancelled: false });
  });

  it("cancel (Claude Desktop) → CANCELLED, never a denial", async () => {
    const b = makeElicitBridge(fakeServer(async () => ({ action: "cancel" })));
    expect(await b(req)).toEqual({ approved: false, cancelled: true });
  });
});
