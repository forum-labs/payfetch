/**
 * P3′ payfetch — MCP tool surface (SPEC §9). Names, description strings, and
 * input schemas are NORMATIVE and transcribed VERBATIM from SPEC §9; they ship
 * unchanged. This module is the ONLY place the five tools are defined.
 *
 * The handlers are THIN wrappers over the `Payfetch` library surface (SPEC §10):
 * they marshal tool arguments in and receipts out. There is ZERO business logic
 * here — every policy/money decision lives in the engine.
 *
 * Invariants (SPEC §0, §9):
 *  - No tool mutates policy or clears auto-deny. This module imports NO
 *    policy-writing / auto-deny-clearing symbol (static-asserted in tests).
 *  - Exactly five tools: paid_fetch, payment_quote, spend_status, list_receipts,
 *    approve_pending (static-asserted in tests).
 *  - Denied/blocked paid_fetch results carry the fixed §9 anti-prompt-injection
 *    notice (with the real dataDir), telling the agent there is no in-band path
 *    to change spending limits or lists.
 *  - T5 approve/deny require PAYFETCH_APPROVER=1 in the SERVER env; without it the
 *    engine returns `approver_not_enabled`. "list" is always permitted.
 */

import { join } from "node:path";

import { USDC_DECIMALS } from "../core/constants.js";
import type { Outcome, Receipt } from "../core/ledger.js";
import type { Payfetch } from "../index.js";
import type { FetchOpts } from "../core/pipeline.js";

// ---------------------------------------------------------------------------
// Tool names (SPEC §9 — verbatim)
// ---------------------------------------------------------------------------

export const TOOL_NAMES = {
  PAID_FETCH: "paid_fetch",
  PAYMENT_QUOTE: "payment_quote",
  SPEND_STATUS: "spend_status",
  LIST_RECEIPTS: "list_receipts",
  APPROVE_PENDING: "approve_pending",
} as const;

// ---------------------------------------------------------------------------
// Tool descriptions (SPEC §9 — VERBATIM, LLM-tool-chooser copy; ship unchanged)
// ---------------------------------------------------------------------------

export const TOOL_DESCRIPTIONS = {
  paid_fetch:
    "Fetch a URL, automatically paying if it requires payment (HTTP 402, x402 protocol) — within the operator's spending policy. Free URLs are fetched normally at no cost. Use payment_quote first if you only want to know the price. Payments above the operator's approval threshold will ask the human for confirmation.",
  payment_quote:
    "Check what a paid URL costs and whether the current spending policy would allow paying it, WITHOUT paying. Returns the price, payment terms, trust-check results, and the policy decision.",
  spend_status:
    "Show today's agent spending: totals, remaining budgets overall and per host, active holds, and recent payments.",
  list_receipts:
    "Query the local payment receipt ledger (audit trail). Filter by time, host, or outcome.",
  approve_pending:
    "List or resolve payments waiting for human approval (queue mode). Approving grants a one-time re-run permission for that exact payment.",
} as const;

// ---------------------------------------------------------------------------
// Input schemas (SPEC §9 — VERBATIM JSON Schema)
// ---------------------------------------------------------------------------

/** list_receipts result-count defaults (SPEC §9 T4). */
const LIST_RECEIPTS_DEFAULT_LIMIT = 50;
const LIST_RECEIPTS_MAX_LIMIT = 200;

/** HTTP methods accepted by paid_fetch / payment_quote (SPEC §9 T1). */
const HTTP_METHOD_ENUM = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"] as const;
/** Response-delivery modes (SPEC §9 T1). */
const RESPONSE_MODE_ENUM = ["inline", "file"] as const;
/** Chains that enable the safety-guard token context (SPEC §9 T1). */
const CHAIN_ENUM = ["solana", "base", "ethereum"] as const;

/** A minimal JSON Schema object (what MCP `Tool.inputSchema` expects). */
export type JsonSchema = {
  type: "object";
  properties?: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
};

export const PAID_FETCH_INPUT_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    url: { type: "string", format: "uri" },
    method: { enum: [...HTTP_METHOD_ENUM], default: "GET" },
    headers: { type: "object", additionalProperties: { type: "string" } },
    body: { type: "string" },
    maxAmountUsd: { type: "number", minimum: 0 },
    dryRun: { type: "boolean", default: false },
    responseMode: { enum: [...RESPONSE_MODE_ENUM], default: "inline" },
    tokenAddress: { type: "string" },
    chain: { enum: [...CHAIN_ENUM] },
  },
  required: ["url"],
};

export const PAYMENT_QUOTE_INPUT_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    url: { type: "string", format: "uri" },
    method: { enum: [...HTTP_METHOD_ENUM], default: "GET" },
    headers: { type: "object", additionalProperties: { type: "string" } },
    body: { type: "string" },
    tokenAddress: { type: "string" },
    chain: { enum: [...CHAIN_ENUM] },
  },
  required: ["url"],
};

export const SPEND_STATUS_INPUT_SCHEMA: JsonSchema = {
  type: "object",
  properties: {},
  additionalProperties: false,
};

export const LIST_RECEIPTS_INPUT_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    sinceTs: { type: "number" },
    host: { type: "string" },
    // SPEC §9 T4 gives no enum for `outcome`; kept as a free string to avoid
    // over-constraining (the engine filters by exact match — see §8.3 outcomes).
    outcome: { type: "string" },
    limit: {
      type: "number",
      default: LIST_RECEIPTS_DEFAULT_LIMIT,
      minimum: 1,
      maximum: LIST_RECEIPTS_MAX_LIMIT,
    },
  },
};

export const APPROVE_PENDING_INPUT_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    action: { enum: ["list", "approve", "deny"] },
    approvalId: { type: "string" },
  },
  required: ["action"],
};

// ---------------------------------------------------------------------------
// The five tool definitions (SPEC §9) — exactly these, in this order
// ---------------------------------------------------------------------------

export type ToolDefinition = {
  name: string;
  description: string;
  inputSchema: JsonSchema;
};

export const PAYFETCH_TOOLS: readonly ToolDefinition[] = [
  {
    name: TOOL_NAMES.PAID_FETCH,
    description: TOOL_DESCRIPTIONS.paid_fetch,
    inputSchema: PAID_FETCH_INPUT_SCHEMA,
  },
  {
    name: TOOL_NAMES.PAYMENT_QUOTE,
    description: TOOL_DESCRIPTIONS.payment_quote,
    inputSchema: PAYMENT_QUOTE_INPUT_SCHEMA,
  },
  {
    name: TOOL_NAMES.SPEND_STATUS,
    description: TOOL_DESCRIPTIONS.spend_status,
    inputSchema: SPEND_STATUS_INPUT_SCHEMA,
  },
  {
    name: TOOL_NAMES.LIST_RECEIPTS,
    description: TOOL_DESCRIPTIONS.list_receipts,
    inputSchema: LIST_RECEIPTS_INPUT_SCHEMA,
  },
  {
    name: TOOL_NAMES.APPROVE_PENDING,
    description: TOOL_DESCRIPTIONS.approve_pending,
    inputSchema: APPROVE_PENDING_INPUT_SCHEMA,
  },
];

// ---------------------------------------------------------------------------
// Anti-prompt-injection notice (SPEC §9 — fixed copy, verbatim)
// ---------------------------------------------------------------------------

/**
 * The fixed §9 string included on every denied/blocked paid_fetch result: the
 * agent is told there is NO in-band path to change spending limits or lists.
 */
export function policyLockNotice(dataDir: string): string {
  return `Spending limits and lists are set by the operator in ${dataDir}/config.json — they cannot be changed from this session.`;
}

// ---------------------------------------------------------------------------
// Handler errors (mapped to MCP errors in server.ts)
// ---------------------------------------------------------------------------

/** A call for a tool name that is not one of the five (→ MCP MethodNotFound). */
export class UnknownToolError extends Error {
  constructor(public readonly toolName: string) {
    super(`unknown tool: ${toolName}`);
    this.name = "UnknownToolError";
  }
}

/** A malformed tool argument (→ MCP tool-error result). */
export class ToolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolInputError";
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export type ToolContext = {
  pf: Payfetch;
  /** The engine's data dir — substituted into the §9 anti-injection notice. */
  dataDir: string;
};

/**
 * Execute a tool call and return its plain-JS result object (server.ts wraps it
 * into an MCP content block). Throws `UnknownToolError` for an unknown tool and
 * `ToolInputError` for a malformed argument; all other outcomes are RESULTS.
 */
export async function dispatchTool(
  ctx: ToolContext,
  name: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  switch (name) {
    case TOOL_NAMES.PAID_FETCH:
      return handlePaidFetch(ctx, args);
    case TOOL_NAMES.PAYMENT_QUOTE:
      return handlePaymentQuote(ctx, args);
    case TOOL_NAMES.SPEND_STATUS:
      return ctx.pf.status();
    case TOOL_NAMES.LIST_RECEIPTS:
      return handleListReceipts(ctx, args);
    case TOOL_NAMES.APPROVE_PENDING:
      return handleApprovePending(ctx, args);
    default:
      throw new UnknownToolError(name);
  }
}

// --- T1 paid_fetch ---------------------------------------------------------

async function handlePaidFetch(ctx: ToolContext, args: Record<string, unknown>): Promise<unknown> {
  const url = requireString(args, "url");
  const init = buildRequestInit(args);
  const opts: FetchOpts = {};
  if (typeof args.maxAmountUsd === "number") opts.maxAmountUsd = args.maxAmountUsd;
  if (typeof args.dryRun === "boolean") opts.dryRun = args.dryRun;
  const responseMode = args.responseMode === "file" ? "file" : "inline";
  opts.responseMode = responseMode;
  if (typeof args.tokenAddress === "string") opts.tokenAddress = args.tokenAddress;
  if (typeof args.chain === "string") opts.chain = args.chain;

  const { response, receipt } = await ctx.pf.fetch(url, init, opts);
  return mapPaidFetchResult(ctx.dataDir, receipt, response, responseMode);
}

async function mapPaidFetchResult(
  dataDir: string,
  receipt: Receipt,
  response: Response | null,
  responseMode: "inline" | "file",
): Promise<unknown> {
  const base: Record<string, unknown> = {
    receiptId: receipt.receiptId,
    outcome: receipt.outcome,
    status: receipt.http?.status ?? null,
    contentType: receipt.http?.contentType ?? null,
    bodyBytes: receipt.http?.bodyBytes ?? null,
    truncated: receipt.http?.truncated ?? false,
    payment: receipt.payment
      ? {
          outcome: receipt.outcome,
          amountUsd: receipt.payment.settledAmountUsd ?? receipt.quote?.amountUsd ?? null,
          txRef: receipt.payment.txRef,
        }
      : null,
    warnings: buildWarnings(receipt),
  };
  // Block legibility (P3 review §3): surface WHY a guard block fired so the agent can
  // tell a retryable fail-close (degraded/timeout/unavailable) from a dangerous host.
  if (receipt.outcome === "guard_blocked" && receipt.guardBlockReason) {
    base.guardBlockReason = receipt.guardBlockReason;
    base.guardBlockGuidance = guardBlockGuidance(receipt.guardBlockReason);
  }

  // Delivered (free or paid) — return the body inline, or its file path.
  if (response !== null) {
    if (responseMode === "file") {
      return { ...base, bodyPath: join(dataDir, "downloads", receipt.receiptId) };
    }
    return { ...base, body: await response.text() };
  }

  // A dry-run preview (no body, not a denial) — surface the decision only.
  if (receipt.outcome === "dry_run") {
    return {
      ...base,
      denyCode: receipt.denyCode,
      quote: receipt.quote,
      remainingBudgets: receipt.budgets,
    };
  }

  // Denied / blocked / payment-failed — the decision PLUS the fixed §9 notice.
  const denied: Record<string, unknown> = {
    ...base,
    denyCode: receipt.denyCode,
    quote: receipt.quote,
    remainingBudgets: receipt.budgets,
    policyNotice: policyLockNotice(dataDir),
  };
  if (receipt.outcome === "approval_queued") {
    denied.approvalId = receipt.receiptId;
    denied.approvalInstructions =
      "A human must approve this via the approve_pending tool (queue mode) before it can be re-run.";
  }
  // CLEAR message when a payment is blocked PURELY because the client can't elicit a
  // human (P3 review): tell the operator how to allow it via config — never a silent
  // deny. Keyed off the elicit-unavailable cause note the engine emits.
  if (
    receipt.outcome === "approval_denied" &&
    (receipt.notes.includes("elicit_unsupported") || receipt.notes.includes("elicit_cancelled"))
  ) {
    denied.approvalGuidance = elicitBlockedGuidance(dataDir);
  }
  return denied;
}

/**
 * The CLEAR operator guidance surfaced when an above-threshold payment was blocked
 * ONLY because the connected MCP client cannot prompt a human (no elicitation, or it
 * cancelled the dialog). Not a silent deny — it names the three config escapes, and
 * reiterates that caps still apply and the agent cannot change any of them (P3 review).
 */
function elicitBlockedGuidance(dataDir: string): string {
  return (
    "This payment is above the approval threshold, and the connected MCP client " +
    "cannot prompt a human to approve it (it does not support elicitation, or it " +
    "dismissed the prompt). This is NOT a denial by a human — it is blocked because " +
    "there is no in-session approval channel. To allow payments like this WITHOUT a " +
    `human dialog, the operator can edit ${dataDir}/config.json to (a) raise ` +
    "approval.thresholdUsd, (b) set approval.preApprovedUpToUsd to a ceiling, or " +
    "(c) add this host to approval.preApprovedHosts. Spending caps still apply, and " +
    "these limits cannot be changed from this session."
  );
}

/** Retry-vs-abandon guidance for each guard-block reason (P3 review §3). */
function guardBlockGuidance(reason: NonNullable<Receipt["guardBlockReason"]>): string {
  switch (reason) {
    case "danger":
      return "A trust/safety guard flagged this host or token as dangerous. This is a verdict, not a transient error — do NOT retry; use a different resource.";
    case "degraded":
      return "The safety screen was DEGRADED (incomplete danger data) so the enforce guard failed closed. A warm re-screen may clear it — retrying shortly may succeed.";
    case "timeout":
      return "The guard timed out on a cold screen. A warm screen is faster — retrying shortly may succeed.";
    case "unavailable":
      return "The guard was unavailable (upstream down, unpaid, or malformed). Retrying later may succeed; an operator can also adjust guards.*.onUnavailable.";
  }
}

// --- T2 payment_quote ------------------------------------------------------

async function handlePaymentQuote(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const url = requireString(args, "url");
  const init = buildRequestInit(args);
  // Dry-run the FULL pipeline (through D9): zero reservation, zero signature.
  // Routed via fetch(dryRun) so tokenAddress/chain thread the safety-guard
  // context (SPEC §9 T2 inputs); the receipt's outcome is `dry_run`.
  const opts: FetchOpts = { dryRun: true };
  if (typeof args.tokenAddress === "string") opts.tokenAddress = args.tokenAddress;
  if (typeof args.chain === "string") opts.chain = args.chain;

  const { receipt } = await ctx.pf.fetch(url, init, opts);
  return {
    // SPEC §9 T2 output. The frozen library surface exposes the SELECTED quote +
    // per-reason rejection tally (not the full pre-filter accepts list), so
    // `terms` surfaces the surviving/selected quote; `rejectedQuotes` carries the
    // filter tally alongside it.
    terms: receipt.quote ? [receipt.quote] : [],
    selectedQuote: receipt.quote,
    rejectedQuotes: receipt.rejectedQuotes,
    decision: {
      outcome: receipt.outcome,
      denyCode: receipt.denyCode,
      decision:
        receipt.outcome === "dry_run"
          ? "would_pay"
          : receipt.outcome === "free"
            ? "free"
            : "would_deny",
      // Block legibility (P3 review §3): present only on a guard_blocked preview.
      ...(receipt.guardBlockReason ? { guardBlockReason: receipt.guardBlockReason } : {}),
    },
    guards: receipt.guards,
    remainingBudgets: receipt.budgets,
    receiptId: receipt.receiptId,
    warnings: buildWarnings(receipt),
  };
}

// --- T4 list_receipts ------------------------------------------------------

async function handleListReceipts(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const q: {
    sinceTs?: number;
    host?: string;
    outcome?: Outcome;
    limit?: number;
  } = {};
  if (typeof args.sinceTs === "number") q.sinceTs = args.sinceTs;
  if (typeof args.host === "string") q.host = args.host;
  if (typeof args.outcome === "string") q.outcome = args.outcome as Outcome;
  if (typeof args.limit === "number") q.limit = args.limit;
  // Receipts never store header values (SPEC §8.3) — already redacted at rest.
  const receipts = await ctx.pf.receipts(q);
  return { receipts, count: receipts.length };
}

// --- T5 approve_pending ----------------------------------------------------

function handleApprovePending(ctx: ToolContext, args: Record<string, unknown>): unknown {
  const action = args.action;
  if (action === "list") {
    // Always permitted — a default session can inspect the queue (SPEC §9 T5).
    return { approvals: ctx.pf.engine.listApprovals() };
  }
  if (action === "approve" || action === "deny") {
    const approvalId = args.approvalId;
    if (typeof approvalId !== "string" || approvalId.length === 0) {
      throw new ToolInputError(`approvalId is required for action "${action}"`);
    }
    // The engine gates approve/deny on PAYFETCH_APPROVER=1 and returns
    // `approver_not_enabled` when the session lacks approval authority (SPEC §9).
    const res = ctx.pf.engine.resolveApproval(approvalId, action === "approve");
    if (!res.ok) {
      return { ok: false, error: res.error, action, approvalId };
    }
    return { ok: true, action, approvalId };
  }
  throw new ToolInputError(
    `unknown action "${String(action)}" — expected "list", "approve", or "deny"`,
  );
}

// ---------------------------------------------------------------------------
// Small marshalling helpers (thin — no policy/money logic)
// ---------------------------------------------------------------------------

function requireString(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new ToolInputError(`"${key}" is required and must be a non-empty string`);
  }
  return v;
}

function buildRequestInit(args: Record<string, unknown>): RequestInit {
  const init: RequestInit = {};
  if (typeof args.method === "string") init.method = args.method;
  if (isStringRecord(args.headers)) init.headers = args.headers;
  if (typeof args.body === "string") init.body = args.body;
  return init;
}

function isStringRecord(v: unknown): v is Record<string, string> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  return Object.values(v as Record<string, unknown>).every((x) => typeof x === "string");
}

/** Human-readable warnings: guard verdicts of note + the receipt's §13 note codes. */
function buildWarnings(receipt: Receipt): string[] {
  const out: string[] = [];
  for (const g of receipt.guards) {
    if (g.verdict === "warn" || g.verdict === "block" || g.verdict === "unavailable") {
      out.push(`guard ${g.id}: ${g.verdict}`);
    }
  }
  for (const n of receipt.notes) out.push(n);
  return out;
}

/** USDC display precision (SPEC §16.1: USDC ≡ $1.00, 6 decimals) — for callers. */
export const USD_DISPLAY_DECIMALS = USDC_DECIMALS;
