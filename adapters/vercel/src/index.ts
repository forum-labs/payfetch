/**
 * @forum-labs/payfetch-vercel — Vercel AI SDK tool adapter for payfetch.
 * UNPUBLISHED, pending human review.
 *
 * Exposes payfetch's paying-fetch surface as Vercel AI SDK tools (ai `tool()`),
 * MINUS anything that could let an unattended agent widen its own authority. The
 * four tools mirror payfetch's MCP tools except the T5 approve/deny tool
 * (deliberately omitted — an agent framework must never self-approve; SPEC M6
 * discipline):
 *
 *   payfetch_fetch         → Payfetch.fetch()     (pay-and-fetch under policy)
 *   payfetch_quote         → Payfetch.quote()     (price + policy decision, $0)
 *   payfetch_spend_status  → Payfetch.status()    (today's spend, read-only)
 *   payfetch_list_receipts → Payfetch.receipts()  (audit ledger, read-only)
 *
 * Invariants this adapter preserves (payfetch owns the money; the agent cannot):
 *  - NON-CUSTODIAL: the payment signer is payfetch's own, resolved from the
 *    operator's env exactly as the payfetch CLI/MCP server resolve it (config.ts
 *    buildFromEnv). This adapter never holds keys — the AI SDK never touches the
 *    wallet; payfetch pays with its own operator-supplied signer.
 *  - NO POLICY WIDENING: no tool mutates policy, clears an auto-deny, or approves
 *    a queued payment. This module imports NO such symbol. Caps, allow/deny lists
 *    and the approval threshold are operator-owned (config.json) and cannot be
 *    changed from a session. `maxAmountUsd` only ever LOWERS the per-call cap; it
 *    can never raise it.
 *  - ATTRIBUTION: the from-env factory forces `via: "vercel-ai-sdk"` into the
 *    createPayfetch opts (overriding any PAYFETCH_VIA), so installs count toward
 *    the integration instrument.
 *
 * Verified against ai@7.0.18 / @ai-sdk/provider-utils@5.0.6 (read from the
 * installed .d.ts, not from memory): the AI SDK `tool()` takes
 * `{ description, inputSchema, execute }` — the v5+ field name `inputSchema`, NOT
 * the pre-v5 `parameters`. `inputSchema` accepts a Zod schema directly
 * (FlexibleSchema includes ZodSchema). `execute(input, options)` may return any
 * value; the AI SDK serializes the returned object, so each tool returns the same
 * result payload the AgentKit adapter JSON.stringify'd.
 */

import { z } from "zod";
import { tool, type Tool } from "ai";

// payfetch is imported from source (this adapter lives in the payfetch repo and
// is unpublished). If it is ever split into a standalone package, these become
// `@forum-labs/payfetch` imports and payfetch must export buildFromEnv /
// realConfigIo from its public entry.
import {
  createPayfetch,
  type CreatePayfetchOpts,
  type FetchOpts,
  type Payfetch,
  type Receipt,
} from "../../../src/index.js";
import {
  buildFromEnv,
  realConfigIo,
  type ConfigIo,
  type EnvRecord,
} from "../../../src/config.js";
import { policyLockNotice } from "../../../src/mcp/tools.js";

// ---------------------------------------------------------------------------
// Attribution tag (non-negotiable) — see buildVercelPayfetchOpts below.
// ---------------------------------------------------------------------------

/** The `via` attribution set on every payfetch instance the adapter builds. */
export const VERCEL_VIA = "vercel-ai-sdk" as const;

/** The four tool names this adapter exposes (mirrors the safe MCP tools). */
export const PAYFETCH_TOOL_NAMES = [
  "payfetch_fetch",
  "payfetch_quote",
  "payfetch_spend_status",
  "payfetch_list_receipts",
] as const;

// ---------------------------------------------------------------------------
// Agent-facing descriptions (honest, precise; no hype). These ARE the agent's
// UI: they spell out that caps are operator-owned and cannot be changed here,
// and that above-threshold payments are NOT prompted for in an unattended
// framework — they depend on operator pre-approval in config or are declined.
//
// These strings are character-identical to the AgentKit adapter's
// PAYFETCH_ACTION_DESCRIPTIONS (same product, same honesty) — a sibling-source
// test asserts they match.
// ---------------------------------------------------------------------------

export const PAYFETCH_ACTION_DESCRIPTIONS = {
  payfetch_fetch:
    "Fetch a URL, automatically paying an HTTP 402 (x402) paywall if the resource requires payment, strictly within the operator's spending policy. Free URLs are fetched at no cost. Every payment is checked against operator-owned caps (per-call, per-day, per-host, total), allow/deny lists, and pre-pay trust/safety guards; those limits live in the operator's config file and cannot be raised or bypassed from this session (maxAmountUsd can lower the per-call ceiling but never raise it). Payments above the operator's approval threshold are NOT made unless the operator pre-approved them in config — this integration has no in-session human-approval prompt, so an above-threshold payment is otherwise declined and reported. Set dryRun to preview the price and policy decision without paying. Returns the outcome, the HTTP result, any payment made, and, on a decline, the reason.",
  payfetch_quote:
    "Check what a paid URL would cost and whether the current operator policy would allow paying it, WITHOUT paying anything. Runs the full pricing and policy/guard evaluation as a dry run and returns the price, the policy decision (would_pay / would_deny / free), trust/safety guard results, and remaining budgets. Moves no money and changes no limit.",
  payfetch_spend_status:
    "Report today's payment activity under the operator's policy: amount spent and remaining for the day, per host, and overall (total cap), any active payment holds, any auto-denied hosts, and recent payments. Read-only; changes nothing.",
  payfetch_list_receipts:
    "Query the local, append-only receipt ledger — the audit trail of every fetch and payment attempt on the operator's machine. Filter by time (sinceTs, epoch milliseconds), host, or outcome, and cap the count with limit. Read-only.",
} as const;

// ---------------------------------------------------------------------------
// Zod argument schemas (AI SDK `Tool.inputSchema`; zod 3, satisfying ai's
// `^3.25.76 || ^4.1.8` peer). Same shapes as the AgentKit adapter.
// ---------------------------------------------------------------------------

const HTTP_METHOD = z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]);
const CHAIN = z.enum(["solana", "base", "ethereum"]);

const FETCH_SCHEMA = z.object({
  url: z.string().url().describe("The URL to fetch (may or may not require payment)."),
  method: HTTP_METHOD.optional().describe("HTTP method. Default GET."),
  headers: z
    .record(z.string())
    .optional()
    .describe("Request headers as a string map. Header values are never stored in the receipt."),
  body: z.string().optional().describe("Request body (string)."),
  maxAmountUsd: z
    .number()
    .min(0)
    .optional()
    .describe(
      "Optional per-call ceiling (USD) you are willing to pay. This can only LOWER the operator's per-call cap for this call; it can never raise it.",
    ),
  dryRun: z
    .boolean()
    .optional()
    .describe("If true, preview the price and policy decision WITHOUT paying or fetching a paid body."),
  responseMode: z
    .enum(["inline", "file"])
    .optional()
    .describe(
      "How to return a delivered body: 'inline' (default) returns the text, 'file' writes it under the operator's data dir and returns the path.",
    ),
  tokenAddress: z
    .string()
    .optional()
    .describe("Optional token contract address, to give the safety guard token-risk context."),
  chain: CHAIN.optional().describe("Optional chain for the token-risk context (solana | base | ethereum)."),
});

const QUOTE_SCHEMA = z.object({
  url: z.string().url().describe("The URL to price."),
  method: HTTP_METHOD.optional().describe("HTTP method. Default GET."),
  headers: z.record(z.string()).optional().describe("Request headers as a string map."),
  body: z.string().optional().describe("Request body (string)."),
});

const SPEND_STATUS_SCHEMA = z.object({}).describe("No arguments.");

const LIST_RECEIPTS_SCHEMA = z.object({
  sinceTs: z.number().optional().describe("Only receipts at or after this epoch-millisecond timestamp."),
  host: z.string().optional().describe("Filter to a single host."),
  outcome: z.string().optional().describe("Filter by outcome code (e.g. paid_delivered, policy_denied)."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(200)
    .optional()
    .describe("Maximum receipts to return (default 50, max 200)."),
});

// ---------------------------------------------------------------------------
// Result mapping (thin, honest — no policy/money logic lives here). Each tool's
// `execute` returns one of these objects; the AI SDK serializes it into the
// tool result.
// ---------------------------------------------------------------------------

/** Human-readable warnings: notable guard verdicts + the receipt's note codes. */
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

function paymentSummary(receipt: Receipt): Record<string, unknown> | null {
  if (!receipt.payment) return null;
  return {
    outcome: receipt.outcome,
    amountUsd: receipt.payment.settledAmountUsd ?? receipt.quote?.amountUsd ?? null,
    txRef: receipt.payment.txRef,
    settlementConfirmed: receipt.payment.settlementConfirmed,
  };
}

/**
 * Guidance surfaced when an above-threshold payment could not proceed because
 * this unattended integration has no in-session human-approval channel. Not a
 * silent deny: it names the operator's config escapes and reiterates that the
 * agent cannot change any of them.
 */
function aboveThresholdGuidance(dataDir: string): string {
  return (
    "This payment is above the operator's approval threshold. This Vercel AI SDK integration is " +
    "unattended and has no in-session human-approval prompt, and it never self-approves. To " +
    `allow payments like this, the operator must edit ${dataDir}/config.json to (a) raise ` +
    "approval.thresholdUsd, (b) set approval.preApprovedUpToUsd to a ceiling, or (c) add this " +
    "host to approval.preApprovedHosts. All spending caps still apply, and none of these can be " +
    "changed from this session."
  );
}

async function formatFetchResult(
  dataDir: string,
  receipt: Receipt,
  response: Response | null,
  responseMode: "inline" | "file",
): Promise<Record<string, unknown>> {
  const base: Record<string, unknown> = {
    receiptId: receipt.receiptId,
    outcome: receipt.outcome,
    test: receipt.test,
    status: receipt.http?.status ?? null,
    contentType: receipt.http?.contentType ?? null,
    bodyBytes: receipt.http?.bodyBytes ?? null,
    truncated: receipt.http?.truncated ?? false,
    payment: paymentSummary(receipt),
    warnings: buildWarnings(receipt),
  };
  if (receipt.outcome === "guard_blocked" && receipt.guardBlockReason) {
    base.guardBlockReason = receipt.guardBlockReason;
  }

  // Delivered (free or paid): body inline, or its on-disk path.
  if (response !== null) {
    if (responseMode === "file") {
      return { ...base, bodyPath: `${dataDir}/downloads/${receipt.receiptId}` };
    }
    return { ...base, body: await response.text() };
  }

  // A dry-run preview (no body, not a denial).
  if (receipt.outcome === "dry_run") {
    return {
      ...base,
      decision: "would_pay",
      denyCode: receipt.denyCode,
      quote: receipt.quote,
      remainingBudgets: receipt.budgets,
    };
  }

  // Denied / blocked / payment-failed: the decision PLUS the fixed policy-lock
  // notice (the agent has no in-band path to widen spending limits or lists).
  const out: Record<string, unknown> = {
    ...base,
    denyCode: receipt.denyCode,
    quote: receipt.quote,
    remainingBudgets: receipt.budgets,
    policyNotice: policyLockNotice(dataDir),
  };
  const blockedByMissingApproval =
    receipt.outcome === "approval_queued" ||
    receipt.outcome === "approval_denied" ||
    receipt.outcome === "approval_timeout";
  if (blockedByMissingApproval) {
    out.approvalGuidance = aboveThresholdGuidance(dataDir);
  }
  return out;
}

function formatQuoteResult(
  dataDir: string,
  decisionOutcome: string,
  decision: "would_pay" | "would_deny" | "free",
  receipt: Receipt,
  denyCode: string | null,
  quote: Receipt["quote"],
  rejectedQuotes: Record<string, number> | null,
  guards: Receipt["guards"],
  remainingBudgets: Receipt["budgets"],
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    receiptId: receipt.receiptId,
    outcome: decisionOutcome,
    decision,
    denyCode,
    test: receipt.test,
    price: quote
      ? {
          amountUsd: quote.amountUsd,
          asset: quote.asset,
          network: quote.network,
          payTo: quote.payTo,
          resource: quote.resource,
        }
      : null,
    quote,
    rejectedQuotes,
    guards,
    remainingBudgets,
    warnings: buildWarnings(receipt),
  };
  // A "would_deny" quote surfaces the same policy-lock notice as a real denial.
  if (decision === "would_deny") out.policyNotice = policyLockNotice(dataDir);
  return out;
}

// ---------------------------------------------------------------------------
// Tool builder — the `tool()` calls are inline (below) so the AI SDK can infer
// each tool's input type from its concrete Zod schema. `boundary` wraps a typed
// handler as an AI SDK `execute`, parsing/normalizing the input at the boundary
// (defensive: the AI SDK validates input against inputSchema before calling
// execute, but a direct `.execute()` call in a test does not), then delegating.
// The AI SDK serializes whatever object the returned promise resolves to.
// ---------------------------------------------------------------------------

function boundary<S extends z.ZodTypeAny, R>(
  schema: S,
  run: (args: z.infer<S>) => Promise<R>,
): (args: unknown) => Promise<R> {
  return (args: unknown) => run(schema.parse(args ?? {}) as z.infer<S>);
}

function buildInit(args: { method?: string; headers?: Record<string, string>; body?: string }): RequestInit {
  const init: RequestInit = {};
  if (args.method) init.method = args.method;
  if (args.headers) init.headers = args.headers;
  if (args.body !== undefined) init.body = args.body;
  return init;
}

// ---------------------------------------------------------------------------
// The tool set
// ---------------------------------------------------------------------------

export interface PayfetchToolsConfig {
  /** The payfetch instance the tools drive (built with `via: "vercel-ai-sdk"`). */
  payfetch: Payfetch;
  /**
   * The operator's data dir — substituted into the policy-lock notice so the
   * agent is told exactly where the (unchangeable-from-here) limits live.
   */
  dataDir: string;
}

/** The record of tools, keyed by the four MCP-mirrored names. */
export type PayfetchToolSet = {
  payfetch_fetch: Tool;
  payfetch_quote: Tool;
  payfetch_spend_status: Tool;
  payfetch_list_receipts: Tool;
};

/**
 * Build the four payfetch tools for a given payfetch instance. The AI SDK never
 * touches the wallet; payfetch pays with its own operator-supplied signer.
 */
export function buildPayfetchToolSet(config: PayfetchToolsConfig): PayfetchToolSet {
  if (!config?.payfetch) {
    throw new TypeError("buildPayfetchToolSet: config.payfetch is required");
  }
  const pf = config.payfetch;
  const dataDir = config.dataDir;

  return {
    payfetch_fetch: tool({
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_fetch,
      inputSchema: FETCH_SCHEMA,
      execute: boundary(FETCH_SCHEMA, async (args) => {
        const init = buildInit(args);
        const opts: FetchOpts = {};
        if (args.maxAmountUsd !== undefined) opts.maxAmountUsd = args.maxAmountUsd;
        if (args.dryRun !== undefined) opts.dryRun = args.dryRun;
        const responseMode: "inline" | "file" = args.responseMode === "file" ? "file" : "inline";
        opts.responseMode = responseMode;
        if (args.tokenAddress !== undefined) opts.tokenAddress = args.tokenAddress;
        if (args.chain !== undefined) opts.chain = args.chain;
        const { response, receipt } = await pf.fetch(args.url, init, opts);
        return formatFetchResult(dataDir, receipt, response, responseMode);
      }),
    }),

    payfetch_quote: tool({
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_quote,
      inputSchema: QUOTE_SCHEMA,
      execute: boundary(QUOTE_SCHEMA, async (args) => {
        // Payfetch.quote() ALWAYS dry-runs by contract — it can never move money.
        const { decision, receipt } = await pf.quote(args.url, buildInit(args));
        return formatQuoteResult(
          dataDir,
          decision.outcome,
          decision.decision,
          receipt,
          decision.denyCode,
          decision.quote,
          decision.rejectedQuotes,
          decision.guards,
          decision.remainingBudgets,
        );
      }),
    }),

    payfetch_spend_status: tool({
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_spend_status,
      inputSchema: SPEND_STATUS_SCHEMA,
      execute: boundary(SPEND_STATUS_SCHEMA, async () => pf.status()),
    }),

    payfetch_list_receipts: tool({
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_list_receipts,
      inputSchema: LIST_RECEIPTS_SCHEMA,
      execute: boundary(LIST_RECEIPTS_SCHEMA, async (args) => {
        const q: { sinceTs?: number; host?: string; outcome?: Receipt["outcome"]; limit?: number } = {};
        if (args.sinceTs !== undefined) q.sinceTs = args.sinceTs;
        if (args.host !== undefined) q.host = args.host;
        if (args.outcome !== undefined) q.outcome = args.outcome as Receipt["outcome"];
        if (args.limit !== undefined) q.limit = args.limit;
        const receipts = await pf.receipts(q);
        return { receipts, count: receipts.length };
      }),
    }),
  };
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

/**
 * Assemble the createPayfetch options from the operator's environment EXACTLY as
 * payfetch's own CLI/MCP server do (config.ts buildFromEnv resolves the single
 * wallet signer, the data dir, and the test/approver flags), then FORCE
 * `via: "vercel-ai-sdk"` — overriding any PAYFETCH_VIA — so the install is
 * attributed to the Vercel AI SDK integration. The signer is the operator's;
 * this adapter never holds keys. `deps.elicit` is left null (as buildFromEnv
 * returns it): an unattended framework has no human to prompt, so above-threshold
 * payments rely on the operator's config pre-approval or are declined — never
 * self-approved.
 */
export function buildVercelPayfetchOpts(
  env: EnvRecord = process.env,
  io: ConfigIo = realConfigIo(),
): CreatePayfetchOpts {
  const opts = buildFromEnv(env, io);
  opts.via = VERCEL_VIA; // attribution — non-negotiable; overrides PAYFETCH_VIA
  return opts;
}

/** Build a payfetch instance (via "vercel-ai-sdk") plus its data dir, from env. */
export function createVercelPayfetch(
  env: EnvRecord = process.env,
  io: ConfigIo = realConfigIo(),
): { payfetch: Payfetch; dataDir: string } {
  const opts = buildVercelPayfetchOpts(env, io);
  return { payfetch: createPayfetch(opts), dataDir: opts.deps.dataDir };
}

/**
 * Build the payfetch tool set for the Vercel AI SDK. Two forms:
 *  - `payfetchTools()` (or `{ env, io }`): builds payfetch from the operator's
 *    environment with `via: "vercel-ai-sdk"` (the usual path).
 *  - `payfetchTools({ payfetch, dataDir })`: drives a payfetch instance the caller
 *    already built (for tests / advanced wiring). NOTE: in this form the caller is
 *    responsible for setting `via: "vercel-ai-sdk"` on their opts.
 *
 * Spread the result straight into a generateText / streamText `tools` map:
 *   const { text } = await generateText({ model, prompt, tools: { ...payfetchTools() } });
 */
export function payfetchTools(
  config: PayfetchToolsConfig | { env?: EnvRecord; io?: ConfigIo } = {},
): PayfetchToolSet {
  if ("payfetch" in config && config.payfetch) {
    return buildPayfetchToolSet(config);
  }
  const envConfig = config as { env?: EnvRecord; io?: ConfigIo };
  const { payfetch, dataDir } = createVercelPayfetch(envConfig.env, envConfig.io);
  return buildPayfetchToolSet({ payfetch, dataDir });
}
