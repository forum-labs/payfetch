/**
 * @forum-labs/payfetch-agentkit — Coinbase AgentKit action-provider adapter for
 * payfetch. UNPUBLISHED, pending human review.
 *
 * Exposes payfetch's paying-fetch surface as AgentKit actions, MINUS anything
 * that could let an unattended agent widen its own authority. The four actions
 * mirror payfetch's MCP tools except the T5 approve/deny tool (deliberately
 * omitted — an agent framework must never self-approve; SPEC M6 discipline):
 *
 *   payfetch_fetch         → Payfetch.fetch()     (pay-and-fetch under policy)
 *   payfetch_quote         → Payfetch.quote()     (price + policy decision, $0)
 *   payfetch_spend_status  → Payfetch.status()    (today's spend, read-only)
 *   payfetch_list_receipts → Payfetch.receipts()  (audit ledger, read-only)
 *
 * Invariants this adapter preserves (payfetch owns the money; the agent cannot):
 *  - NON-CUSTODIAL: the payment signer is payfetch's own, resolved from the
 *    operator's env exactly as the payfetch CLI/MCP server resolve it (config.ts
 *    buildFromEnv). This adapter never holds keys and never uses AgentKit's
 *    walletProvider to pay — `getActions()` ignores it. `supportsNetwork()` is
 *    therefore true on every network (the actions do not depend on AgentKit's
 *    wallet).
 *  - NO POLICY WIDENING: no action mutates policy, clears an auto-deny, or
 *    approves a queued payment. This module imports NO such symbol. Caps,
 *    allow/deny lists and the approval threshold are operator-owned
 *    (config.json) and cannot be changed from a session. `maxAmountUsd` only
 *    ever LOWERS the per-call cap; it can never raise it.
 *  - ATTRIBUTION: the from-env factory forces `via: "agentkit"` into the
 *    createPayfetch opts (overriding any PAYFETCH_VIA), so installs count toward
 *    the integration instrument.
 *
 * Implementation note (verified against @coinbase/agentkit@0.10.4): we subclass
 * `ActionProvider` and OVERRIDE `getActions()` to return hand-built `Action`
 * objects rather than using the `@CreateAction` decorator. This is fully
 * contract-compliant (AgentKit calls `provider.getActions(walletProvider)` and
 * concatenates the `Action[]`), and it deliberately avoids two decorator
 * behaviors that are wrong for this adapter: (a) the decorator prefixes every
 * action name with the provider class name, and (b) it fires a per-invoke
 * analytics POST to cca-lite.coinbase.com (no opt-out env). Overriding keeps the
 * exact MCP-mirrored names and keeps the adapter hermetic / no-telemetry.
 */

import { z } from "zod";
import {
  ActionProvider,
  type Action,
  type Network,
  type WalletProvider,
} from "@coinbase/agentkit";

// payfetch is imported from its PUBLISHED public entry (`@forum-labs/payfetch`,
// the only `exports` path). `buildFromEnv` / `realConfigIo` / `policyLockNotice`
// and the `ConfigIo` / `EnvRecord` types are re-exported from that entry as of
// payfetch 1.0.1 (before then they were reachable only via a blocked deep import).
import {
  buildFromEnv,
  createPayfetch,
  paymentRejectedHint,
  policyLockNotice,
  realConfigIo,
  type ConfigIo,
  type CreatePayfetchOpts,
  type EnvRecord,
  type FetchOpts,
  type Payfetch,
  type Receipt,
} from "@forum-labs/payfetch";

// ---------------------------------------------------------------------------
// Attribution tag (non-negotiable) — see createAgentKitPayfetch below.
// ---------------------------------------------------------------------------

/** The `via` attribution set on every payfetch instance the adapter builds. */
export const AGENTKIT_VIA = "agentkit" as const;

/** The AgentKit provider name (its `Action`s are NOT class-name-prefixed). */
export const PAYFETCH_PROVIDER_NAME = "payfetch" as const;

/** The four action names this adapter exposes (mirrors the safe MCP tools). */
export const PAYFETCH_ACTION_NAMES = [
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
// Zod argument schemas (AgentKit `Action.schema`; zod 3, matching AgentKit).
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
// Result mapping (thin, honest — no policy/money logic lives here).
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
    "This payment is above the operator's approval threshold. This AgentKit integration is " +
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
  // A paid request the server rejected with a 4xx (1.0.1): honest hint, no
  // settlement overclaim. Mirrors payfetch's MCP paid_fetch result.
  if (receipt.outcome === "payment_rejected") {
    const st = receipt.http?.status ?? null;
    if (st !== null && st >= 400 && st < 500) out.hint = paymentRejectedHint(st);
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
// Action builder — parses args at the boundary (defensive; some AgentKit
// front-ends validate, some do not), then delegates to a payfetch method.
// ---------------------------------------------------------------------------

function makeAction<S extends z.ZodTypeAny>(def: {
  name: string;
  description: string;
  schema: S;
  invoke: (args: z.infer<S>) => Promise<string>;
}): Action {
  return {
    name: def.name,
    description: def.description,
    schema: def.schema,
    // Parse at the boundary; tolerate a no-arg call arriving as undefined.
    invoke: (args: z.infer<S>) => def.invoke(def.schema.parse(args ?? {}) as z.infer<S>),
  };
}

function buildInit(args: { method?: string; headers?: Record<string, string>; body?: string }): RequestInit {
  const init: RequestInit = {};
  if (args.method) init.method = args.method;
  if (args.headers) init.headers = args.headers;
  if (args.body !== undefined) init.body = args.body;
  return init;
}

// ---------------------------------------------------------------------------
// The action provider
// ---------------------------------------------------------------------------

export interface PayfetchActionProviderConfig {
  /** The payfetch instance the actions drive (built with `via: "agentkit"`). */
  payfetch: Payfetch;
  /**
   * The operator's data dir — substituted into the policy-lock notice so the
   * agent is told exactly where the (unchangeable-from-here) limits live.
   */
  dataDir: string;
}

export class PayfetchActionProvider extends ActionProvider<WalletProvider> {
  readonly #pf: Payfetch;
  readonly #dataDir: string;

  constructor(config: PayfetchActionProviderConfig) {
    super(PAYFETCH_PROVIDER_NAME, []);
    if (!config?.payfetch) {
      throw new TypeError("PayfetchActionProvider: config.payfetch is required");
    }
    this.#pf = config.payfetch;
    this.#dataDir = config.dataDir;
  }

  /**
   * These actions do not depend on AgentKit's wallet network (payfetch pays with
   * its own operator-supplied signer), so they are available on every network.
   */
  supportsNetwork(_network: Network): boolean {
    return true;
  }

  /**
   * The four payfetch actions. AgentKit calls this with its walletProvider; we
   * deliberately ignore it (non-custodial: payfetch owns the payment signer).
   */
  getActions(_walletProvider: WalletProvider): Action[] {
    const pf = this.#pf;
    const dataDir = this.#dataDir;

    const fetchAction = makeAction({
      name: "payfetch_fetch",
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_fetch,
      schema: FETCH_SCHEMA,
      invoke: async (args) => {
        const init = buildInit(args);
        const opts: FetchOpts = {};
        if (args.maxAmountUsd !== undefined) opts.maxAmountUsd = args.maxAmountUsd;
        if (args.dryRun !== undefined) opts.dryRun = args.dryRun;
        const responseMode: "inline" | "file" = args.responseMode === "file" ? "file" : "inline";
        opts.responseMode = responseMode;
        if (args.tokenAddress !== undefined) opts.tokenAddress = args.tokenAddress;
        if (args.chain !== undefined) opts.chain = args.chain;
        const { response, receipt } = await pf.fetch(args.url, init, opts);
        return JSON.stringify(await formatFetchResult(dataDir, receipt, response, responseMode), null, 2);
      },
    });

    const quoteAction = makeAction({
      name: "payfetch_quote",
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_quote,
      schema: QUOTE_SCHEMA,
      invoke: async (args) => {
        // Payfetch.quote() ALWAYS dry-runs by contract — it can never move money.
        const { decision, receipt } = await pf.quote(args.url, buildInit(args));
        return JSON.stringify(
          formatQuoteResult(
            dataDir,
            decision.outcome,
            decision.decision,
            receipt,
            decision.denyCode,
            decision.quote,
            decision.rejectedQuotes,
            decision.guards,
            decision.remainingBudgets,
          ),
          null,
          2,
        );
      },
    });

    const spendStatusAction = makeAction({
      name: "payfetch_spend_status",
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_spend_status,
      schema: SPEND_STATUS_SCHEMA,
      invoke: async () => {
        const status = await pf.status();
        return JSON.stringify(status, null, 2);
      },
    });

    const listReceiptsAction = makeAction({
      name: "payfetch_list_receipts",
      description: PAYFETCH_ACTION_DESCRIPTIONS.payfetch_list_receipts,
      schema: LIST_RECEIPTS_SCHEMA,
      invoke: async (args) => {
        const q: { sinceTs?: number; host?: string; outcome?: Receipt["outcome"]; limit?: number } = {};
        if (args.sinceTs !== undefined) q.sinceTs = args.sinceTs;
        if (args.host !== undefined) q.host = args.host;
        if (args.outcome !== undefined) q.outcome = args.outcome as Receipt["outcome"];
        if (args.limit !== undefined) q.limit = args.limit;
        const receipts = await pf.receipts(q);
        return JSON.stringify({ receipts, count: receipts.length }, null, 2);
      },
    });

    return [fetchAction, quoteAction, spendStatusAction, listReceiptsAction];
  }
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

/**
 * Assemble the createPayfetch options from the operator's environment EXACTLY as
 * payfetch's own CLI/MCP server do (config.ts buildFromEnv resolves the single
 * wallet signer, the data dir, and the test/approver flags), then FORCE
 * `via: "agentkit"` — overriding any PAYFETCH_VIA — so the install is attributed
 * to the AgentKit integration. The signer is the operator's; this adapter never
 * holds keys. `deps.elicit` is left null (as buildFromEnv returns it): an
 * unattended framework has no human to prompt, so above-threshold payments rely
 * on the operator's config pre-approval or are declined — never self-approved.
 */
export function buildAgentKitPayfetchOpts(
  env: EnvRecord = process.env,
  io: ConfigIo = realConfigIo(),
): CreatePayfetchOpts {
  const opts = buildFromEnv(env, io);
  opts.via = AGENTKIT_VIA; // attribution — non-negotiable; overrides PAYFETCH_VIA
  return opts;
}

/** Build a payfetch instance (via "agentkit") plus its data dir, from env. */
export function createAgentKitPayfetch(
  env: EnvRecord = process.env,
  io: ConfigIo = realConfigIo(),
): { payfetch: Payfetch; dataDir: string } {
  const opts = buildAgentKitPayfetchOpts(env, io);
  return { payfetch: createPayfetch(opts), dataDir: opts.deps.dataDir };
}

/**
 * Build the AgentKit action provider. Two forms:
 *  - `payfetchActionProvider()` (or `{ env, io }`): builds payfetch from the
 *    operator's environment with `via: "agentkit"` (the usual path).
 *  - `payfetchActionProvider({ payfetch, dataDir })`: drives a payfetch instance
 *    the caller already built (for tests / advanced wiring). NOTE: in this form
 *    the caller is responsible for setting `via: "agentkit"` on their opts.
 *
 * Register with AgentKit like any provider:
 *   const agentkit = await AgentKit.from({ walletProvider, actionProviders: [payfetchActionProvider()] });
 */
export function payfetchActionProvider(
  config: PayfetchActionProviderConfig | { env?: EnvRecord; io?: ConfigIo } = {},
): PayfetchActionProvider {
  if ("payfetch" in config && config.payfetch) {
    return new PayfetchActionProvider(config);
  }
  const envConfig = config as { env?: EnvRecord; io?: ConfigIo };
  const { payfetch, dataDir } = createAgentKitPayfetch(envConfig.env, envConfig.io);
  return new PayfetchActionProvider({ payfetch, dataDir });
}
