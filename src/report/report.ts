/**
 * report/report.ts — R8 Stage 0 (MVR8) buy-side outcome reporting, Option C.
 *
 * Turns an immutable local receipt into a wallet-signed `p3f.outcome-report.v1`
 * payload and submits it to the scaffold `/v1/outcomes/report` route
 * (R8_OUTCOME_CHANNEL_SPEC §4.1/§9). Manual, per-incident, operator-invoked (the
 * `payfetch report <receiptId>` CLI). NEVER an MCP tool — the agent can neither file
 * nor suppress a report (SPEC §0 no-self-escalation, spec §1.2).
 *
 * Option C mechanics:
 *   - The report is signed by the PAYING wallet via EIP-712 typed data, reusing the
 *     existing `WalletSigner.signTypedData` (SPEC §2) — no new key interface.
 *   - Every field is derived MECHANICALLY from the receipt (never agent-supplied).
 *   - The URL is query-stripped; the exact amount is banded; the timestamp is
 *     coarsened to the UTC day; the receiptId, response body, and headers are never
 *     sent (§4.1 "never" list). No install-id ever rides this path.
 *
 * The EIP-712 domain/types/message here are byte-identical to the scaffold verifier
 * (scaffold/src/outcomes/verify.ts) — change one, change both, or signatures fail to
 * recover. The round-trip is asserted in report.test.ts.
 */
import { hashTerms } from "../payer/parse402.js";
import type { Eip712TypedData, WalletSigner, X402Terms } from "../payer/types.js";
import type { Receipt } from "../core/ledger.js";

// ---------------------------------------------------------------------------
// Frozen enums (mirror scaffold/src/outcomes/schema.ts + R8 spec §10)
// ---------------------------------------------------------------------------

export const OUTCOME_REPORT_SCHEMA_ID = "p3f.outcome-report.v1" as const;

export const REPORT_CLASSES_V1 = ["paid_not_delivered", "paid_delivered"] as const;
export type ReportClass = (typeof REPORT_CLASSES_V1)[number];

export const AMOUNT_BANDS = ["lt_0.01", "0.01_0.10", "0.10_1", "gte_1"] as const;
export type AmountBand = (typeof AMOUNT_BANDS)[number];

export const HTTP_STATUS_CLASSES = ["2xx", "3xx", "4xx", "5xx"] as const;
export type HttpStatusClass = (typeof HTTP_STATUS_CLASSES)[number];

export type ReportChecks = {
  settlementConfirmed: boolean;
  httpStatusClass: HttpStatusClass | null;
  contentTypeOk: boolean | null;
  nonEmpty: boolean;
};

export type OutcomeReport = {
  schema: typeof OUTCOME_REPORT_SCHEMA_ID;
  endpoint: { method: string; url: string };
  outcome: ReportClass;
  checks: ReportChecks;
  termsHash: string;
  payTo: string | null;
  amountBand: AmountBand;
  utcDay: string;
  test: boolean;
  clientVersion: string;
  payer: string;
  sig: string;
  anchor?: { kind: "tx"; txRef: string; network: string };
};

/** Thrown when a receipt is not a reportable payment outcome (Stage 0 v1). */
export class NotReportableError extends Error {
  constructor(public readonly outcome: string) {
    super(
      `payfetch: receipt outcome "${outcome}" is not reportable — only settled payment ` +
        `outcomes (paid_delivered / paid_not_delivered) can be reported in this version.`,
    );
    this.name = "NotReportableError";
  }
}

// ---------------------------------------------------------------------------
// Field derivation (mechanical; mirrors R8 spec §4.1)
// ---------------------------------------------------------------------------

/** Coarse amount band for a USD amount — never the exact amount. */
export function amountBandFor(usd: number): AmountBand {
  if (!(usd >= 0.01)) return "lt_0.01";
  if (usd < 0.1) return "0.01_0.10";
  if (usd < 1) return "0.10_1";
  return "gte_1";
}

/** Coarse HTTP status class, or null when there was no HTTP response. */
export function httpStatusClassOf(status: number | null | undefined): HttpStatusClass | null {
  if (status == null || !Number.isFinite(status)) return null;
  if (status >= 200 && status < 300) return "2xx";
  if (status >= 300 && status < 400) return "3xx";
  if (status >= 400 && status < 500) return "4xx";
  if (status >= 500 && status < 600) return "5xx";
  return null;
}

/** Strip query + fragment from a URL (byte-identical policy to the guard egress). */
export function stripQuery(rawUrl: string): string {
  let s = rawUrl;
  const hash = s.indexOf("#");
  if (hash >= 0) s = s.slice(0, hash);
  const q = s.indexOf("?");
  if (q >= 0) s = s.slice(0, q);
  return s;
}

/** Reconstruct the paid quote's single terms tuple → its P2-parity `termsHash`. */
function termsHashFromReceipt(receipt: Receipt): string {
  const q = receipt.quote;
  if (q === null) return "";
  const term: X402Terms = {
    scheme: q.scheme,
    network: q.network,
    asset: q.asset,
    amountAtomic: q.amountAtomic,
    amountUsd: q.amountUsd,
    payTo: q.payTo,
    maxTimeoutSeconds: q.maxTimeoutSeconds,
    mimeType: q.mimeType,
    hasOutputSchema: q.outputSchemaSha256 !== null,
    outputSchemaSha256: q.outputSchemaSha256,
    networkAsDeclared: q.networkAsDeclared,
    resource: q.resource,
    rawAccepts: q.rawAccepts,
  };
  return hashTerms([term]);
}

/** UTC day (YYYY-MM-DD) for an epoch-ms instant. */
function utcDayOf(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10);
}

const REPORTABLE = new Set<string>(REPORT_CLASSES_V1);

/**
 * Build the UNSIGNED report payload from a receipt (mechanical). Throws
 * `NotReportableError` for any non-settled-payment outcome. `payer`/`sig` are filled
 * by `signReport`.
 */
export function buildReportFromReceipt(
  receipt: Receipt,
): Omit<OutcomeReport, "payer" | "sig"> {
  if (!REPORTABLE.has(receipt.outcome)) throw new NotReportableError(receipt.outcome);
  if (receipt.payment === null) throw new NotReportableError(receipt.outcome);

  const status = receipt.http?.status ?? null;
  const advertisedMime = receipt.quote?.mimeType ?? null;
  const gotType = receipt.http?.contentType ?? null;
  const contentTypeOk =
    advertisedMime !== null && gotType !== null
      ? gotType.toLowerCase().includes(advertisedMime.toLowerCase())
      : null;

  const amountUsd =
    receipt.payment.settledAmountUsd ?? receipt.quote?.amountUsd ?? 0;

  const report: Omit<OutcomeReport, "payer" | "sig"> = {
    schema: OUTCOME_REPORT_SCHEMA_ID,
    endpoint: { method: receipt.method.toUpperCase(), url: stripQuery(receipt.url) },
    outcome: receipt.outcome as ReportClass,
    checks: {
      settlementConfirmed: receipt.payment.settlementConfirmed,
      httpStatusClass: httpStatusClassOf(status),
      contentTypeOk,
      nonEmpty: (receipt.http?.bodyBytes ?? 0) > 0,
    },
    termsHash: termsHashFromReceipt(receipt),
    payTo: receipt.quote?.payTo ?? null,
    amountBand: amountBandFor(amountUsd),
    utcDay: utcDayOf(receipt.ts),
    test: receipt.test,
    clientVersion: receipt.clientVersion,
  };

  // Settled classes carry the on-chain anchor when the receipt has a tx ref.
  if (receipt.payment.txRef !== null) {
    report.anchor = { kind: "tx", txRef: receipt.payment.txRef, network: receipt.quote?.network ?? "base" };
  }
  return report;
}

// ---------------------------------------------------------------------------
// EIP-712 typed data (byte-identical to scaffold/src/outcomes/verify.ts)
// ---------------------------------------------------------------------------

export const OUTCOME_REPORT_DOMAIN = {
  name: "Forum Labs Outcome Report",
  version: "1",
} as const;

// MALLEABILITY (R8 review, LOW): every persisted / meaning-bearing field is bound
// into the signature — including `test`, `clientVersion`, and the FULL anchor
// (`anchorKind` + `anchorNetwork` + `anchorTxRef`) — so none can be flipped after
// signing. Byte-identical (name AND order) to scaffold/src/outcomes/verify.ts.
export const OUTCOME_REPORT_TYPES = {
  OutcomeReport: [
    { name: "schema", type: "string" },
    { name: "endpointMethod", type: "string" },
    { name: "endpointUrl", type: "string" },
    { name: "outcome", type: "string" },
    { name: "settlementConfirmed", type: "bool" },
    { name: "httpStatusClass", type: "string" },
    { name: "contentTypeOk", type: "string" },
    { name: "nonEmpty", type: "bool" },
    { name: "termsHash", type: "string" },
    { name: "payTo", type: "string" },
    { name: "amountBand", type: "string" },
    { name: "utcDay", type: "string" },
    { name: "test", type: "bool" },
    { name: "clientVersion", type: "string" },
    { name: "payer", type: "address" },
    { name: "anchorKind", type: "string" },
    { name: "anchorNetwork", type: "string" },
    { name: "anchorTxRef", type: "string" },
  ],
} as const;

function triBool(v: boolean | null): string {
  return v === null ? "" : v ? "true" : "false";
}

/** The concrete signed-message shape (matches OUTCOME_REPORT_TYPES field-for-field). */
export type OutcomeReportSignedMessage = {
  schema: string;
  endpointMethod: string;
  endpointUrl: string;
  outcome: string;
  settlementConfirmed: boolean;
  httpStatusClass: string;
  contentTypeOk: string;
  nonEmpty: boolean;
  termsHash: string;
  payTo: string;
  amountBand: string;
  utcDay: string;
  test: boolean;
  clientVersion: string;
  payer: `0x${string}`;
  anchorKind: string;
  anchorNetwork: string;
  anchorTxRef: string;
};

/** Canonical EIP-712 message — nulls collapse to "" (fully-determined struct). */
export function outcomeReportMessage(
  report: Omit<OutcomeReport, "sig">,
): OutcomeReportSignedMessage {
  return {
    schema: report.schema,
    endpointMethod: report.endpoint.method.toUpperCase(),
    endpointUrl: report.endpoint.url,
    outcome: report.outcome,
    settlementConfirmed: report.checks.settlementConfirmed,
    httpStatusClass: report.checks.httpStatusClass ?? "",
    contentTypeOk: triBool(report.checks.contentTypeOk),
    nonEmpty: report.checks.nonEmpty,
    termsHash: report.termsHash,
    payTo: report.payTo ?? "",
    amountBand: report.amountBand,
    utcDay: report.utcDay,
    test: report.test,
    clientVersion: report.clientVersion,
    payer: report.payer as `0x${string}`,
    anchorKind: report.anchor?.kind ?? "",
    anchorNetwork: report.anchor?.network ?? "",
    anchorTxRef: report.anchor?.txRef ?? "",
  };
}

/** The full EIP-712 typed-data payload the signer signs. */
export function outcomeReportTypedData(report: Omit<OutcomeReport, "sig">): Eip712TypedData {
  return {
    domain: OUTCOME_REPORT_DOMAIN,
    types: OUTCOME_REPORT_TYPES,
    primaryType: "OutcomeReport",
    message: outcomeReportMessage(report),
  };
}

/** Sign an unsigned report with the payment wallet → a complete Option-C payload. */
export async function signReport(
  unsigned: Omit<OutcomeReport, "payer" | "sig">,
  signer: WalletSigner,
): Promise<OutcomeReport> {
  const payer = (await signer.address()).toLowerCase();
  const withPayer: Omit<OutcomeReport, "sig"> = { ...unsigned, payer };
  const sig = await signer.signTypedData(outcomeReportTypedData(withPayer));
  return { ...withPayer, sig };
}

// ---------------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------------

export const OUTCOME_REPORT_PATH = "/v1/outcomes/report";

export type SubmitResult = { status: number; ok: boolean; body: unknown };

/** POST a signed report to `{baseUrl}/v1/outcomes/report`. */
export async function submitReport(
  report: OutcomeReport,
  baseUrl: string,
  fetchImpl: typeof fetch,
): Promise<SubmitResult> {
  const res = await fetchImpl(`${baseUrl}${OUTCOME_REPORT_PATH}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(report),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, ok: res.ok, body };
}

// ---------------------------------------------------------------------------
// CLI core (testable; the bin wraps this with real IO)
// ---------------------------------------------------------------------------

export type RunReportDeps = {
  /** Read every receipt from the ledger (Ledger.readAllReceipts). */
  readReceipts: () => Receipt[];
  receiptId: string;
  signer: WalletSigner;
  fetchImpl: typeof fetch;
  baseUrl: string;
  /** Confirm submission (the CLI prompts stdin; `--yes` returns true). */
  confirm: () => Promise<boolean>;
  out: (line: string) => void;
  err: (line: string) => void;
};

export type RunReportOutcome =
  | { kind: "not_found" }
  | { kind: "not_reportable"; outcome: string }
  | { kind: "aborted" }
  | { kind: "submit_failed"; status: number }
  | { kind: "submitted"; status: number; report: OutcomeReport };

/**
 * The `payfetch report <receiptId>` core: find the receipt, build + sign the
 * payload, PRINT exactly what will be sent, ask for confirmation, then submit. Pure
 * over its injected IO — no process/stdin/network coupling.
 */
export async function runReport(deps: RunReportDeps): Promise<RunReportOutcome> {
  const receipt = deps.readReceipts().find((r) => r.receiptId === deps.receiptId);
  if (receipt === undefined) {
    deps.err(`payfetch: no receipt found with id ${deps.receiptId}.`);
    return { kind: "not_found" };
  }

  let unsigned: Omit<OutcomeReport, "payer" | "sig">;
  try {
    unsigned = buildReportFromReceipt(receipt);
  } catch (e) {
    if (e instanceof NotReportableError) {
      deps.err(e.message);
      return { kind: "not_reportable", outcome: e.outcome };
    }
    throw e;
  }

  const report = await signReport(unsigned, deps.signer);

  // Show EXACTLY what will be sent (Option D consent: an explicit, previewed act).
  deps.out("This is the wallet-signed outcome report that will be submitted:");
  deps.out(JSON.stringify(report, null, 2));
  deps.out(
    "It contains NO query string, request/response body, exact amount, exact " +
      "timestamp, or receiptId — and no install-id. Reporting is opt-in and manual.",
  );

  if (!(await deps.confirm())) {
    deps.out("Aborted — nothing was submitted.");
    return { kind: "aborted" };
  }

  const result = await submitReport(report, deps.baseUrl, deps.fetchImpl);
  if (!result.ok) {
    deps.err(
      `payfetch: report submission failed (HTTP ${result.status}): ${JSON.stringify(result.body)}`,
    );
    return { kind: "submit_failed", status: result.status };
  }
  deps.out(`Report accepted (HTTP ${result.status}): ${JSON.stringify(result.body)}`);
  return { kind: "submitted", status: result.status, report };
}
