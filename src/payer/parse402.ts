/**
 * P3′ payfetch — x402 challenge parsing + terms hashing (SPEC §3.1).
 *
 * Purpose: defensively parse an HTTP 402 body into a `ParsedChallenge`
 * (`X402Terms[]` + `termsHash`), with the SAME normalization + hash SEMANTICS as
 * P2 PROBER_SPEC §3.3 (SPEC §3.1 declares "same semantics as", and §1 targets
 * unifying the two into one shared module). This file is a faithful mirror of
 * products/p2_trust/prober/src/probe/parse402.ts, adapted to P3's output shape.
 *
 * Invariants:
 *  - Minimum-parseable rule (§3.1): the body must be a JSON object carrying an
 *    `accepts` array with ≥1 entry having scheme, network, payTo, AND an amount.
 *    Anything less → `{ malformed: true }` (never guess at terms).
 *  - `termsHash` is sha256 over the SORTED, normalized entries using ONLY
 *    (scheme, network, asset, amountAtomic, payTo, maxTimeoutSeconds, mimeType,
 *    outputSchemaSha256) — first 16 hex. `description` and `resource` are
 *    EXCLUDED. Byte-for-byte identical to P2 §3.3 `hashTerms` → cross-side
 *    value-identity (SPEC §1).
 *  - `amountUsd` is derived ONLY for KNOWN_ASSETS (SPEC §3.2). `payTo` is
 *    lowercased. `amountAtomic` is preserved as an as-advertised STRING (never
 *    parsed to float). `rail` is "x402" iff the body has x402Version + accepts[].
 *  - NEVER throws on shape drift — returns typed nulls / `{ malformed: true }`.
 *    The `unknown`-typed defensive accessors below are the justified `any`-free
 *    parse boundary (strict types everywhere else).
 */

import { createHash } from "node:crypto";

import { safeBase64Decode } from "@x402/core/utils";

import { canonicalNetwork, deriveAmountUsd } from "../core/constants.js";
import type { ParsedChallenge, Rail, X402Terms } from "./types.js";

// ---------------------------------------------------------------------------
// Defensive accessors (the untrusted-input boundary)
// ---------------------------------------------------------------------------

function asRecord(v: unknown): Record<string, unknown> | null {
  return v != null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}
function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
/** Amount as an advertised atomic string (string preferred; a number is stringified). */
function asAtomicString(v: unknown): string | null {
  if (typeof v === "string" && v.trim().length > 0) return v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}
function asFiniteNumber(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function sha256hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

// ---------------------------------------------------------------------------
// Single accepts entry → X402Terms (or null if below the §3.1 minimum)
// ---------------------------------------------------------------------------

/**
 * Parse one `accepts` entry. Returns null unless it carries scheme, network,
 * payTo, AND an amount (the §3.1 minimum-parseable requirement). Preserves the
 * raw entry (`rawAccepts`) for payload construction and `resource` for the quote.
 *
 * DIALECT (§3.1a, WIRE-PARITY WAVE): the amount is dual-read — v1 declares
 * `maxAmountRequired`, v2 declares `amount` (per @x402/core@2.17.0
 * PaymentRequirements{V1,V2}Schema); we prefer `maxAmountRequired` then fall back
 * to `amount`. The network is NORMALIZED to canonical (`canonicalNetwork`) for
 * the hashed `network` slot and policy/asset logic, while the RAW declared string
 * is preserved on `networkAsDeclared` for the payment payload's echoed field
 * (§3.1a rule 3).
 */
export function parseAcceptsEntry(raw: unknown): X402Terms | null {
  const r = asRecord(raw);
  if (!r) return null;

  const scheme = asString(r.scheme);
  const networkRaw = asString(r.network);
  const payToRaw = asString(r.payTo);
  // Amount dual-read (§3.1a rule 4): v1 `maxAmountRequired` | v2 `amount`.
  const amountAtomic = asAtomicString(r.maxAmountRequired ?? r.amount);
  if (!scheme || !networkRaw || !payToRaw || amountAtomic == null) return null;

  const network = canonicalNetwork(networkRaw) ?? networkRaw; // canonical for hash/policy
  const asset = asString(r.asset); // preserved as-advertised
  const payTo = payToRaw.toLowerCase();
  const maxTimeoutSeconds = asFiniteNumber(r.maxTimeoutSeconds);
  const mimeType = asString(r.mimeType);
  const resource = asString(r.resource);

  const outputSchema = asRecord(r.outputSchema);
  const hasOutputSchema = outputSchema != null;
  const outputSchemaSha256 = hasOutputSchema ? sha256hex(stableStringify(outputSchema)) : null;

  // amountUsd: derived only for KNOWN_ASSETS + non-negative integer amount (§3.2).
  const amountUsd = deriveAmountUsd(amountAtomic, asset);

  return {
    scheme,
    network,
    asset,
    amountAtomic,
    amountUsd,
    payTo,
    maxTimeoutSeconds,
    mimeType,
    hasOutputSchema,
    outputSchemaSha256,
    networkAsDeclared: networkRaw,
    resource,
    rawAccepts: raw,
  };
}

/**
 * Parse an `accepts` array into X402Terms[]. Returns null if the input is not an
 * array or yields ZERO qualifying entries (→ malformed for the caller).
 */
export function parseAccepts(rawAccepts: unknown): X402Terms[] | null {
  if (!Array.isArray(rawAccepts)) return null;
  const out: X402Terms[] = [];
  for (const entry of rawAccepts) {
    const t = parseAcceptsEntry(entry);
    if (t) out.push(t);
  }
  return out.length > 0 ? out : null;
}

// ---------------------------------------------------------------------------
// termsHash (§3.1 / P2 §3.3) — first 16 hex over the sorted normalized 8-tuples
// ---------------------------------------------------------------------------

/**
 * Canonical terms hash: map each entry to its normalized 8-field tuple, sort the
 * JSON rows, then sha256 the newline join and take the first 16 hex. Fixed tuple
 * ORDER (not object keys) removes key-ordering ambiguity; `resource`/`description`
 * are never included. Mirrors P2 §3.3 `hashTerms` EXACTLY (value-identity, §1).
 *
 * DIALECT-INVARIANCE (§3.1a rule 3, WIRE-PARITY WAVE): the `network` slot uses
 * `X402Terms.network`, which parse402 has already NORMALIZED to canonical
 * (`eip155:84532` → `base-sepolia`). Together with the amount dual-read this
 * makes the hash IDENTICAL for the same terms expressed in the v1 or v2 dialect
 * — the field set and algorithm are otherwise UNCHANGED (P2 §3.3 parity).
 */
export function hashTerms(terms: readonly X402Terms[]): string {
  const rows = terms.map((t) =>
    JSON.stringify([
      t.scheme,
      t.network,
      t.asset,
      t.amountAtomic,
      t.payTo,
      t.maxTimeoutSeconds,
      t.mimeType,
      t.outputSchemaSha256,
    ]),
  );
  rows.sort();
  return sha256hex(rows.join("\n")).slice(0, 16);
}

// ---------------------------------------------------------------------------
// Full 402 body parse → ParsedChallenge (§3.1)
// ---------------------------------------------------------------------------

const MALFORMED: ParsedChallenge = Object.freeze({
  rail: null,
  x402Version: null,
  terms: [],
  termsHash: null,
  malformed: true,
});

/**
 * Parse a 402 challenge body into a `ParsedChallenge`. Accepts an already-parsed
 * JSON object, a JSON string, or raw bytes (Uint8Array) — the transport/tests
 * may hand any of these. Never throws.
 *
 * `rail` = "x402" iff the body is a JSON object with a numeric `x402Version` AND
 * an `accepts` array (strict §3.1 detection). `malformed` = true iff no valid
 * `accepts` entry could be extracted (the §3.1 minimum), independent of rail.
 */
export function parseChallenge(rawBody: unknown): ParsedChallenge {
  const root = asRecord(toJson(rawBody));
  if (!root) return { ...MALFORMED };

  const x402Version = asFiniteNumber(root.x402Version);
  const acceptsPresent = Array.isArray(root.accepts);
  const rail: Rail | null = x402Version !== null && acceptsPresent ? "x402" : null;

  const terms = parseAccepts(root.accepts);
  if (terms === null) {
    // Body may be structurally x402 (rail set) but carries no usable terms.
    return { rail, x402Version, terms: [], termsHash: null, malformed: true };
  }

  // v2 dialect (§3.1a): the resource is a challenge-level object `{url,...}`, not
  // an accepts-entry field. Surface `resource.url` onto entries that carry no own
  // resource (display/receipt only — `resource` is NOT hashed, so this preserves
  // termsHash dialect-invariance).
  const resourceUrl = asString(asRecord(root.resource)?.url);
  if (resourceUrl !== null) {
    for (const t of terms) if (t.resource === null) t.resource = resourceUrl;
  }

  return { rail, x402Version, terms, termsHash: hashTerms(terms), malformed: false };
}

// ---------------------------------------------------------------------------
// Challenge channel (§3.1a rule 1) — PAYMENT-REQUIRED header vs body
// ---------------------------------------------------------------------------

/**
 * Decode a base64 PAYMENT-REQUIRED header value into a ParsedChallenge, or null
 * if it cannot be base64/JSON-decoded (i.e. "unparseable" → the caller falls back
 * to the body per §3.1a rule 1). The header's decoded JSON IS the challenge
 * (v2-canonical channel); base64 decode reuses the pinned @x402/core@2.17.0
 * `safeBase64Decode`, then the SAME defensive `parseChallenge` handles the JSON.
 */
function challengeFromHeader(headerValue: string): ParsedChallenge | null {
  let json: string;
  try {
    json = safeBase64Decode(headerValue);
  } catch {
    return null; // not base64 → unparseable header
  }
  return parseChallenge(json);
}

/**
 * Parse a 402 into a ParsedChallenge honoring the §3.1a rule-1 CHALLENGE CHANNEL
 * (WIRE-PARITY WAVE): if the response carries a PAYMENT-REQUIRED header, its
 * base64-decoded JSON IS the challenge (v2-canonical); otherwise the body JSON is
 * (v1 style). If the header is present but unusable (unparseable OR malformed as a
 * challenge) we fall back to the body; if BOTH are unusable → malformed_402.
 *
 * Conservative reading (flagged, §3.1a rule 1): "unparseable" is read broadly to
 * include a header that decodes to JSON but yields no usable terms — such a header
 * defers to a usable body rather than forcing malformed, matching the rule's
 * "both unusable → malformed_402" and never guessing at terms. A usable header
 * always wins over the body (the live scaffold sends the v2 challenge here).
 */
export function parse402Challenge(
  rawBody: unknown,
  paymentRequiredHeader: string | null,
): ParsedChallenge {
  if (paymentRequiredHeader != null && paymentRequiredHeader.length > 0) {
    const fromHeader = challengeFromHeader(paymentRequiredHeader);
    if (fromHeader !== null && !fromHeader.malformed) return fromHeader; // header usable → wins
    const fromBody = parseChallenge(rawBody);
    if (!fromBody.malformed) return fromBody; // fall back to a usable body
    return fromHeader ?? fromBody; // both unusable → malformed (prefer the header's)
  }
  return parseChallenge(rawBody);
}

// ---------------------------------------------------------------------------
// Input normalization + deterministic stringify (defensive boundary)
// ---------------------------------------------------------------------------

/** Normalize a body (object | JSON string | bytes) to parsed JSON, or null. */
function toJson(rawBody: unknown): unknown {
  if (rawBody == null) return null;
  if (typeof rawBody === "string") return tryParseJson(rawBody);
  if (rawBody instanceof Uint8Array) {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: false }).decode(rawBody);
    } catch {
      return null;
    }
    return tryParseJson(text);
  }
  if (typeof rawBody === "object") return rawBody; // already-parsed body
  return null;
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Stable stringify (keys sorted recursively) so schema hashing is order-stable. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(rec[k])}`).join(",")}}`;
}
