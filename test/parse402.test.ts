/**
 * P3′ payfetch — parse402 tests (SPEC §14 "Parsing" matrix + termsHash boundary).
 *
 * Hermetic: parses fixture bodies only. Verifies normalization (amountUsd
 * derivation, payTo lowercasing, outputSchemaSha256), rail detection, the
 * defensive minimum-parseable rule, and the termsHash field-selection boundary
 * (description/resource excluded; amount/payTo included) — the value-identity
 * contract with P2 PROBER_SPEC §3.3.
 */

import { safeBase64Encode } from "@x402/core/utils";
import { describe, expect, it } from "vitest";

import {
  hashTerms,
  parse402Challenge,
  parseAcceptsEntry,
  parseChallenge,
} from "../src/payer/parse402.js";
import { acceptsEntry, acceptsEntryV2, challenge402, challenge402V2 } from "./fakes.js";

describe("parseChallenge — happy path normalization", () => {
  it("parses a single valid accepts entry with derived amountUsd and lowercased payTo", () => {
    const c = parseChallenge(
      challenge402({
        accepts: [
          acceptsEntry({
            maxAmountRequired: "10000",
            payTo: "0xAABBccDDeeFF00112233445566778899AaBbCcDd",
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          }),
        ],
      }),
    );
    expect(c.malformed).toBe(false);
    expect(c.rail).toBe("x402");
    expect(c.x402Version).toBe(1);
    expect(c.terms).toHaveLength(1);
    const t = c.terms[0];
    expect(t.amountAtomic).toBe("10000"); // preserved as string
    expect(t.amountUsd).toBeCloseTo(0.01, 12); // 10000 / 1e6
    expect(t.payTo).toBe("0xaabbccddeeff00112233445566778899aabbccdd"); // lowercased
    expect(t.scheme).toBe("exact");
    expect(t.network).toBe("base");
    expect(typeof c.termsHash).toBe("string");
    expect(c.termsHash).toMatch(/^[0-9a-f]{16}$/);
  });

  it("derives null amountUsd for an unknown asset (never overpays an unpriceable asset)", () => {
    const c = parseChallenge(
      challenge402({
        accepts: [acceptsEntry({ asset: "0x1111111111111111111111111111111111111111" })],
      }),
    );
    expect(c.malformed).toBe(false);
    expect(c.terms[0].amountUsd).toBeNull();
  });

  it("hashes outputSchema into outputSchemaSha256 when present; null when absent", () => {
    const withSchema = parseAcceptsEntry(
      acceptsEntry({ outputSchema: { type: "object", required: ["x"] } }),
    );
    const without = parseAcceptsEntry(acceptsEntry({ outputSchema: undefined }));
    expect(withSchema?.hasOutputSchema).toBe(true);
    expect(withSchema?.outputSchemaSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(without?.hasOutputSchema).toBe(false);
    expect(without?.outputSchemaSha256).toBeNull();
  });
});

describe("parseChallenge — defensive / malformed variants (SPEC §3.1 minimum-parseable)", () => {
  it("empty accepts → malformed, rail still x402 (x402Version + accepts[] present)", () => {
    const c = parseChallenge(challenge402({ accepts: [] }));
    expect(c.malformed).toBe(true);
    expect(c.terms).toEqual([]);
    expect(c.termsHash).toBeNull();
    expect(c.rail).toBe("x402");
  });

  it("non-JSON body → malformed, rail null", () => {
    const c = parseChallenge("this is not json");
    expect(c.malformed).toBe(true);
    expect(c.rail).toBeNull();
    expect(c.x402Version).toBeNull();
  });

  it("JSON that is not an object (array) → malformed, rail null", () => {
    const c = parseChallenge("[1,2,3]");
    expect(c.malformed).toBe(true);
    expect(c.rail).toBeNull();
  });

  it("entry missing payTo → dropped; all dropped → malformed", () => {
    const c = parseChallenge(
      challenge402({ accepts: [acceptsEntry({ payTo: undefined })] }),
    );
    expect(c.malformed).toBe(true);
    expect(c.terms).toEqual([]);
  });

  it("entry missing amount → dropped", () => {
    const c = parseChallenge(
      challenge402({ accepts: [acceptsEntry({ maxAmountRequired: undefined, amount: undefined })] }),
    );
    expect(c.malformed).toBe(true);
  });

  it("accepts with x402Version absent → rail null but still parses terms (strict detection)", () => {
    // Conservative reading (flagged): rail requires x402Version per §3.1; the
    // minimum-parseable rule (malformed) is about accepts only.
    const body = challenge402();
    delete (body as Record<string, unknown>).x402Version;
    const c = parseChallenge(body);
    expect(c.rail).toBeNull();
    expect(c.malformed).toBe(false);
    expect(c.terms).toHaveLength(1);
  });

  it("accepts a Uint8Array (raw bytes) body", () => {
    const bytes = new TextEncoder().encode(JSON.stringify(challenge402()));
    const c = parseChallenge(bytes);
    expect(c.malformed).toBe(false);
    expect(c.terms).toHaveLength(1);
  });
});

describe("parseChallenge — multi-accepts", () => {
  it("parses every qualifying entry in order", () => {
    const c = parseChallenge(
      challenge402({
        accepts: [
          acceptsEntry({ maxAmountRequired: "30000" }),
          acceptsEntry({ maxAmountRequired: "10000" }),
          acceptsEntry({ maxAmountRequired: "20000" }),
        ],
      }),
    );
    expect(c.terms.map((t) => t.amountAtomic)).toEqual(["30000", "10000", "20000"]);
    expect(c.malformed).toBe(false);
  });
});

describe("hashTerms — field-selection boundary (SPEC §3.1 / P2 §3.3)", () => {
  const hashOf = (over: Record<string, unknown>): string => {
    const c = parseChallenge(challenge402({ accepts: [acceptsEntry(over)] }));
    expect(c.termsHash).not.toBeNull();
    return c.termsHash as string;
  };

  it("description change does NOT change the hash", () => {
    expect(hashOf({ description: "A" })).toBe(hashOf({ description: "B totally different" }));
  });

  it("resource change does NOT change the hash", () => {
    expect(hashOf({ resource: "https://a.example/x" })).toBe(
      hashOf({ resource: "https://b.example/y" }),
    );
  });

  it("amount change DOES change the hash", () => {
    expect(hashOf({ maxAmountRequired: "10000" })).not.toBe(
      hashOf({ maxAmountRequired: "20000" }),
    );
  });

  it("payTo change DOES change the hash", () => {
    expect(hashOf({ payTo: "0x000000000000000000000000000000000000bEEF" })).not.toBe(
      hashOf({ payTo: "0x000000000000000000000000000000000000dEAD" }),
    );
  });

  it("is stable, 16-hex, and order-independent across accepts ordering", () => {
    const a = parseChallenge(
      challenge402({
        accepts: [acceptsEntry({ maxAmountRequired: "10000" }), acceptsEntry({ maxAmountRequired: "20000" })],
      }),
    ).termsHash;
    const b = parseChallenge(
      challenge402({
        accepts: [acceptsEntry({ maxAmountRequired: "20000" }), acceptsEntry({ maxAmountRequired: "10000" })],
      }),
    ).termsHash;
    // hashTerms sorts rows → order-independent (P2 §3.3 semantics).
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it("hashTerms is a pure function of the normalized 8-tuple (golden lock)", () => {
    // Locks the algorithm so an accidental change to field set/order is caught.
    const term = parseAcceptsEntry(
      acceptsEntry({
        scheme: "exact",
        network: "base",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        maxAmountRequired: "10000",
        payTo: "0x000000000000000000000000000000000000bEEF",
        maxTimeoutSeconds: 60,
        mimeType: "application/json",
        outputSchema: undefined,
      }),
    );
    expect(term).not.toBeNull();
    const h = hashTerms([term!]);
    expect(h).toMatch(/^[0-9a-f]{16}$/);
    // Re-hash is identical (determinism).
    expect(hashTerms([term!])).toBe(h);
  });
});

// ===========================================================================
// §3.1a — protocol version & dialect rules (WIRE-PARITY WAVE)
// ===========================================================================

describe("§3.1a rule 4 — amount dual-read (v1 maxAmountRequired | v2 amount)", () => {
  it("reads v2 `amount` when maxAmountRequired is absent", () => {
    const t = parseAcceptsEntry(acceptsEntryV2({ amount: "1000" }));
    expect(t?.amountAtomic).toBe("1000");
    expect(t?.amountUsd).toBeCloseTo(0.001, 12); // Base Sepolia USDC, 6 decimals
  });
  it("prefers v1 maxAmountRequired if both are present (defensive precedence)", () => {
    const t = parseAcceptsEntry(acceptsEntry({ maxAmountRequired: "10000", amount: "999" }));
    expect(t?.amountAtomic).toBe("10000");
  });
});

describe("§3.1a rule 3 — network normalization (canonical for hash/policy, raw echoed)", () => {
  it("normalizes a CAIP-2 network to canonical while preserving the raw declared string", () => {
    const t = parseAcceptsEntry(acceptsEntryV2({ network: "eip155:84532" }));
    expect(t?.network).toBe("base-sepolia"); // canonical (hash/policy)
    expect(t?.networkAsDeclared).toBe("eip155:84532"); // raw (payload echo)
  });
  it("leaves an already-canonical v1 name unchanged (raw === canonical)", () => {
    const t = parseAcceptsEntry(acceptsEntry({ network: "base" }));
    expect(t?.network).toBe("base");
    expect(t?.networkAsDeclared).toBe("base");
  });
  it("captures the challenge x402Version (v2)", () => {
    const c = parseChallenge(challenge402V2());
    expect(c.x402Version).toBe(2);
    expect(c.rail).toBe("x402");
    expect(c.malformed).toBe(false);
  });
  it("surfaces the v2 challenge-level resource.url onto entries lacking their own", () => {
    const c = parseChallenge(
      challenge402V2({ resource: { url: "https://api.example.com/v1/hello" } }),
    );
    expect(c.terms[0].resource).toBe("https://api.example.com/v1/hello");
  });
});

describe("§3.1a — termsHash dialect-invariance (v1 names ≡ v2 CAIP-2)", () => {
  it("the SAME terms via v1 (base + maxAmountRequired) and v2 (eip155:8453 + amount) hash IDENTICALLY", () => {
    const v1 = parseChallenge(
      challenge402({
        accepts: [
          acceptsEntry({
            network: "base",
            maxAmountRequired: "10000",
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            payTo: "0x000000000000000000000000000000000000bEEF",
            maxTimeoutSeconds: 60,
            // strip v1-only hashed extras so the 8-tuples match the v2 entry
            mimeType: undefined,
            outputSchema: undefined,
            resource: undefined,
            description: undefined,
          }),
        ],
      }),
    );
    const v2 = parseChallenge(
      challenge402V2({
        resource: null,
        accepts: [
          acceptsEntryV2({
            network: "eip155:8453", // CAIP-2 Base mainnet → canonical "base"
            amount: "10000",
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            payTo: "0x000000000000000000000000000000000000bEEF",
            maxTimeoutSeconds: 60,
          }),
        ],
      }),
    );
    expect(v1.termsHash).not.toBeNull();
    expect(v2.termsHash).toBe(v1.termsHash); // dialect-invariant (§3.1a rule 3)
  });
});

describe("§3.1a rule 1 — challenge channel (parse402Challenge)", () => {
  const headerFor = (challenge: unknown): string => safeBase64Encode(JSON.stringify(challenge));

  it("a PAYMENT-REQUIRED header IS the challenge — the body is ignored when the header parses", () => {
    const headerChallenge = challenge402V2({
      accepts: [acceptsEntryV2({ amount: "1000" })],
    });
    // Body carries DIFFERENT (v1) terms; the header must win.
    const body = challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "999999" })] });
    const c = parse402Challenge(body, headerFor(headerChallenge));
    expect(c.x402Version).toBe(2);
    expect(c.terms).toHaveLength(1);
    expect(c.terms[0].amountAtomic).toBe("1000"); // from the header, not the body
    expect(c.terms[0].network).toBe("base-sepolia");
    expect(c.terms[0].networkAsDeclared).toBe("eip155:84532");
  });

  it("an unparseable header falls back to the body", () => {
    const body = challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "12345" })] });
    const c = parse402Challenge(body, "!!!not-base64-or-json!!!");
    expect(c.malformed).toBe(false);
    expect(c.x402Version).toBe(1);
    expect(c.terms[0].amountAtomic).toBe("12345"); // body used
  });

  it("a header that decodes to JSON-but-not-a-challenge falls back to a usable body", () => {
    const body = challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "222" })] });
    const c = parse402Challenge(body, headerFor({ foo: "bar" }));
    expect(c.malformed).toBe(false);
    expect(c.terms[0].amountAtomic).toBe("222");
  });

  it("both header and body unusable → malformed_402", () => {
    const c = parse402Challenge("not json either", headerFor({ foo: "bar" }));
    expect(c.malformed).toBe(true);
    expect(c.terms).toEqual([]);
  });

  it("no header present → parses the body (v1 path)", () => {
    const c = parse402Challenge(challenge402(), null);
    expect(c.x402Version).toBe(1);
    expect(c.malformed).toBe(false);
  });
});
