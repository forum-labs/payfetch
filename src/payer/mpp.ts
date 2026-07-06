/**
 * P3′ payfetch — MppPayer: detection stub for the MPP rail (SPEC §2, §0).
 *
 * Purpose: reserve the `mpp` rail seam without implementing it. v1 is x402-only
 * (`RAILS_ENABLED = ["x402"]`); MPP is a documented non-goal until a stable MPP
 * challenge shape exists.
 *
 * Invariants:
 *  - `detects()` ALWAYS returns false (no MPP challenge is recognized in v1).
 *  - `quotes()` / `buildPayment()` throw `UnsupportedRailError` — they are never
 *    reached because the pipeline routes a challenge only to a payer whose
 *    `detects()` returned true.
 */

import type {
  ParsedChallenge,
  PayfetchDeps,
  PaymentPayer,
  PaymentProof,
  PaymentQuote,
  WalletSigner,
} from "./types.js";
import { UnsupportedRailError } from "./types.js";

export class MppPayer implements PaymentPayer {
  readonly rail = "mpp" as const;

  /**
   * Detection reserved. Returns false pending a stable MPP challenge shape.
   * -- VERIFY (MPP build time, SPEC §2): define MPP challenge detection here and
   *    add "mpp" to RAILS_ENABLED (constants.ts) before flipping this on.
   */
  detects(_challenge: ParsedChallenge): boolean {
    return false;
  }

  quotes(_challenge: ParsedChallenge): PaymentQuote[] {
    throw new UnsupportedRailError("mpp", "quotes");
  }

  buildPayment(
    _quote: PaymentQuote,
    _signer: WalletSigner,
    _deps: PayfetchDeps,
  ): Promise<PaymentProof> {
    throw new UnsupportedRailError("mpp", "buildPayment");
  }
}
