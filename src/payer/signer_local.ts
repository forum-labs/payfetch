/**
 * P3′ payfetch — LocalKeySigner: a WalletSigner over a viem local account (SPEC
 * §2, §12).
 *
 * Purpose: sign EIP-712 typed data with an operator-supplied private key
 * (`PAYFETCH_PRIVATE_KEY` / `PAYFETCH_KEY_FILE`, SPEC §12). The bounded-authority
 * property (SPEC §2) lives in x402.ts; this module only wires the key to viem.
 *
 * Invariants:
 *  - `kind === "local_key"`. `address()` returns the account address LOWERCASED
 *    (WalletSigner contract, SPEC §2).
 *  - Key material never leaves this object: the private key is held only inside
 *    the viem account and is never logged, stringified, or placed in errors.
 *    (`deps.log` is typed to never receive the signer — SPEC §1/§12.)
 */

import { privateKeyToAccount } from "viem/accounts";
import type { PrivateKeyAccount } from "viem/accounts";

import type { Eip712TypedData, WalletSigner } from "./types.js";

export class LocalKeySigner implements WalletSigner {
  readonly kind = "local_key" as const;
  readonly #account: PrivateKeyAccount;

  /** @param privateKey 0x-hex private key (SPEC §12: `PAYFETCH_PRIVATE_KEY`). */
  constructor(privateKey: `0x${string}`) {
    this.#account = privateKeyToAccount(privateKey);
  }

  async address(): Promise<string> {
    return this.#account.address.toLowerCase();
  }

  async signTypedData(td: Eip712TypedData): Promise<`0x${string}`> {
    // Boundary cast: our structural `Eip712TypedData` matches viem's runtime
    // expectation, but viem's `TypedDataDefinition` is a stricter generic. The
    // x402 exact scheme builds this exact shape (see x402.ts, mirrored from the
    // pinned package). Justified single cast at the SDK adapter seam.
    return this.#account.signTypedData(
      td as Parameters<PrivateKeyAccount["signTypedData"]>[0],
    );
  }
}
