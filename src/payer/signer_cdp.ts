/**
 * P3′ payfetch — CdpServerWalletSigner: a WalletSigner over a Coinbase CDP server
 * wallet (SPEC §2, §12; RESULTS.md `-- VERIFY cdp-signer`, RESOLVED).
 *
 * Purpose: sign EIP-712 typed data with the operator's CDP server wallet
 * (`PAYFETCH_CDP_*`, SPEC §12). The CDP EVM account exposes a viem-compatible
 * `signTypedData(...): Promise<Hex>` (@coinbase/cdp-sdk@1.51.2,
 * _types/accounts/evm/types.d.ts:39), which is all the WalletSigner seam needs.
 *
 * Invariants:
 *  - `kind === "cdp_server_wallet"`. `address()` returns the account address
 *    LOWERCASED (WalletSigner contract, SPEC §2).
 *  - LAZY-CONNECT: the constructor touches no network; the CdpClient and account
 *    are resolved on first `address()`/`signTypedData()` and cached (one connect).
 *  - KEY MATERIAL NEVER LEAKS: SDK errors are caught and RE-THROWN as a fresh
 *    Error whose message is scrubbed of the provided secrets and of any
 *    key-shaped substring (SPEC §12). The original error (which may carry secrets
 *    in config fields) is NOT attached as `cause`.
 */

import { CdpClient } from "@coinbase/cdp-sdk";

import { DEFAULT_CDP_ACCOUNT_NAME } from "../core/constants.js";
import type { Eip712TypedData, WalletSigner } from "./types.js";

/** Operator CDP credentials (SPEC §12 env; never config-file). */
export type CdpSignerConfig = {
  apiKeyId: string;
  apiKeySecret: string;
  walletSecret: string;
  accountName?: string; // PAYFETCH_CDP_ACCOUNT_NAME (optional); default below
};

/** The resolved CDP EVM account type (address + viem-compatible signTypedData). */
type CdpAccount = Awaited<ReturnType<CdpClient["evm"]["getOrCreateAccount"]>>;

export class CdpServerWalletSigner implements WalletSigner {
  readonly kind = "cdp_server_wallet" as const;

  readonly #apiKeyId: string;
  readonly #apiKeySecret: string;
  readonly #walletSecret: string;
  readonly #accountName: string;
  /** Cached lazy connection — resolved once, reused thereafter. */
  #accountPromise: Promise<CdpAccount> | null = null;

  constructor(config: CdpSignerConfig) {
    this.#apiKeyId = config.apiKeyId;
    this.#apiKeySecret = config.apiKeySecret;
    this.#walletSecret = config.walletSecret;
    this.#accountName =
      config.accountName && config.accountName.length > 0
        ? config.accountName
        : DEFAULT_CDP_ACCOUNT_NAME;
    // No network here (lazy-connect invariant).
  }

  async address(): Promise<string> {
    const account = await this.#account();
    return account.address.toLowerCase();
  }

  async signTypedData(td: Eip712TypedData): Promise<`0x${string}`> {
    const account = await this.#account();
    try {
      // Boundary cast at the SDK adapter seam (same rationale as LocalKeySigner):
      // our structural Eip712TypedData matches the SDK's runtime expectation, but
      // its `TypedDataDefinition` generic is stricter.
      return await account.signTypedData(
        td as Parameters<CdpAccount["signTypedData"]>[0],
      );
    } catch (err) {
      throw this.#scrubbedError(err, "CDP signTypedData failed");
    }
  }

  /** Lazily resolve (and cache) the named CDP EVM account; scrub any SDK error. */
  #account(): Promise<CdpAccount> {
    if (this.#accountPromise === null) {
      this.#accountPromise = this.#connect().catch((err: unknown) => {
        // Reset so a later call can retry a transient failure, but never leak.
        this.#accountPromise = null;
        throw this.#scrubbedError(err, "CDP account resolution failed");
      });
    }
    return this.#accountPromise;
  }

  async #connect(): Promise<CdpAccount> {
    const cdp = new CdpClient({
      apiKeyId: this.#apiKeyId,
      apiKeySecret: this.#apiKeySecret,
      walletSecret: this.#walletSecret,
    });
    return cdp.evm.getOrCreateAccount({ name: this.#accountName });
  }

  /**
   * Wrap an SDK error into a fresh Error with a scrubbed message. Redacts the
   * three provided secrets verbatim, then any key-shaped substring (long hex,
   * PEM blocks, long base64url tokens). Never attaches the original as `cause`.
   */
  #scrubbedError(err: unknown, context: string): Error {
    const raw = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return new Error(`${context}: ${this.#scrub(raw)}`);
  }

  #scrub(text: string): string {
    let out = text;
    for (const secret of [this.#apiKeySecret, this.#walletSecret, this.#apiKeyId]) {
      if (secret && secret.length > 0) out = out.split(secret).join("[redacted]");
    }
    // PEM private-key blocks.
    out = out.replace(
      /-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----/g,
      "[redacted-pem]",
    );
    // Long hex runs (private keys / secrets), 0x-optional, ≥ 32 hex chars.
    out = out.replace(/\b(?:0x)?[0-9a-fA-F]{32,}\b/g, "[redacted-hex]");
    // Long base64url tokens (≥ 40 chars) — CDP secrets/JWTs.
    out = out.replace(/\b[A-Za-z0-9_-]{40,}\b/g, "[redacted-token]");
    return out;
  }
}
