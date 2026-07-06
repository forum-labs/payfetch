/**
 * P3′ payfetch — LocalKeySigner tests (SPEC §14 "Signer").
 *
 * Hermetic (no network). Verifies address lowercasing, signature determinism,
 * and faithful delegation to the underlying viem account, using a WELL-KNOWN
 * TEST-ONLY key. This key is the standard Anvil/Hardhat account #1 — public,
 * unfunded on mainnet, and used here purely as a signing test vector. NEVER a
 * real key.
 */

import { privateKeyToAccount } from "viem/accounts";
import type { PrivateKeyAccount } from "viem/accounts";
import { getAddress } from "viem";
import { describe, expect, it } from "vitest";

import { chainIdForNetwork } from "../src/core/constants.js";
import { AUTHORIZATION_PRIMARY_TYPE, AUTHORIZATION_TYPES } from "../src/payer/x402.js";
import { LocalKeySigner } from "../src/payer/signer_local.js";
import type { Eip712TypedData } from "../src/payer/types.js";

// TEST-ONLY: Anvil/Hardhat account #1. Public knowledge; not a real wallet.
const TEST_PRIVATE_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
const TEST_ADDRESS_CHECKSUM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

function sampleTypedData(): Eip712TypedData {
  return {
    types: AUTHORIZATION_TYPES,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    domain: {
      name: "USD Coin",
      version: "2",
      chainId: chainIdForNetwork("base") ?? 0,
      verifyingContract: getAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    },
    message: {
      from: getAddress(TEST_ADDRESS_CHECKSUM),
      to: getAddress("0x000000000000000000000000000000000000bEEF"),
      value: "10000",
      validAfter: "1699999400",
      validBefore: "1700000000",
      nonce: `0x${"07".repeat(32)}`,
    },
  };
}

describe("LocalKeySigner", () => {
  it("kind is local_key and address() is lowercased", async () => {
    const signer = new LocalKeySigner(TEST_PRIVATE_KEY);
    expect(signer.kind).toBe("local_key");
    expect(await signer.address()).toBe(TEST_ADDRESS_CHECKSUM.toLowerCase());
  });

  it("produces a deterministic 65-byte signature (same input → same output)", async () => {
    const signer = new LocalKeySigner(TEST_PRIVATE_KEY);
    const td = sampleTypedData();
    const a = await signer.signTypedData(td);
    const b = await signer.signTypedData(td);
    expect(a).toBe(b);
    expect(a).toMatch(/^0x[0-9a-f]{130}$/i); // 65 bytes = r(32)+s(32)+v(1)
  });

  it("delegates faithfully to the underlying viem account", async () => {
    const signer = new LocalKeySigner(TEST_PRIVATE_KEY);
    const account = privateKeyToAccount(TEST_PRIVATE_KEY);
    const td = sampleTypedData();
    const viaSigner = await signer.signTypedData(td);
    const viaAccount = await account.signTypedData(
      td as Parameters<PrivateKeyAccount["signTypedData"]>[0],
    );
    expect(viaSigner).toBe(viaAccount);
  });
});
