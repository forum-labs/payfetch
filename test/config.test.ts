/**
 * P3′ payfetch — config / env-resolution tests (SPEC §12).
 *
 * Covers: each signer source alone builds; zero → refuse; two → refuse;
 * incomplete CDP → refuse; PAYFETCH_KEY_FILE group/world-readable → refuse
 * (real mkdtemp + chmod); the refusal errors name the three options; the flag
 * env (data dir / test mode / approver / via); and the key-material scrub — a
 * fake key value never appears in a thrown error message (automated).
 */

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  ConfigError,
  ENV,
  buildFromEnv,
  realConfigIo,
  resolveDataDir,
  scrubSecrets,
  selectSignerSource,
  type ConfigIo,
  type EnvRecord,
} from "../src/config.js";

// A well-known valid secp256k1 test key (Hardhat account #0). Never used to sign
// anything real; construction only.
const VALID_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/** A fake ConfigIo whose fs is unused (private-key / CDP paths don't touch disk). */
function testIo(over: Partial<ConfigIo> = {}): ConfigIo {
  return {
    readText: over.readText ?? ((p) => {
      throw new Error(`readText not configured for ${p}`);
    }),
    statMode: over.statMode ?? (() => null),
    homedir: over.homedir ?? (() => "/home/tester"),
    fetch: over.fetch ?? ((async () => new Response(null)) as typeof fetch),
    now: over.now ?? (() => 0),
    random: over.random ?? (() => new Uint8Array(32)),
    log: over.log ?? (() => {}),
  };
}

const tmpDirs: string[] = [];
function mkKeyFile(contents: string, mode: number): string {
  const dir = mkdtempSync(join(tmpdir(), "payfetch-key-"));
  tmpDirs.push(dir);
  const path = join(dir, "wallet.key");
  writeFileSync(path, contents);
  chmodSync(path, mode);
  return path;
}
afterEach(() => {
  while (tmpDirs.length) rmSync(tmpDirs.pop()!, { recursive: true, force: true });
});

describe("selectSignerSource (SPEC §12)", () => {
  it("selects the single configured source", () => {
    expect(selectSignerSource({ [ENV.PRIVATE_KEY]: VALID_KEY })).toBe("private_key");
    expect(selectSignerSource({ [ENV.KEY_FILE]: "/x/key" })).toBe("key_file");
    expect(
      selectSignerSource({
        [ENV.CDP_API_KEY_ID]: "id",
        [ENV.CDP_API_KEY_SECRET]: "sec",
        [ENV.CDP_WALLET_SECRET]: "ws",
      }),
    ).toBe("cdp");
  });

  it("refuses ZERO sources, naming all three options", () => {
    let err: unknown;
    try {
      selectSignerSource({});
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfigError);
    const msg = (err as Error).message;
    expect(msg).toContain(ENV.PRIVATE_KEY);
    expect(msg).toContain(ENV.KEY_FILE);
    expect(msg).toContain(ENV.CDP_API_KEY_ID);
  });

  it("refuses TWO sources (ambiguous — never guesses the wallet)", () => {
    expect(() =>
      selectSignerSource({ [ENV.PRIVATE_KEY]: VALID_KEY, [ENV.KEY_FILE]: "/x/key" }),
    ).toThrow(ConfigError);
    expect(() =>
      selectSignerSource({ [ENV.PRIVATE_KEY]: VALID_KEY, [ENV.CDP_API_KEY_ID]: "id" }),
    ).toThrow(/EXACTLY ONE/i);
  });

  it("refuses an INCOMPLETE CDP source, naming the missing vars", () => {
    let err: unknown;
    try {
      selectSignerSource({ [ENV.CDP_API_KEY_ID]: "id" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfigError);
    const msg = (err as Error).message;
    expect(msg).toContain(ENV.CDP_API_KEY_SECRET);
    expect(msg).toContain(ENV.CDP_WALLET_SECRET);
  });
});

describe("buildFromEnv — each signer source alone (SPEC §12)", () => {
  it("PAYFETCH_PRIVATE_KEY alone → local_key signer", () => {
    const opts = buildFromEnv({ [ENV.PRIVATE_KEY]: VALID_KEY }, testIo());
    expect(opts.deps.signer.kind).toBe("local_key");
    expect(opts.deps.dataDir).toBe("/home/tester/.payfetch");
    expect(opts.testMode).toBe(false);
    expect(opts.approver).toBe(false);
    expect(opts.via).toBeNull();
  });

  it("PAYFETCH_KEY_FILE (mode 600) alone → local_key signer", () => {
    const path = mkKeyFile(`${VALID_KEY}\n`, 0o600);
    const opts = buildFromEnv({ [ENV.KEY_FILE]: path }, realConfigIo());
    expect(opts.deps.signer.kind).toBe("local_key");
  });

  it("CDP creds alone → cdp_server_wallet signer (no network)", () => {
    const opts = buildFromEnv(
      {
        [ENV.CDP_API_KEY_ID]: "id",
        [ENV.CDP_API_KEY_SECRET]: "secret",
        [ENV.CDP_WALLET_SECRET]: "walletsecret",
        [ENV.CDP_ACCOUNT_NAME]: "buyer",
      },
      testIo(),
    );
    expect(opts.deps.signer.kind).toBe("cdp_server_wallet");
  });

  it("zero and two sources both refuse via buildFromEnv", () => {
    expect(() => buildFromEnv({}, testIo())).toThrow(ConfigError);
    expect(() =>
      buildFromEnv({ [ENV.PRIVATE_KEY]: VALID_KEY, [ENV.KEY_FILE]: "/x" }, testIo()),
    ).toThrow(ConfigError);
  });
});

describe("buildFromEnv — key-file permission refusal (SPEC §12)", () => {
  it("refuses a WORLD-readable key file (mode 644)", () => {
    const path = mkKeyFile(VALID_KEY, 0o644);
    expect(() => buildFromEnv({ [ENV.KEY_FILE]: path }, realConfigIo())).toThrow(
      /group\/world-readable/,
    );
  });

  it("refuses a GROUP-readable key file (mode 640)", () => {
    const path = mkKeyFile(VALID_KEY, 0o640);
    expect(() => buildFromEnv({ [ENV.KEY_FILE]: path }, realConfigIo())).toThrow(ConfigError);
  });

  it("refuses a missing key file", () => {
    expect(() => buildFromEnv({ [ENV.KEY_FILE]: "/no/such/key" }, realConfigIo())).toThrow(
      /not found/,
    );
  });
});

describe("buildFromEnv — flag env (SPEC §12)", () => {
  const base: EnvRecord = { [ENV.PRIVATE_KEY]: VALID_KEY };

  it("PAYFETCH_DATA_DIR overrides the default", () => {
    const opts = buildFromEnv({ ...base, [ENV.DATA_DIR]: "/custom/dir" }, testIo());
    expect(opts.deps.dataDir).toBe("/custom/dir");
  });

  it("PAYFETCH_TEST_MODE presence enables test mode", () => {
    expect(buildFromEnv({ ...base, [ENV.TEST_MODE]: "1" }, testIo()).testMode).toBe(true);
    expect(buildFromEnv({ ...base, [ENV.TEST_MODE]: "" }, testIo()).testMode).toBe(true);
    expect(buildFromEnv(base, testIo()).testMode).toBe(false);
  });

  it("PAYFETCH_APPROVER=1 enables approver; other values do not", () => {
    expect(buildFromEnv({ ...base, [ENV.APPROVER]: "1" }, testIo()).approver).toBe(true);
    expect(buildFromEnv({ ...base, [ENV.APPROVER]: "0" }, testIo()).approver).toBe(false);
    expect(buildFromEnv({ ...base, [ENV.APPROVER]: "yes" }, testIo()).approver).toBe(false);
  });

  it("PAYFETCH_VIA is threaded (trimmed) or null", () => {
    expect(buildFromEnv({ ...base, [ENV.VIA]: " langchain " }, testIo()).via).toBe("langchain");
    expect(buildFromEnv(base, testIo()).via).toBeNull();
  });

  it("resolveDataDir falls back to ~/.payfetch", () => {
    expect(resolveDataDir({}, () => "/home/x")).toBe("/home/x/.payfetch");
    expect(resolveDataDir({ [ENV.DATA_DIR]: "/d" }, () => "/home/x")).toBe("/d");
  });
});

describe("key-material scrub (SPEC §12 key hygiene)", () => {
  it("scrubSecrets redacts the exact secret literal and key-shaped substrings", () => {
    const secret = "supersecretwalletvalue123456";
    const hex = "deadbeefcafe1234deadbeefcafe1234deadbeef";
    const scrubbed = scrubSecrets(`boom ${secret} and 0x${hex} and ${hex}`, [secret]);
    expect(scrubbed).not.toContain(secret);
    expect(scrubbed).not.toContain(hex);
  });

  it("an invalid private key never leaks into the thrown error message", () => {
    const marker = "LEAKMARKERsupersecretkeyvalue999";
    const fakeKey = `0x${marker}`;
    let err: unknown;
    try {
      buildFromEnv({ [ENV.PRIVATE_KEY]: fakeKey }, testIo());
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfigError);
    expect((err as Error).message).not.toContain(marker);
    expect((err as Error).message).not.toContain(fakeKey);
  });
});
