import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { deriveUnifiedAccount, generatePqcKeypair, unifiedAccountFromSeed } from "@qorechain/sdk";
import { sha256Hex16 } from "../src/core/scan";
import { ecdsaDerivedPqcKey, pqcKeyCandidates, pqcKeyOrigin } from "../src/cli/signer";

// A fixed test mnemonic (BIP-39 test vector). It holds nothing on any network.
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const bytes = (h: string) => Uint8Array.from(h.replace(/^0x/, "").match(/../g)!, (b) => parseInt(b, 16));

/** Run the CLI offline; every case here fails before any network call. */
function qday(...args: string[]) {
  const r = spawnSync(process.execPath, ["--import", "tsx", "src/cli/qday.ts", ...args], { encoding: "utf8", env: { ...process.env, QDAY_KEY_FILE: "" } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("ecdsaDerivedPqcKey reproduces the SDK's pre-0.13.0 seed derivation", async () => {
  const acct = await deriveUnifiedAccount(MNEMONIC, 0);
  const sdk = unifiedAccountFromSeed(bytes(acct.privateKey), { legacySeedDerivation: true });
  assert.equal(sdk.cosmos, acct.cosmos);
  assert.deepEqual(ecdsaDerivedPqcKey(acct.cosmos, bytes(acct.privateKey)).publicKey, sdk.pqc.publicKey);
});

test("whoami's key-origin check tells an ECDSA-derived ML-DSA-87 key from the address-bound one", async () => {
  const acct = await deriveUnifiedAccount(MNEMONIC, 0);
  const candidates = pqcKeyCandidates(acct.cosmos, MNEMONIC, bytes(acct.privateKey));
  // What deriveUnifiedAccount (and so `qday attest`) registers is the address-bound key.
  assert.deepEqual(candidates["address-bound"], acct.pqc.publicKey);
  for (const origin of ["address-bound", "mnemonic-only", "ecdsa-derived"] as const) {
    assert.equal(await pqcKeyOrigin(await sha256Hex16(new Uint8Array(candidates[origin])), candidates), origin);
  }
  const unrelated = generatePqcKeypair(new Uint8Array(32).fill(1)).publicKey;
  assert.equal(await pqcKeyOrigin(await sha256Hex16(new Uint8Array(unrelated)), candidates), "other");
  assert.notDeepEqual(candidates["ecdsa-derived"], candidates["address-bound"]);
});

test("CLI: a missing key file gets a clear message and the keygen command, not a raw ENOENT", () => {
  for (const cmd of [["whoami"], ["attest", "--dry-run"], ["record", "AB"]]) {
    const r = qday(...cmd, "--key", "no-such-dir/missing.key");
    assert.equal(r.code, 2, cmd.join(" "));
    assert.match(r.err, /Key file no-such-dir\/missing\.key not found\. Create a testnet key with `qday keygen --key no-such-dir\/missing\.key`/);
    assert.doesNotMatch(r.err, /ENOENT/);
  }
});

test("CLI: a key file other users can read is refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "qday-"));
  try {
    const file = join(dir, "k.key");
    writeFileSync(file, MNEMONIC, { mode: 0o644 });
    const r = qday("whoami", "--key", file);
    assert.equal(r.code, 2);
    assert.match(r.err, /readable by others; run chmod 600/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: scanning only invalid input does not claim the network policy was unreadable", () => {
  const r = qday("scan", "notanaddress");
  assert.equal(r.code, 2);
  assert.match(r.out, /"notanaddress" is not a qor1… or 0x… address/);
  assert.doesNotMatch(r.out, /Network policy/);
});

test("CLI: an unknown command fails with exit 2 instead of printing help as success", () => {
  const r = qday("scna", "qor1x");
  assert.equal(r.code, 2);
  assert.match(r.err, /unknown command "scna"/);
  assert.equal(qday("help").code, 0);
  assert.equal(qday().code, 0);
});
