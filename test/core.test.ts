import assert from "node:assert/strict";
import { test } from "node:test";
// @ts-expect-error plain ESM module without type declarations
import { upstreamFor } from "../gateway.mjs";
import { parseAddress, splitAddresses } from "../src/core/addr";
import { buildMemo, parseMemo } from "../src/core/attest";
import { NETWORKS } from "../src/core/networks";
import { assess, enforcesHybrid, isScanResult, ML_DSA_87_PUBLIC_KEY_BYTES, parsePolicy, projectAfterRegistration, type Raw } from "../src/core/scan";

const NET = NETWORKS.testnet;
const QOR = "qor1p2pkkdjkg3486c87skry656ys5wharvz9hwkxm";
const EVM = "0x0a836b3656446a7d60fe85864d5344851d7e8d82";
const PUB = { "@type": "/cosmos.crypto.secp256k1.PubKey", key: "A0" };
const PQC = { algorithm_name: "dilithium5", key_type: "hybrid", created_at_height: "100", possession_proven: true };
const raw = (r: Partial<Raw>): Raw => ({ warnings: [], code: "0x", ...r });
const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

test("parseAddress converts between qor1 and 0x", () => {
  assert.equal(parseAddress(QOR).evm, EVM);
  assert.equal(parseAddress(EVM).qor, QOR);
  assert.equal(parseAddress(EVM.toUpperCase().replace("0X", "0x")).qor, QOR);
  assert.throws(() => parseAddress(QOR.slice(0, -1) + "q"));
  assert.throws(() => parseAddress("cosmos1abc"));
});

test("splitAddresses dedupes and skips comments", () => {
  assert.deepEqual(splitAddresses(`${QOR}, ${QOR.toUpperCase()}\n# note\n${EVM};`), [QOR, EVM]);
});

test("funded account with a public ECDSA key and no PQC key is critical", () => {
  const r = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB, sequence: "3" }, balances: [{ denom: "uqor", amount: "150000" }] }));
  assert.deepEqual(ids(r), ["no-pqc-key-exposed"]);
  assert.equal(r.grade, "F");
  assert.equal(r.readiness, 15);
});

test("funded account without a published key is high, empty one low, unseen info", () => {
  const funded = assess(parseAddress(QOR), NET, raw({ auth: { sequence: "0" }, balances: [{ denom: "uqor", amount: "1" }] }));
  assert.deepEqual([ids(funded), funded.grade], [["no-pqc-key"], "D"]);
  const empty = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, balances: [] }));
  assert.deepEqual([ids(empty), empty.grade], [["no-pqc-key-empty"], "B"]);
  const unseen = assess(parseAddress(QOR), NET, raw({ auth: null, balances: [] }));
  assert.equal(unseen.kind, "unseen");
  assert.equal(unseen.grade, "A");
});

test("registered account scores A; a missing possession proof costs 3", () => {
  const r = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: PQC, balances: [{ denom: "uqor", amount: "5" }] }));
  assert.deepEqual([ids(r), r.readiness], [["pqc-registered"], 100]);
  const noPop = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: { ...PQC, possession_proven: false } }));
  assert.equal(noPop.readiness, 97);
});

const REQUIRED = { hybrid_signature_mode: 2, hybrid_signature_mode_name: "required", allow_classical_fallback: false, min_security_level: 5, default_signature_algo_name: "dilithium5" };
const b64 = (n: number) => Buffer.alloc(n, 7).toString("base64");

test("network policy: parsed from qorechain/pqc/v1/params; registered keys lose points when hybrid is optional", () => {
  assert.deepEqual(parsePolicy(REQUIRED), { hybridMode: "required", classicalFallback: false, minSecurityLevel: 5, defaultAlgorithm: "ML-DSA-87" });
  assert.equal(parsePolicy({ hybrid_signature_mode: 1 })?.hybridMode, "optional");
  assert.equal(parsePolicy(null), undefined);
  assert.ok(enforcesHybrid(parsePolicy(REQUIRED)!));
  assert.ok(!enforcesHybrid(parsePolicy({ ...REQUIRED, allow_classical_fallback: true })!));
  const ok = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: PQC, policy: REQUIRED }));
  assert.deepEqual([ids(ok), ok.readiness, ok.policy?.hybridMode], [["pqc-registered"], 100, "required"]);
  const optional = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: PQC, policy: { ...REQUIRED, hybrid_signature_mode: 1, hybrid_signature_mode_name: "optional" } }));
  assert.ok(ids(optional).includes("network-not-enforcing"));
  assert.equal(optional.readiness, 80);
  // Policy does not change the grade of an account without a key: its own finding already covers it.
  const bare = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, balances: [{ denom: "uqor", amount: "1" }], policy: { ...REQUIRED, hybrid_signature_mode_name: "optional" } }));
  assert.deepEqual(ids(bare), ["no-pqc-key-exposed"]);
});

test("registered key: size check, fingerprint and classical binding", () => {
  const good = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: { ...PQC, public_key: b64(ML_DSA_87_PUBLIC_KEY_BYTES), ecdsa_pubkey: PUB.key }, pqcKeyDigest: "00112233aabbccdd" }));
  assert.deepEqual([ids(good), good.pqc?.publicKeyBytes, good.pqc?.classicalBinding, good.pqc?.fingerprint], [["pqc-registered"], 2592, "matches", "00112233aabbccdd"]);
  assert.match(good.findings[0].detail, /2,592 bytes, SHA-256 `00112233aabbccdd`, bound to this account's own secp256k1 key/);
  const short = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: { ...PQC, public_key: b64(1952) } }));
  assert.ok(ids(short).includes("pqc-key-size"));
  assert.equal(short.grade, "C");
  const other = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: { ...PQC, ecdsa_pubkey: "Bxx" } }));
  assert.deepEqual([other.pqc?.classicalBinding, other.readiness], ["differs", 95]);
});

test("EIP-7702 delegated account is an account, not a contract", () => {
  const code = "0xef0100" + "00".repeat(19) + "aa";
  const r = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: PQC, code, delegateHasCode: false }));
  assert.equal(r.kind, "account");
  const c = assess(parseAddress(QOR), NET, raw({ code: "0x6080" }));
  assert.equal(c.kind, "contract");
  assert.equal(c.grade, "n/a");
});

test("fest ERC-20 bank denoms count as value with symbols", () => {
  const r = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, balances: [{ denom: "erc20:0x97143b771d34ddb9130b807b135ae675a5a963ca", amount: "2500000" }] }));
  assert.equal(r.findings[0].id, "no-pqc-key-exposed");
});

test("projectAfterRegistration drops the no-key findings", () => {
  const r = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, balances: [{ denom: "uqor", amount: "1" }] }));
  const p = projectAfterRegistration(r);
  assert.equal(p.findings[0].id, "pqc-registered");
  assert.ok(!ids(p).includes("no-pqc-key-exposed"));
  assert.ok(p.readiness > r.readiness);
});

test("isScanResult skips the empty slots of a progressive scan", () => {
  const r = assess(parseAddress(QOR), NET, raw({}));
  const rows: (typeof r | { input: string; error: string } | undefined)[] = [];
  rows[2] = r; // third account answered first
  rows[0] = { input: "x", error: "bad address" };
  assert.deepEqual([...rows].filter(isScanResult), [r]);
});

test("attestation memo round-trips and stays within 256 bytes", async () => {
  const r = assess(parseAddress(QOR), NET, raw({ auth: { pub_key: PUB }, pqc: PQC }));
  const memo = await buildMemo(r);
  assert.ok(new TextEncoder().encode(memo).length <= 256);
  assert.deepEqual(parseMemo(memo), { subject: QOR, grade: "A", readiness: 100, digest: memo.split(";")[4] });
  assert.equal(parseMemo("hello"), undefined);
  assert.equal(parseMemo(`qday:v1;notqor;A;100;x`), undefined);
});

test("gateway allows only read routes and rejects path tricks", () => {
  assert.equal(upstreamFor(`/chain/testnet/rest/cosmos/bank/v1beta1/balances/${QOR}`), `https://api-testnet.qore.host/cosmos/bank/v1beta1/balances/${QOR}`);
  assert.ok(upstreamFor("/chain/mainnet/rpc/tx?hash=0xAB"));
  for (const bad of [
    "/chain/testnet/rest/cosmos/gov/v1/proposals",
    "/chain/testnet/rest/cosmos/auth/v1beta1/../../../cosmos/gov/v1/proposals",
    "/chain/testnet/rest/cosmos/auth/v1beta1/%2e%2e/x",
    "/chain/testnet/rest/cosmos/auth/v1beta1//x",
    "/chain/testnet/rpc/broadcast_tx_sync?tx=00",
    "/chain/devnet/rest/cosmos/auth/v1beta1/accounts",
    "/etc/passwd",
  ]) assert.equal(upstreamFor(bad), undefined, bad);
});

test("registry check matches a record to its transaction, and says when a newer one replaced it", async () => {
  const { registryCheck } = await import("../src/core/registry");
  const { qdayRegistryAbi } = await import("../contracts/contracts/QDayRegistry.artifact");
  const fns = qdayRegistryAbi.filter((x) => x.type === "function").map((x) => x.name);
  for (const f of ["record", "latest", "count", "isReady", "qorAddress"]) assert.ok(fns.includes(f as never), f);
  const memo = { subject: QOR, grade: "A", readiness: 100, digest: "70b31e56bd69" };
  const tx = "6B8EED3EC26B019CB9485BEFFC6B5F81DB04A59F54703A404DB539852ED045F8";
  const rec = { count: 2, signBytesHash: "0x00", keyHash: "0x00", nativeTx: tx, sequence: 2n, blockNumber: 9939327n, readiness: 100, grade: "A", digest: "70b31e56bd69" } as const;
  assert.equal(registryCheck(NET, tx.toLowerCase(), 2n, memo, { ...rec }).ok, true);
  assert.equal(registryCheck(NET, tx, 2n, { ...memo, readiness: 99 }, { ...rec }).ok, false);
  const older = registryCheck(NET, "3DC0994B1BFF78D1ECA2D90CFCE02DF08CA54A0FDADAFA87BB23A6C769D2113B", 1n, memo, { ...rec });
  assert.equal(older.ok, undefined);
  assert.match(older.detail, /newer attestation/);
  assert.equal(registryCheck(NET, tx, 2n, memo, undefined).ok, undefined);
});
