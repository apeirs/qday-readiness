import assert from "node:assert/strict";
import { test } from "node:test";
// @ts-expect-error plain ESM module without type declarations
import { upstreamFor } from "../gateway.mjs";
import { parseAddress, splitAddresses } from "../src/core/addr";
import { buildMemo, parseMemo } from "../src/core/attest";
import { NETWORKS } from "../src/core/networks";
import { assess, projectAfterRegistration, type Raw } from "../src/core/scan";

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
