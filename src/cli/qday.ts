#!/usr/bin/env node
/**
 * qday: Q-Day readiness scanner for QoreChain accounts.
 *
 *   qday scan <qor1…|0x…> [more…] [--file list.txt] [--json] [--network testnet|mainnet|localnet]
 *   qday verify <txhash>
 *   qday keygen --key <file>          new 24-word key in a 0600 file; prints addresses only
 *   qday whoami --key <file>          address + scan of that key's account
 *   qday attest --key <file> [--dry-run]
 *        register the ML-DSA-87 key if needed, then send ONE hybrid-signed attestation tx
 */
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { splitAddresses } from "../core/addr";
import { buildMemo, verifyAttestation } from "../core/attest";
import { formatScan, toJson } from "../core/format";
import { networkByName, type Network } from "../core/networks";
import { formatQor, isScanResult, scanAddress, scanMany } from "../core/scan";
import { attestWithKey, loadKey, offlineSelfTest } from "./signer";

interface Args {
  cmd: string;
  positional: string[];
  flags: Record<string, string | true>;
}

function parseArgs(argv: string[]): Args {
  const [cmd = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      if (v !== undefined) flags[k] = v;
      else if (rest[i + 1] && !rest[i + 1].startsWith("--") && ["file", "network", "key"].includes(k)) flags[k] = rest[++i];
      else flags[k] = true;
    } else positional.push(a);
  }
  return { cmd, positional, flags };
}

const HELP = `qday: Q-Day readiness scanner for QoreChain

  qday scan <qor1…|0x…> [more…]   score accounts (or --file list.txt, one per line)
  qday verify <txhash>             check a transaction's hybrid signature and attestation memo
  qday keygen --key <file>         create a testnet key file (0600); prints addresses only
  qday whoami --key <file>         show and scan the key's account
  qday attest --key <file>         register the PQC key if needed, then send one hybrid-signed attestation
               [--dry-run]         build and verify the signed tx offline, broadcast nothing

  --network testnet|mainnet|localnet   (default testnet)
  --json                               machine-readable output
  The key file can also come from QDAY_KEY_FILE. It is never printed.`;

async function cmdScan(a: Args, net: Network) {
  let inputs = [...a.positional];
  if (typeof a.flags.file === "string") inputs.push(...splitAddresses(readFileSync(a.flags.file, "utf8")));
  inputs = splitAddresses(inputs.join(" "));
  if (!inputs.length) throw new Error("Give at least one qor1… or 0x… address.");
  const results = await scanMany(inputs, net);
  if (a.flags.json) {
    console.log(JSON.stringify(toJson(results), null, 2));
  } else {
    console.log(`Q-Day readiness · ${net.chainId} · ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC\n`);
    for (const r of results) console.log(isScanResult(r) ? formatScan(r) : `${r.input}\n  ERROR  ${r.error}`, "\n");
    const ok = results.filter(isScanResult);
    if (ok.length > 1) {
      const atRisk = ok.filter((r) => r.findings.some((f) => f.severity === "critical" || f.severity === "high"));
      console.log(`${ok.length} scanned · ${atRisk.length} need a post-quantum key now`);
    }
  }
  const worst = results.some((r) => !isScanResult(r)) ? 2 : results.filter(isScanResult).some((r) => r.findings.some((f) => f.severity === "critical")) ? 1 : 0;
  process.exitCode = worst;
}

async function cmdVerify(a: Args, net: Network) {
  const hash = a.positional[0];
  if (!hash) throw new Error("Give a transaction hash.");
  const v = await verifyAttestation(hash, net);
  if (!v) throw new Error(`${net.chainId} does not know transaction ${hash}.`);
  if (a.flags.json) return console.log(JSON.stringify(toJson(v), null, 2));
  console.log(`Transaction ${v.tx.txhash} on ${v.tx.chainId}`);
  for (const ch of v.checks) console.log(`  ${ch.ok === true ? "PASS" : ch.ok === false ? "FAIL" : " -- "}  ${ch.label}: ${ch.detail}`);
  if (v.memo) {
    const now = await scanAddress(v.memo.subject, net);
    console.log(`  Now:  ${v.memo.subject} grades ${now.grade} (${now.readiness}/100)`);
  }
  console.log(v.hybridVerified ? "\nHybrid-signed: yes (secp256k1 + ML-DSA-87)." : "\nHybrid-signed: NOT verified.");
  process.exitCode = v.hybridVerified ? 0 : 1;
}

async function cmdKeygen(a: Args) {
  const file = keyPath(a);
  if (existsSync(file)) throw new Error(`${file} exists; refusing to overwrite a key.`);
  const { generateMnemonic } = await import("@qorechain/sdk");
  writeFileSync(file, generateMnemonic(256) + "\n", { mode: 0o600, flag: "wx" });
  chmodSync(file, 0o600);
  const k = await loadKey(file);
  console.log(`New key written to ${file} (mode 600). Back it up; it is the only copy.`);
  console.log(`  native: ${k.address}\n  evm:    ${k.evmAddress}`);
}

async function cmdWhoami(a: Args, net: Network) {
  const k = await loadKey(keyPath(a));
  console.log(`native: ${k.address}\nevm:    ${k.evmAddress}\n`);
  console.log(formatScan(await scanAddress(k.address, net)));
}

async function cmdAttest(a: Args, net: Network) {
  const k = await loadKey(keyPath(a));
  if (a.flags["dry-run"]) {
    const before = await scanAddress(k.address, net);
    const memo = await buildMemo({ ...before, grade: "A", readiness: 100 });
    const t = await offlineSelfTest(k, net, memo);
    console.log(`Dry run for ${k.address} on ${net.chainId} (nothing broadcast)`);
    console.log(`  memo:              ${memo}`);
    console.log(`  sign-bytes:        ${t.signBytesVersion}`);
    console.log(`  tx size:           ${t.txBytes} bytes, ML-DSA-87 signature ${t.pqcSignatureBytes} bytes`);
    console.log(`  ML-DSA-87 verify:  ${t.pqcVerifies ? "PASS" : "FAIL"} (local, with the derived public key)`);
    console.log(`  balance now:       ${formatQor(before.liquidUqor)}; needs about ${formatQor(t.neededUqor)} (${before.pqc ? "send only" : "key registration + send"})`);
    return;
  }
  const res = await attestWithKey(k, net, (line) => console.log(line));
  console.log(`\nAttestation tx: ${res.txHash}\n  ${net.explorerTx(res.txHash)}${net.explorerNote ? ` (${net.explorerNote})` : ""}\n  ${net.restTx(res.txHash)}`);
  const v = await verifyAttestation(res.txHash, net);
  if (v) for (const ch of v.checks) console.log(`  ${ch.ok === true ? "PASS" : ch.ok === false ? "FAIL" : " -- "}  ${ch.label}: ${ch.detail}`);
}

function keyPath(a: Args): string {
  const p = typeof a.flags.key === "string" ? a.flags.key : process.env.QDAY_KEY_FILE;
  if (!p) throw new Error("Pass --key <file> or set QDAY_KEY_FILE.");
  return p;
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  const net = networkByName(typeof a.flags.network === "string" ? a.flags.network : undefined);
  switch (a.cmd) {
    case "scan":
      return cmdScan(a, net);
    case "verify":
      return cmdVerify(a, net);
    case "keygen":
      return cmdKeygen(a);
    case "whoami":
      return cmdWhoami(a, net);
    case "attest":
      return cmdAttest(a, net);
    default:
      console.log(HELP);
  }
}

main().catch((err) => {
  console.error(`qday: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 2;
});
