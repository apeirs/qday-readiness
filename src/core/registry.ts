import { decodeFunctionResult, encodeFunctionData, type Hex } from "viem";
import { qdayRegistryAbi } from "../../contracts/contracts/QDayRegistry.artifact";
import { parseAddress } from "./addr";
import type { AttestationMemo } from "./attest";
import type { Network } from "./networks";

/**
 * QDayRegistry (contracts/contracts/QDayRegistry.sol) is the on-chain record of attestations. It
 * accepts one only after checking, through the chain's PQC precompiles, that the account's
 * registered ML-DSA-87 key signed the attestation transaction, and it parses the grade from the
 * signed memo itself. Reads go straight to the public EVM JSON-RPC (it allows any origin).
 */
export interface RegistryRecord {
  count: number;
  signBytesHash: Hex;
  keyHash: Hex;
  nativeTx: string;
  sequence: bigint;
  blockNumber: bigint;
  readiness: number;
  grade: string;
  digest: string;
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

async function ethCall(net: Network, data: Hex, fetchImpl: FetchLike): Promise<Hex> {
  if (!net.evmRpc || !net.registry) throw new Error(`No QDayRegistry on ${net.chainId}.`);
  const res = await fetchImpl(net.evmRpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: net.registry, data }, "latest"] }),
  });
  if (!res.ok) throw new Error(`EVM RPC answered HTTP ${res.status}.`);
  const j = (await res.json()) as { result?: Hex; error?: { message?: string } };
  if (!j.result) throw new Error(`EVM RPC error: ${j.error?.message ?? "no result"}`);
  return j.result;
}

/** The latest record for a qor1 account, or undefined when it has none. */
export async function readRegistry(net: Network, qorAddress: string, fetchImpl: FetchLike = fetch): Promise<RegistryRecord | undefined> {
  const evm = parseAddress(qorAddress)?.evm as Hex | undefined;
  if (!evm) throw new Error(`${qorAddress} is not an account address.`);
  const countHex = await ethCall(net, encodeFunctionData({ abi: qdayRegistryAbi, functionName: "count", args: [evm] }), fetchImpl);
  const count = Number(decodeFunctionResult({ abi: qdayRegistryAbi, functionName: "count", data: countHex }));
  if (!count) return undefined;
  const latestHex = await ethCall(net, encodeFunctionData({ abi: qdayRegistryAbi, functionName: "latest", args: [evm] }), fetchImpl);
  const [signBytesHash, keyHash, nativeTx, sequence, blockNumber, readiness, grade, digest] = decodeFunctionResult({
    abi: qdayRegistryAbi,
    functionName: "latest",
    data: latestHex,
  });
  return {
    count,
    signBytesHash,
    keyHash,
    nativeTx: nativeTx.slice(2).toUpperCase(),
    sequence,
    blockNumber,
    readiness,
    grade: String.fromCharCode(parseInt(grade.slice(2), 16)),
    digest: digest.slice(2),
  };
}

/** The Verify row for the registry: does its latest record for the signer match this transaction? */
export function registryCheck(
  net: Network,
  txhash: string,
  sequence: bigint | undefined,
  memo: AttestationMemo,
  rec: RegistryRecord | undefined,
): { label: string; ok: boolean | undefined; detail: string } {
  const label = "Recorded in QDayRegistry";
  const where = `contract ${net.registry}`;
  if (!rec) return { label, ok: undefined, detail: `not relayed to ${where} yet (anyone can: qday record ${txhash.slice(0, 8)}…)` };
  const same = rec.nativeTx === txhash.toUpperCase() && (sequence === undefined || rec.sequence === sequence);
  if (same) {
    const fields = rec.grade === memo.grade && rec.readiness === memo.readiness && rec.digest === memo.digest;
    return {
      label,
      ok: fields,
      detail: fields
        ? `the contract checked this transaction's ML-DSA-87 signature on chain and holds grade ${rec.grade}, readiness ${rec.readiness} (EVM block ${rec.blockNumber.toLocaleString("en-US")})`
        : `the record for this transaction holds grade ${rec.grade}, readiness ${rec.readiness}, which differs from the memo`,
    };
  }
  if (sequence !== undefined && rec.sequence > sequence) {
    return { label, ok: undefined, detail: `a newer attestation is on record (${rec.nativeTx.slice(0, 8)}…, grade ${rec.grade}, readiness ${rec.readiness})` };
  }
  return { label, ok: undefined, detail: `the latest record is ${rec.nativeTx.slice(0, 8)}…, not this transaction` };
}
