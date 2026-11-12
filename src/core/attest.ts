import { inspectTransaction, type InspectedTransaction } from "@qorechain/qoresign/network";
import type { Network } from "./networks";
import { readRegistry, registryCheck } from "./registry";
import type { ScanResult } from "./scan";

/**
 * A readiness attestation is one hybrid-signed (secp256k1 + ML-DSA-87) native
 * transaction: a 1 uqor MsgSend from the account to itself whose memo records
 * the scan. The chain only accepts it if the account's registered ML-DSA-87 key
 * signed it, so the transaction itself proves the key is in place and in use.
 *
 * Memo (<= 256 bytes): `qday:v1;<subject qor1>;<grade>;<readiness>;<digest12>`
 */
export const MEMO_PREFIX = "qday:v1";
export const ATTEST_AMOUNT_UQOR = "1";
export const MSG_SEND_TYPE_URL = "/cosmos.bank.v1beta1.MsgSend";

export interface AttestationMemo {
  subject: string;
  grade: string;
  readiness: number;
  digest: string;
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Digest of the parts of a scan that decide its grade, so a memo can be checked against a re-scan. */
export async function scanDigest(r: ScanResult): Promise<string> {
  const canonical = JSON.stringify({
    subject: r.address.qor,
    chainId: r.chainId,
    pqc: r.pqc ? { alg: r.pqc.algorithm, h: r.pqc.registeredAtHeight, pop: r.pqc.possessionProven } : null,
    findings: r.findings.map((f) => f.id).sort(),
    readiness: r.readiness,
  });
  return (await sha256Hex(canonical)).slice(0, 12);
}

export async function buildMemo(r: ScanResult): Promise<string> {
  const memo = [MEMO_PREFIX, r.address.qor, r.grade, String(r.readiness), await scanDigest(r)].join(";");
  if (new TextEncoder().encode(memo).length > 256) throw new Error("Memo would exceed 256 bytes.");
  return memo;
}

export function parseMemo(memo: string): AttestationMemo | undefined {
  const parts = memo.split(";");
  if (parts.length !== 5 || parts[0] !== MEMO_PREFIX) return undefined;
  const readiness = Number(parts[3]);
  if (!/^qor1[02-9ac-hj-np-z]+$/.test(parts[1]) || !Number.isInteger(readiness)) return undefined;
  return { subject: parts[1], grade: parts[2], readiness, digest: parts[4] };
}

/** The MsgSend the attestation carries, as a plain EncodeObject (SDK / CosmJS form). */
export function attestationMsg(sender: string) {
  return {
    typeUrl: MSG_SEND_TYPE_URL,
    value: { fromAddress: sender, toAddress: sender, amount: [{ denom: "uqor", amount: ATTEST_AMOUNT_UQOR }] },
  };
}

export interface VerifiedAttestation {
  tx: InspectedTransaction;
  memo?: AttestationMemo;
  /** True only when the tx succeeded, carries the ML-DSA-87 layer and that layer verifies against the signer's registered key. */
  hybridVerified: boolean;
  checks: { label: string; ok: boolean | undefined; detail: string }[];
}

/**
 * Read a committed transaction and check it independently with QoreSign: the
 * classical signature, the ML-DSA-87 layer against the key the signer has
 * registered, and the attestation memo; then, where a QDayRegistry is deployed, whether the
 * contract holds this attestation (it re-checks the signature on chain before recording one).
 */
export async function verifyAttestation(txhash: string, net: Network, fetchImpl?: typeof fetch): Promise<VerifiedAttestation | undefined> {
  const hash = txhash.trim().replace(/^0x/i, "").toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(hash)) throw new Error("A transaction hash is 64 hex characters.");
  const tx = await inspectTransaction({
    rest: net.rest,
    rpc: fetchImpl ? undefined : net.rpc,
    chainId: net.chainId,
    txhash: hash,
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
  });
  if (!tx) return undefined;
  const memo = parseMemo(tx.memo);
  const pq = tx.pqLayer;
  const checks: VerifiedAttestation["checks"] = [
    { label: "Committed", ok: tx.code === 0, detail: tx.code === 0 ? `block ${tx.height.toLocaleString("en-US")}` : `failed with code ${tx.code} (${tx.codespace})` },
    {
      label: "Classical signature",
      ok: tx.classicalSignatureValid,
      detail: tx.signer ? `${tx.signer.keyType} key of ${tx.signer.address}` : "no signer info (EVM lane)",
    },
    {
      label: "ML-DSA-87 signature",
      ok: pq.present ? pq.verified : tx.tier === "enrollment" ? undefined : false,
      detail: pq.present
        ? pq.verified
          ? `verifies against the signer's registered key (sign-bytes ${pq.signBytesVersion})`
          : `present but does not verify${pq.reason ? `: ${pq.reason}` : ""} (a later key rotation also causes this)`
        : tx.tier === "enrollment"
          ? "none: this transaction registers the key, which the chain lets the classical key sign by design"
          : `no post-quantum layer (tier: ${tx.tier})`,
    },
    {
      label: "Q-Day attestation memo",
      ok: memo ? true : undefined,
      detail: memo ? `${memo.subject} graded ${memo.grade} (${memo.readiness}/100), scan ${memo.digest}` : "not a qday:v1 memo",
    },
  ];
  // The on-chain record, when this network has a QDayRegistry and the memo names the signer.
  if (net.registry && memo && tx.code === 0 && tx.signer?.address === memo.subject) {
    try {
      checks.push(registryCheck(net, hash, tx.signer.sequence, memo, await readRegistry(net, memo.subject, fetchImpl ?? fetch)));
    } catch (e) {
      checks.push({ label: "Recorded in QDayRegistry", ok: undefined, detail: `could not read the contract: ${(e as Error).message}` });
    }
  }
  return { tx, memo, hybridVerified: tx.code === 0 && pq.present && pq.verified === true, checks };
}
