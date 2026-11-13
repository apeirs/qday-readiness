/**
 * File-key signing for the CLI (Node only). The mnemonic is read from a 0600
 * file, kept in memory, and never printed or logged. QoreX users never need
 * this: the web app asks the wallet to sign instead.
 */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { Registry } from "@cosmjs/proto-signing";
import { defaultRegistryTypes } from "@cosmjs/stargate";
import {
  buildHybridTx,
  createClient,
  deriveNativeAccount,
  derivePqcCanonical,
  derivePqcLegacy,
  deriveUnifiedAccount,
  generatePqcKeypair,
  directSignerFromPrivateKey,
  ensurePqcRegistered,
  pqcVerify,
  qorToEvm,
  validateMnemonic,
  type PqcKeypair,
  type UnifiedAccount,
} from "@qorechain/sdk";
import { attestationMsg, buildMemo } from "../core/attest";
import { getJson } from "../core/http";
import type { Network } from "../core/networks";
import { formatQor, scanAddress, sha256Hex16 } from "../core/scan";

export interface LoadedKey {
  address: string;
  evmAddress: string;
  privateKey: Uint8Array;
  pqc: PqcKeypair;
}

/** Fees on Diana: MsgRegisterPQCKeyV2 needs ~600k gas, a hybrid MsgSend ~300k, at 0.1-0.15 uqor/gas. */
export const REGISTER_FEE_UQOR = 90_000n;
const SEND_FEE_UQOR = 60_000n;

function readMnemonic(file: string): string {
  let st;
  try {
    st = statSync(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`Key file ${file} not found. Create a testnet key with \`qday keygen --key ${file}\`, or pass --key <file> holding a 24-word mnemonic (mode 600).`);
    }
    throw err;
  }
  if ((st.mode & 0o077) !== 0) throw new Error(`${file} is readable by others; run chmod 600 on it.`);
  const mnemonic = readFileSync(file, "utf8").trim().split(/\s+/).join(" ");
  if (!validateMnemonic(mnemonic)) throw new Error(`${file} does not hold a valid BIP-39 mnemonic.`);
  return mnemonic;
}

export async function loadKey(file: string): Promise<LoadedKey> {
  const mnemonic = readMnemonic(file);
  const acct = await deriveNativeAccount(mnemonic);
  return {
    address: acct.address,
    evmAddress: qorToEvm(acct.address),
    privateKey: acct.privateKey,
    pqc: derivePqcCanonical(acct.address, mnemonic),
  };
}

/**
 * Where a registered ML-DSA-87 key came from, as far as this key file can tell:
 * - "address-bound": the SDK's current derivation from the mnemonic and the address (what `qday attest` registers);
 * - "mnemonic-only": the deprecated "bridge" derivation from the mnemonic alone (rotate it);
 * - "ecdsa-derived": computed from the account's secp256k1 private key, as SDK releases before 0.13.0 did for
 *   private-key accounts. A quantum attacker who recovers the ECDSA key then gets the ML-DSA-87 key too;
 * - "other": not derivable from this file (another wallet or derivation registered it).
 */
export type PqcKeyOrigin = "address-bound" | "mnemonic-only" | "ecdsa-derived" | "other";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** The pre-0.13.0 seed derivation of `unifiedAccountFromSeed`: SHAKE256("qorechain:pqc:v1|<qor1>|seed:<private key hex>"). */
export function ecdsaDerivedPqcKey(address: string, privateKey: Uint8Array): PqcKeypair {
  const seed = createHash("shake256", { outputLength: 32 }).update(`qorechain:pqc:v1|${address}|seed:${hex(privateKey)}`).digest();
  return generatePqcKeypair(new Uint8Array(seed));
}

/** The candidate keys this key file could have registered for `address`, by origin. */
export function pqcKeyCandidates(address: string, mnemonic: string, privateKey: Uint8Array): Record<Exclude<PqcKeyOrigin, "other">, Uint8Array> {
  return {
    "address-bound": derivePqcCanonical(address, mnemonic).publicKey,
    "mnemonic-only": derivePqcLegacy(mnemonic).publicKey,
    "ecdsa-derived": ecdsaDerivedPqcKey(address, privateKey).publicKey,
  };
}

/** Match a registered key's fingerprint (first 16 hex of its SHA-256) against the candidates. */
export async function pqcKeyOrigin(fingerprint: string, candidates: Partial<Record<PqcKeyOrigin, Uint8Array>>): Promise<PqcKeyOrigin> {
  for (const [origin, publicKey] of Object.entries(candidates)) {
    if ((await sha256Hex16(new Uint8Array(publicKey))) === fingerprint) return origin as PqcKeyOrigin;
  }
  return "other";
}

export const PQC_ORIGIN_TEXT: Record<PqcKeyOrigin, string> = {
  "address-bound": "this key file's ML-DSA-87 key, derived from the mnemonic and bound to the address; it cannot be computed from the ECDSA key",
  "mnemonic-only": "this key file's legacy mnemonic-only ML-DSA-87 key (deprecated): rotate it with rotatePqcKeyMsgFromMnemonic",
  "ecdsa-derived":
    "CRITICAL: the ML-DSA-87 key is computed from this account's ECDSA private key (pre-0.13.0 SDK seed derivation). A quantum attacker who recovers the ECDSA key gets it too: rotate to a key from independent entropy",
  other: "not derivable from this key file: another wallet or derivation registered it; compare its fingerprint with that wallet",
};

/** Origin of each account's registered key, for `qday whoami`. */
export async function describeKeyOrigins(file: string, accounts: { address: string; privateKey: Uint8Array; fingerprint?: string }[]) {
  const mnemonic = readMnemonic(file);
  return Promise.all(
    accounts.map(async (a) => ({
      address: a.address,
      origin: a.fingerprint ? await pqcKeyOrigin(a.fingerprint, pqcKeyCandidates(a.address, mnemonic, a.privateKey)) : undefined,
    })),
  );
}

/**
 * The Ethereum-type (eth_secp256k1, m/44'/60'/0'/0/0) account of the same mnemonic. Its qor1 and 0x
 * forms are one account, so it can send EVM transactions; the native account above cannot (its
 * address is not the keccak hash of its key). The CLI uses it only to relay to QDayRegistry.
 */
export async function loadRelayer(file: string): Promise<UnifiedAccount> {
  return deriveUnifiedAccount(readMnemonic(file), 0);
}

export function sdkClient(net: Network) {
  return createClient({
    network: net.name,
    chainId: net.chainId,
    endpoints: { rest: net.rest, rpc: net.rpc, ...(net.evmRpc ? { evmRpc: net.evmRpc } : {}) },
  });
}

/**
 * Build and sign the attestation transaction exactly as `attest` would, without
 * broadcasting it, then check the ML-DSA-87 signature locally.
 */
export async function offlineSelfTest(k: LoadedKey, net: Network, memo: string) {
  let accountNumber = 0;
  let sequence = 0;
  let registered = false;
  let signBytesVersion: "auto" | "v2" = "auto";
  try {
    const r = await getJson<any>(net.rest, `/cosmos/auth/v1beta1/accounts/${k.address}`);
    const base = r.json?.account?.base_account ?? r.json?.account;
    if (base) {
      accountNumber = Number(base.account_number ?? 0);
      sequence = Number(base.sequence ?? 0);
    }
    const p = await getJson<any>(net.rest, `/qorechain/pqc/v1/account/${k.address}`);
    registered = Boolean(p.json?.found);
  } catch {
    signBytesVersion = "v2"; // network unreachable: sign the current (v2) form
  }
  const built = await buildHybridTx({
    registry: new Registry(defaultRegistryTypes),
    signer: await directSignerFromPrivateKey(k.privateKey, "qor"),
    pqcKeypair: k.pqc,
    messages: [attestationMsg(k.address)],
    fee: { amount: [{ denom: "uqor", amount: SEND_FEE_UQOR.toString() }], gas: "400000" },
    memo,
    chainId: net.chainId,
    accountNumber,
    sequence,
    signBytesVersion,
    rest: net.rest,
  });
  return {
    signBytesVersion: built.signBytesVersion,
    txBytes: built.txRawBytes.length,
    pqcSignatureBytes: built.pqcSignature.length,
    pqcVerifies: pqcVerify(k.pqc.publicKey, built.pqcSignedMessage, built.pqcSignature),
    neededUqor: (registered ? 0n : REGISTER_FEE_UQOR) + SEND_FEE_UQOR + 1n,
  };
}

/** Register the ML-DSA-87 key if needed, then broadcast one hybrid-signed attestation. */
export async function attestWithKey(k: LoadedKey, net: Network, log: (line: string) => void): Promise<{ txHash: string; memo: string }> {
  const before = await scanAddress(k.address, net);
  const needed = (before.pqc ? 0n : REGISTER_FEE_UQOR) + SEND_FEE_UQOR + 1n;
  log(`Account ${k.address}: ${formatQor(before.liquidUqor)}, PQC key ${before.pqc ? "registered" : "not registered"}.`);
  if (before.liquidUqor < needed) {
    throw new Error(
      `${k.address} holds ${formatQor(before.liquidUqor)}; the attestation needs about ${formatQor(needed)} for fees. ` +
        `Fund it from the ${net.chainId} faucet (QoreChain dashboard) and run this again.`,
    );
  }
  const client = sdkClient(net);
  const signer = await directSignerFromPrivateKey(k.privateKey, "qor");
  const tx = await client.connectTx(signer, { pqcKeypair: k.pqc });
  try {
    const reg = await ensurePqcRegistered(tx, { pqcKeypair: k.pqc, rest: net.rest, chainId: net.chainId });
    log(reg.alreadyRegistered ? "ML-DSA-87 key already registered." : `Registered the ML-DSA-87 key: ${reg.txHash}`);
    // The scan after registration is what the attestation records.
    let after = await scanAddress(k.address, net);
    for (let i = 0; i < 5 && !after.pqc; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      after = await scanAddress(k.address, net);
    }
    const memo = await buildMemo(after);
    log(`Attesting: ${memo}`);
    const res = await tx.signAndBroadcast([attestationMsg(k.address)], "auto", memo);
    if (res.code !== 0) throw new Error(`Attestation tx ${res.transactionHash} failed with code ${res.code}.`);
    return { txHash: res.transactionHash, memo };
  } finally {
    tx.disconnect();
  }
}
