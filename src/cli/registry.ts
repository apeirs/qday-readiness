/**
 * QDayRegistry from the CLI (Node only): deploy it, and relay attestations to it.
 *
 * The attesting account signs nothing new here. QDayRegistry.record() takes the attestation
 * transaction's hybrid sign-bytes and ML-DSA-87 signature and checks them on chain against the
 * account's registered key, so anyone may relay. The CLI relays from the Ethereum-type account of the
 * same mnemonic (see loadRelayer): QoreX and the native account have no EVM lane.
 *
 * On QoreChain an EVM transaction is admitted only inside an authorisation window that the account
 * opened with a hybrid-signed (secp256k1 + ML-DSA-87) native message. Each write here opens the
 * narrowest window that fits: one transaction, a few hundred blocks, enough value for its fee only,
 * and for a record the registry as the only allowed recipient.
 */
import { decodeTxRaw as decodeTxProto } from "@cosmjs/proto-signing";
import { StargateClient } from "@cosmjs/stargate";
import { createEvmClient, evmAccountFromPrivateKey, evmWindowCost, evmWindowStatus } from "@qorechain/evm";
import { decodeTxRaw, fromBase64, hybridSignBytes, pqcLayers } from "@qorechain/qoresign";
import {
  EthNativeSigner,
  buildRegisterPqcKeyMsg,
  directSignerFromPrivateKey,
  openEvmWindowMsg,
  signProofOfPossession,
  type EncodeObject,
  type UnifiedAccount,
} from "@qorechain/sdk";
import type { Address, Hex } from "viem";
import { qdayRegistryAbi, qdayRegistryBytecode } from "../../contracts/contracts/QDayRegistry.artifact";
import { parseAddress } from "../core/addr";
import { parseMemo } from "../core/attest";
import { getJson } from "../core/http";
import type { Network } from "../core/networks";
import { formatQor } from "../core/scan";
import { sdkClient, type LoadedKey } from "./signer";

/** Window: blocks open (~5 min at Diana's ~1.5 s blocks) and the gas each admitted tx may use. */
const WINDOW_BLOCKS = 200;
/** Measured: deploy ~1.5M gas; record ~0.4M (5 kB of calldata, the ML-DSA-87 check, one record). */
const DEPLOY_GAS = 2_500_000n;
const RECORD_GAS = 700_000n;
/** Fee cap per EVM gas: a bit over twice the 112.5 gwei base fee seen on Diana. */
const MAX_FEE_PER_GAS = 250_000_000_000n;
const PRIORITY_FEE_PER_GAS = 1_000_000_000n;
/** Native fees for the relayer's own messages (0.15 uqor per gas). */
const NATIVE_GAS = 800_000;
const NATIVE_FEE_UQOR = 120_000n;
/** Top the relayer up to this from the attesting account when it runs low. */
const RELAYER_FLOOR_UQOR = 1_500_000n;
const RELAYER_TOPUP_UQOR = 3_000_000n;

type Log = (line: string) => void;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function balanceUqor(net: Network, address: string): Promise<bigint> {
  const r = await getJson<any>(net.rest, `/cosmos/bank/v1beta1/balances/${address}/by_denom?denom=uqor`);
  return BigInt(r.json?.balance?.amount ?? 0);
}

async function accountSeq(net: Network, address: string) {
  const r = await getJson<any>(net.rest, `/cosmos/auth/v1beta1/accounts/${address}`);
  const base = r.json?.account?.base_account ?? r.json?.account;
  if (!base) throw new Error(`${address} has no account on ${net.chainId} yet.`);
  return { accountNumber: BigInt(base.account_number ?? 0), sequence: BigInt(base.sequence ?? 0) };
}

async function pqcRegistered(net: Network, address: string): Promise<boolean> {
  const r = await getJson<any>(net.rest, `/qorechain/pqc/v1/account/${address}`);
  return Boolean(r.json?.found ?? r.json?.account);
}

/** Sign one native tx from the relayer (eth_secp256k1) and wait for it to land. */
async function relayerNativeTx(relayer: UnifiedAccount, net: Network, messages: EncodeObject[], signMode: "hybrid" | "classical") {
  const signer = new EthNativeSigner(relayer, { signMode, signBytesVersion: "auto", rest: net.rest });
  const client = await StargateClient.connect(net.rpc);
  try {
    const res = await signer.signAndBroadcast(client, {
      chainId: net.chainId,
      messages,
      fee: { amount: [{ denom: "uqor", amount: NATIVE_FEE_UQOR.toString() }], gas: String(NATIVE_GAS) },
      ...(await accountSeq(net, relayer.cosmos)),
    });
    if (res.code !== 0) throw new Error(`Relayer tx ${res.transactionHash} failed with code ${res.code}: ${res.rawLog ?? ""}`);
    return res.transactionHash;
  } finally {
    client.disconnect();
  }
}

/** Fund the relayer from the attesting account if it is low, and register its ML-DSA-87 key once. */
async function readyRelayer(k: LoadedKey, relayer: UnifiedAccount, net: Network, log: Log) {
  log(`Relayer ${relayer.cosmos} (${relayer.evm}), the Ethereum-type account of the same key file.`);
  let bal = await balanceUqor(net, relayer.cosmos);
  if (bal < RELAYER_FLOOR_UQOR) {
    const tx = await sdkClient(net).connectTx(await directSignerFromPrivateKey(k.privateKey, "qor"), { pqcKeypair: k.pqc });
    try {
      const msg = { typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { fromAddress: k.address, toAddress: relayer.cosmos, amount: [{ denom: "uqor", amount: RELAYER_TOPUP_UQOR.toString() }] } };
      const res = await tx.signAndBroadcast([msg], "auto", "qday relayer gas");
      if (res.code !== 0) throw new Error(`Funding the relayer failed (code ${res.code}, ${res.transactionHash}).`);
      log(`Funded the relayer with ${formatQor(RELAYER_TOPUP_UQOR)} (hybrid-signed): ${res.transactionHash}`);
    } finally {
      tx.disconnect();
    }
    for (let i = 0; i < 10 && bal < RELAYER_FLOOR_UQOR; i++) {
      await sleep(1500);
      bal = await balanceUqor(net, relayer.cosmos);
    }
  }
  if (!(await pqcRegistered(net, relayer.cosmos))) {
    const proofOfPossession = signProofOfPossession({ chainId: net.chainId, account: relayer.cosmos, keypair: relayer.pqc, algorithmId: 1 });
    const msg = buildRegisterPqcKeyMsg(relayer.cosmos, { pqcKeypair: relayer.pqc, keyType: "hybrid", proofOfPossession });
    // Registration is the one message the chain lets the classical key sign alone.
    const hash = await relayerNativeTx(relayer, net, [msg], "classical");
    log(`Registered the relayer's ML-DSA-87 key (with proof of possession): ${hash}`);
    for (let i = 0; i < 10 && !(await pqcRegistered(net, relayer.cosmos)); i++) await sleep(1500);
  }
}

async function openWindow(relayer: UnifiedAccount, net: Network, gas: bigint, allowedTargets: string[] | undefined, log: Log) {
  const maxValue = evmWindowCost({ gas, maxFeePerGas: MAX_FEE_PER_GAS });
  const msg = openEvmWindowMsg({ sender: relayer.cosmos, blocks: WINDOW_BLOCKS, maxTxs: 1, maxValue, ...(allowedTargets ? { allowedTargets } : {}) });
  const hash = await relayerNativeTx(relayer, net, [msg], "hybrid");
  log(`Opened an EVM window (hybrid-signed): ${hash} (1 tx, ${WINDOW_BLOCKS} blocks, ${formatQor(maxValue)} max${allowedTargets ? `, only ${allowedTargets.join(", ")}` : ""})`);
  for (let i = 0; i < 15; i++) {
    const w = await evmWindowStatus({ rest: net.rest, address: relayer.cosmos });
    if (w.live) return hash;
    await sleep(1500);
  }
  throw new Error("The EVM window did not show up as live within ~20 s.");
}

async function evm(net: Network, relayer: UnifiedAccount) {
  if (!net.evmRpc) throw new Error(`${net.chainId} has no EVM endpoint configured.`);
  const client = await createEvmClient({ endpoints: { evmRpc: net.evmRpc } });
  const account = evmAccountFromPrivateKey(relayer.privateKey as Hex);
  if (account.address.toLowerCase() !== relayer.evm.toLowerCase()) throw new Error("Relayer key and address disagree.");
  return { client, account, wallet: client.getWalletClient(account) };
}

const fees = { maxFeePerGas: MAX_FEE_PER_GAS, maxPriorityFeePerGas: PRIORITY_FEE_PER_GAS };

/** Deploy QDayRegistry for this network's chain id. Returns its address and the deploy tx. */
export async function deployRegistry(k: LoadedKey, relayer: UnifiedAccount, net: Network, log: Log) {
  await readyRelayer(k, relayer, net, log);
  const { client, account, wallet } = await evm(net, relayer);
  const windowTx = await openWindow(relayer, net, DEPLOY_GAS, undefined, log);
  const hash = await wallet.deployContract({ abi: qdayRegistryAbi, bytecode: qdayRegistryBytecode, args: [net.chainId], account, chain: wallet.chain, gas: DEPLOY_GAS, ...fees });
  log(`Deploy tx: ${hash}`);
  const receipt = await client.publicClient.waitForTransactionReceipt({ hash, timeout: 90_000 });
  if (receipt.status !== "success" || !receipt.contractAddress) throw new Error(`Deploy ${hash} failed (${receipt.status}).`);
  return { address: receipt.contractAddress as Address, txHash: hash, block: receipt.blockNumber, gasUsed: receipt.gasUsed, windowTx };
}

/** The record() arguments for a committed attestation tx: its subject, v2 sign-bytes and ML-DSA-87 signature. */
export async function recordArgs(net: Network, txhash: string) {
  const hash = txhash.replace(/^0x/i, "").toUpperCase();
  const j = await getJson<any>(net.rpc, `/tx?hash=0x${hash}`);
  const b64 = j.json?.result?.tx;
  if (!b64) throw new Error(`Transaction ${hash} was not found on ${net.chainId}.`);
  const raw = fromBase64(b64);
  const t = decodeTxRaw(raw);
  const memo = parseMemo(decodeTxProto(raw).body.memo);
  if (!memo) throw new Error(`${hash} carries no qday:v1 memo.`);
  const [layer] = pqcLayers(t.bodyBytes);
  if (!layer) throw new Error(`${hash} has no ML-DSA-87 layer to check.`);
  const signBytes = hybridSignBytes({ chainId: net.chainId, bodyBytes: t.bodyBytes, authInfoBytes: t.authInfoBytes, signBytesVersion: "v2" });
  const subject = parseAddress(memo.subject)?.evm as Address;
  return {
    memo,
    args: [subject, `0x${Buffer.from(signBytes).toString("hex")}`, `0x${Buffer.from(layer.signature).toString("hex")}`, `0x${hash.toLowerCase()}`] as const,
  };
}

/** Relay a committed attestation to the registry. Simulates first, so a bad one costs nothing. */
export async function recordAttestation(k: LoadedKey, relayer: UnifiedAccount, net: Network, txhash: string, log: Log) {
  if (!net.registry) throw new Error(`No QDayRegistry is deployed on ${net.chainId}.`);
  const { memo, args } = await recordArgs(net, txhash);
  const { client, account, wallet } = await evm(net, relayer);
  const registry = net.registry as Address;
  await client.publicClient.simulateContract({ address: registry, abi: qdayRegistryAbi, functionName: "record", args: [...args], account });
  log(`The registry accepts ${memo.subject} graded ${memo.grade} (${memo.readiness}/100) in simulation; relaying.`);
  await readyRelayer(k, relayer, net, log);
  await openWindow(relayer, net, RECORD_GAS, [registry], log);
  const hash = await wallet.writeContract({ address: registry, abi: qdayRegistryAbi, functionName: "record", args: [...args], account, chain: wallet.chain, gas: RECORD_GAS, ...fees });
  log(`Record tx: ${hash}`);
  const receipt = await client.publicClient.waitForTransactionReceipt({ hash, timeout: 90_000 });
  if (receipt.status !== "success") throw new Error(`Registry record ${hash} reverted.`);
  return { txHash: hash, block: receipt.blockNumber, gasUsed: receipt.gasUsed };
}
