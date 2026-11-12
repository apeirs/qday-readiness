import { getQorexNative, hasCapability } from "@qorechain/qorex-types";
import { MsgSend } from "cosmjs-types/cosmos/bank/v1beta1/tx";
import { ATTEST_AMOUNT_UQOR, MSG_SEND_TYPE_URL } from "./core/attest";

export interface NativeAccount {
  address: string;
}

export type QorexState = "missing" | "outdated" | "ready";

export function qorexState(): QorexState {
  const native = getQorexNative();
  if (!native) return "missing";
  return hasCapability(native, "signAndBroadcast") ? "ready" : "outdated";
}

/** Connect to QoreX's native lane and return the account's qor1 address. */
export async function connectNative(chainId: string): Promise<NativeAccount> {
  const native = getQorexNative();
  if (!native) throw new Error("QoreX is not installed in this browser.");
  await native.enable(chainId);
  const key = await native.getKey(chainId);
  return { address: key.bech32Address };
}

/**
 * Send the attestation through QoreX: a 1 uqor MsgSend to self carrying the memo.
 * QoreX builds the transaction, registers the ML-DSA-87 key first if this is the
 * account's first transaction, signs with both keys and broadcasts.
 */
export async function sendAttestation(chainId: string, address: string, memo: string) {
  const native = getQorexNative();
  if (!native || !hasCapability(native, "signAndBroadcast")) throw new Error("This QoreX build cannot send native transactions; update QoreX.");
  const value = MsgSend.encode(
    MsgSend.fromPartial({ fromAddress: address, toAddress: address, amount: [{ denom: "uqor", amount: ATTEST_AMOUNT_UQOR }] }),
  ).finish();
  const res = await native.signAndBroadcast({
    chainId,
    messages: [{ typeUrl: MSG_SEND_TYPE_URL, value: Array.from(value) }],
    memo,
    gasLimit: 400_000,
  });
  if (res.code !== 0) throw new Error(`The chain refused the transaction (code ${res.code}, ${res.txHash}).`);
  return res;
}
