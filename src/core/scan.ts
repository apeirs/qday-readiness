import { parseAddress, type ParsedAddress } from "./addr";
import { evmCall, getJson, type HttpOptions } from "./http";
import type { Network } from "./networks";

/** Severity of one finding, worst first. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  /** Points added to the exposure score (0-100 overall). */
  points: number;
  title: string;
  detail: string;
  fix?: string;
}

export interface PqcKeyInfo {
  algorithm: string;
  keyType: string;
  registeredAtHeight: number;
  classicalKeySource: string;
  possessionProven: boolean;
  migrationPending: boolean;
  /** Size of the registered public key; ML-DSA-87 keys are 2,592 bytes (FIPS 204). */
  publicKeyBytes?: number;
  /** First 16 hex of the SHA-256 of the registered public key, to compare with the wallet's own. */
  fingerprint?: string;
  /** Whether the classical key bound at registration is the account's own on-chain key. */
  classicalBinding?: "matches" | "differs" | "unknown";
  /** ML-DSA-87 key whose t1 part is all zero: anyone can forge its signatures. */
  forgeable?: boolean;
}

/** The chain's PQC enforcement (qorechain/pqc/v1/params): a registered key only helps if it is required. */
export interface NetworkPolicy {
  /** "required", "optional" or "disabled". */
  hybridMode: string;
  /** Classical-only signatures still accepted. */
  classicalFallback: boolean;
  minSecurityLevel: number;
  defaultAlgorithm: string;
}

/** ML-DSA-87 public key size in bytes (FIPS 204, security category 5). */
export const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
/** An ML-DSA public key is `rho` (32 bytes) followed by the packed vector t1. */
const ML_DSA_RHO_BYTES = 32;

/**
 * True for an ML-DSA-87 public key whose t1 part is all zero. With t1 = 0 the
 * verification equation no longer depends on any secret, so anyone can produce
 * signatures that verify (the same test as @qorechain/sdk `isDegeneratePqcPublicKey`).
 */
export function isForgeableMlDsa87Key(publicKey: Uint8Array): boolean {
  if (publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES) return false;
  for (let i = ML_DSA_RHO_BYTES; i < publicKey.length; i++) if (publicKey[i] !== 0) return false;
  return true;
}

export interface EvmWindowInfo {
  live: boolean;
  expiryHeight: number;
  remainingBlocks: number;
  remainingTxs: number;
  remainingValueUqor: bigint;
  nativeOnly: boolean;
  allowedTargets: string[];
}

export interface TokenBalance {
  symbol: string;
  amount: string; // human units
}

export interface ScanResult {
  address: ParsedAddress;
  network: Network["name"];
  chainId: string;
  scannedAt: string;
  /** "account" | "contract" | "unseen" (no auth record, no balance). */
  kind: "account" | "contract" | "unseen";
  classicalKeyType?: string;
  classicalPubkeyOnChain: boolean;
  sequence: number;
  pqc?: PqcKeyInfo;
  evmWindow?: EvmWindowInfo;
  liquidUqor: bigint;
  stakedUqor: bigint;
  otherBalances: TokenBalance[];
  abstractAccount?: { type: string; authenticators: number; spendingRules: number; sessionKeys: number };
  delegation?: { delegate: string; live: boolean };
  exposure: number;
  readiness: number;
  grade: "A" | "B" | "C" | "D" | "F" | "n/a";
  verdict: string;
  findings: Finding[];
  /** Calls that failed; the result is then partial and says so. */
  /** The network's PQC enforcement when it could be read. */
  policy?: NetworkPolicy;
  warnings: string[];
}

/**
 * ERC-20 balances show up in the bank module as `erc20:<contract>` denoms.
 * Known tokens get a symbol and decimals; others are shown raw.
 */
const KNOWN_DENOMS: Record<string, { symbol: string; decimals: number }> = {
  "erc20:0x97143b771d34ddb9130b807b135ae675a5a963ca": { symbol: "fUSD", decimals: 6 },
  "erc20:0x02292293c13880a26242690eb70a0e42b8e91c28": { symbol: "fETH", decimals: 18 },
  "erc20:0x4604e7e45b2ecdbfbdc157103f5b2b62cb16451a": { symbol: "fBTC", decimals: 8 },
};

function describeDenom(denom: string, amount: string): TokenBalance {
  const known = KNOWN_DENOMS[denom.toLowerCase()];
  if (known) return { symbol: known.symbol, amount: formatUnits(BigInt(amount), known.decimals) };
  const short = denom.startsWith("erc20:") ? `ERC-20 ${denom.slice(6, 14)}…` : denom;
  return { symbol: short, amount };
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function formatUnits(raw: bigint, decimals: number, maxFrac = 4): string {
  const neg = raw < 0n;
  const v = neg ? -raw : raw;
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  let frac = (v % base).toString().padStart(decimals, "0").slice(0, maxFrac).replace(/0+$/, "");
  const s = whole.toLocaleString("en-US") + (frac ? "." + frac : "");
  return neg ? "-" + s : s;
}

export const formatQor = (uqor: bigint) => `${formatUnits(uqor, 6, 2)} QOR`;

function gradeFor(readiness: number): ScanResult["grade"] {
  if (readiness >= 90) return "A";
  if (readiness >= 75) return "B";
  if (readiness >= 50) return "C";
  if (readiness >= 25) return "D";
  return "F";
}

type Json = Record<string, any>;

export interface Raw {
  auth?: Json | null;
  pqc?: Json | null;
  window?: Json | null;
  consent?: Json | null;
  balances?: Json[];
  delegations?: Json[];
  aa?: Json | null;
  aaRules?: Json[];
  code?: string;
  delegateHasCode?: boolean;
  /** qorechain/pqc/v1/params `params`. */
  policy?: Json | null;
  /** First 16 hex of the SHA-256 of the registered PQC public key. */
  pqcKeyDigest?: string;
  warnings: string[];
}

export function parsePolicy(p: Json | null | undefined): NetworkPolicy | undefined {
  if (!p || typeof p !== "object") return undefined;
  const mode = String(p.hybrid_signature_mode_name ?? p.hybrid_signature_mode ?? "unknown").toLowerCase();
  return {
    hybridMode: mode === "2" ? "required" : mode === "1" ? "optional" : mode === "0" ? "disabled" : mode,
    classicalFallback: Boolean(p.allow_classical_fallback),
    minSecurityLevel: Number(p.min_security_level ?? 0),
    defaultAlgorithm: p.default_signature_algo_name === "dilithium5" ? "ML-DSA-87" : String(p.default_signature_algo_name ?? "unknown"),
  };
}

/** True when the chain rejects a native transaction that carries only the classical signature. */
export const enforcesHybrid = (p: NetworkPolicy) => p.hybridMode === "required" && !p.classicalFallback;

const policyCache = new Map<string, { at: number; value: Promise<Json | null> }>();

/** The network's PQC params, read once a minute at most (every scan in a batch shares one read). */
export function fetchPolicyRaw(net: Network, http: HttpOptions = {}): Promise<Json | null> {
  const hit = policyCache.get(net.rest);
  if (hit && Date.now() - hit.at < 60_000) return hit.value;
  const value = getJson<Json>(net.rest, "/qorechain/pqc/v1/params", http).then((r) => {
    if (r.status !== 200 || !r.json?.params) throw new Error(`HTTP ${r.status}`);
    return r.json.params as Json;
  });
  value.catch(() => policyCache.delete(net.rest));
  policyCache.set(net.rest, { at: Date.now(), value });
  return value;
}

export async function fetchPolicy(net: Network, http: HttpOptions = {}): Promise<NetworkPolicy | undefined> {
  return parsePolicy(await fetchPolicyRaw(net, http));
}

const b64Bytes = (s: string): Uint8Array<ArrayBuffer> => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));
const b64Length = (s: string) => Math.floor((s.length * 3) / 4) - (s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0);

async function sha256Hex16(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const d = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
  return Array.from(d.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchRaw(addr: ParsedAddress, net: Network, http: HttpOptions): Promise<Raw> {
  const raw: Raw = { warnings: [] };
  const rest = net.rest;
  const q = addr.qor;
  const attempt = async <T>(label: string, fn: () => Promise<T>): Promise<T | undefined> => {
    try {
      return await fn();
    } catch (err) {
      raw.warnings.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
      return undefined;
    }
  };
  // 4xx with a JSON body means "not found" on these routes; anything else is a warning.
  const okOrNull = (label: string, r: { status: number; json: any }) => {
    if (r.status === 200) return r.json ?? null;
    if (r.status === 404 || r.status === 400 || (r.json && typeof r.json.code === "number")) return null;
    raw.warnings.push(`${label}: HTTP ${r.status}`);
    return null;
  };

  await Promise.all([
    attempt("auth", async () => {
      raw.auth = okOrNull("auth", await getJson(rest, `/cosmos/auth/v1beta1/accounts/${q}`, http))?.account ?? null;
    }),
    attempt("pqc", async () => {
      const j = okOrNull("pqc", await getJson<Json>(rest, `/qorechain/pqc/v1/account/${q}`, http));
      raw.pqc = j?.found ? j.account : null;
      if (typeof raw.pqc?.public_key === "string" && raw.pqc.public_key) raw.pqcKeyDigest = await sha256Hex16(b64Bytes(raw.pqc.public_key));
    }),
    attempt("network policy", async () => {
      raw.policy = await fetchPolicyRaw(net, http);
    }),
    attempt("evm window", async () => {
      const j = okOrNull("evm window", await getJson<Json>(rest, `/qorechain/pqc/v1/evm_window/${q}`, http));
      raw.window = j?.found ? j : null;
    }),
    attempt("7702 consent", async () => {
      const j = okOrNull("7702 consent", await getJson<Json>(rest, `/qorechain/pqc/v1/evm_delegation_consent/${q}`, http));
      raw.consent = j?.found ? j : null;
    }),
    attempt("balances", async () => {
      raw.balances = okOrNull("balances", await getJson<Json>(rest, `/cosmos/bank/v1beta1/balances/${q}?pagination.limit=200`, http))?.balances ?? [];
    }),
    attempt("staking", async () => {
      raw.delegations =
        okOrNull("staking", await getJson<Json>(rest, `/cosmos/staking/v1beta1/delegations/${q}`, http))?.delegation_responses ?? [];
    }),
    attempt("abstract account", async () => {
      const j = okOrNull("abstract account", await getJson<Json>(rest, `/qorechain/abstractaccount/v1/accounts/${q}`, http));
      raw.aa = j?.account ?? null;
      if (raw.aa) {
        const r = okOrNull("spending rules", await getJson<Json>(rest, `/qorechain/abstractaccount/v1/accounts/${q}/spending_rules`, http));
        raw.aaRules = r?.rules ?? [];
      }
    }),
    attempt("evm code", async () => {
      if (!net.evmRpc || !addr.evm) return;
      raw.code = await evmCall<string>(net.evmRpc, "eth_getCode", [addr.evm, "latest"], http);
      const c = (raw.code ?? "").toLowerCase();
      if (c.startsWith("0xef0100") && c.length === 48) {
        const dc = await evmCall<string>(net.evmRpc, "eth_getCode", [`0x${c.slice(8)}`, "latest"], http);
        raw.delegateHasCode = Boolean(dc && dc !== "0x");
      }
    }),
  ]);
  return raw;
}

/** Turn the raw chain state into findings, an exposure score and a fix list. Pure; unit-testable. */
export function assess(addr: ParsedAddress, net: Network, raw: Raw, latestHeight?: number): ScanResult {
  const base = (raw.auth?.base_account ?? raw.auth ?? {}) as Json;
  const pubKey = base.pub_key as Json | undefined;
  const classicalKeyType = pubKey?.["@type"] ? String(pubKey["@type"]).split(".").slice(-2, -1)[0] : undefined;
  const sequence = Number(base.sequence ?? 0);
  const liquidUqor = BigInt((raw.balances ?? []).find((b) => b.denom === "uqor")?.amount ?? "0");
  const otherBalances: TokenBalance[] = [
    ...(raw.balances ?? [])
      .filter((b) => b.denom !== "uqor")
      .map((b) => describeDenom(String(b.denom), String(b.amount))),
  ];
  const stakedUqor = (raw.delegations ?? []).reduce((s, d) => s + BigInt(d?.balance?.amount ?? "0"), 0n);
  const valueUqor = liquidUqor + stakedUqor;
  const policy = parsePolicy(raw.policy);
  const hasValue = valueUqor > 0n || otherBalances.length > 0;
  // EIP-7702: an account's code is `0xef0100 ‖ delegate` while delegated; that is still a keyed account.
  const code = (raw.code ?? "0x").toLowerCase();
  const delegateFromCode = code.startsWith("0xef0100") && code.length === 48 ? `0x${code.slice(8)}` : undefined;
  const isContract = (code !== "0x" && !delegateFromCode) || addr.byteLength === 32 || /ModuleAccount|ContractAccount/.test(String(raw.auth?.["@type"] ?? ""));
  const findings: Finding[] = [];
  const add = (f: Finding) => findings.push(f);
  const valueText = [valueUqor > 0n ? formatQor(valueUqor) : "", ...otherBalances.map((t) => `${t.amount} ${t.symbol}`)]
    .filter(Boolean)
    .join(" + ") || "nothing";

  let pqc: PqcKeyInfo | undefined;
  if (raw.pqc) {
    pqc = {
      algorithm: raw.pqc.algorithm_name === "dilithium5" ? "ML-DSA-87 (Dilithium5)" : String(raw.pqc.algorithm_name ?? raw.pqc.algorithm_id),
      keyType: String(raw.pqc.key_type ?? "unknown"),
      registeredAtHeight: Number(raw.pqc.created_at_height ?? 0),
      classicalKeySource: String(raw.pqc.classical_key_source ?? "none"),
      possessionProven: Boolean(raw.pqc.possession_proven),
      migrationPending: Boolean(raw.pqc.migration_public_key),
      publicKeyBytes: typeof raw.pqc.public_key === "string" && raw.pqc.public_key ? b64Length(raw.pqc.public_key) : undefined,
      fingerprint: raw.pqcKeyDigest,
      classicalBinding:
        raw.pqc.ecdsa_pubkey && pubKey?.key ? (raw.pqc.ecdsa_pubkey === pubKey.key ? "matches" : "differs") : "unknown",
      forgeable: typeof raw.pqc.public_key === "string" && raw.pqc.public_key ? isForgeableMlDsa87Key(b64Bytes(raw.pqc.public_key)) : undefined,
    };
  }

  let evmWindow: EvmWindowInfo | undefined;
  if (raw.window) {
    evmWindow = {
      live: Boolean(raw.window.live),
      expiryHeight: Number(raw.window.expiry_height ?? 0),
      remainingBlocks: Number(raw.window.remaining_blocks ?? 0),
      remainingTxs: Number(raw.window.remaining_txs ?? 0),
      remainingValueUqor: BigInt(raw.window.remaining_value ?? "0"),
      nativeOnly: Boolean(raw.window.native_only),
      allowedTargets: (raw.window.allowed_targets ?? []) as string[],
    };
  }

  const kind: ScanResult["kind"] = isContract ? "contract" : !raw.auth && !hasValue && !pqc ? "unseen" : "account";

  if (kind === "contract") {
    add({
      id: "contract",
      severity: "info",
      points: 0,
      title: "Contract or module address",
      detail: "No private key controls this address, so there is no signing key to protect. Scan the account that owns or upgrades it instead.",
    });
  } else if (!pqc) {
    if (hasValue && pubKey) {
      add({
        id: "no-pqc-key-exposed",
        severity: "critical",
        points: 85,
        title: "No ML-DSA-87 key, and the ECDSA public key is already on chain",
        detail:
          `This account holds ${valueText} and has never registered a post-quantum key. Its ${classicalKeyType ?? "secp256k1"} public key is public, so a quantum attacker can derive the private key. ` +
          "Worse, the first post-quantum key registered for an account binds it: an attacker who derives the ECDSA key can register their own ML-DSA-87 key first and lock you out.",
        fix: "Register your post-quantum key now: send any transaction from QoreX (it registers the key first), or run `qday attest` / `ensurePqcRegistered` from @qorechain/sdk.",
      });
    } else if (hasValue) {
      add({
        id: "no-pqc-key",
        severity: "high",
        points: 60,
        title: "Funded, but no ML-DSA-87 key registered",
        detail:
          `This account holds ${valueText}. Its public key is not stored on chain yet (EVM signatures can still reveal it), its first transaction will publish it, and until a post-quantum key is registered the account can be claimed by whoever holds the ECDSA key.`,
        fix: "Make the first transaction a PQC registration: QoreX does this automatically, or run `qday attest`.",
      });
    } else if (raw.auth) {
      add({
        id: "no-pqc-key-empty",
        severity: "low",
        points: 25,
        title: "No ML-DSA-87 key (account is empty)",
        detail: "Nothing is at risk today, but anything sent here lands in an account with only a classical key.",
        fix: "Register a post-quantum key before you fund it (QoreX does it on the first transaction).",
      });
    } else {
      add({
        id: "unseen",
        severity: "info",
        // 15, not less: an address with no post-quantum key must not reach grade A.
        points: 15,
        title: "The chain has never seen this address",
        detail: "No balance, no transactions, no keys. It is safe until it receives funds.",
        fix: "Register a post-quantum key as the first thing you do with it.",
      });
    }
  } else {
    add({
      id: "pqc-registered",
      severity: "info",
      points: 0,
      title: `${pqc.algorithm} key registered (${pqc.keyType})`,
      detail:
        `Registered at block ${pqc.registeredAtHeight.toLocaleString("en-US")}` +
        (pqc.publicKeyBytes ? `; public key ${pqc.publicKeyBytes.toLocaleString("en-US")} bytes` : "") +
        (pqc.fingerprint ? `, SHA-256 \`${pqc.fingerprint}\`` : "") +
        (pqc.classicalBinding === "matches" ? `, bound to this account's own ${classicalKeyType ?? "classical"} key` : "") +
        ". " +
        (policy && !enforcesHybrid(policy)
          ? "The network does not require it yet (see below)."
          : "Native transactions from this account must carry a valid ML-DSA-87 signature next to the classical one."),
    });
    if (pqc.publicKeyBytes !== undefined && /dilithium5|ML-DSA-87/i.test(pqc.algorithm) && pqc.publicKeyBytes !== ML_DSA_87_PUBLIC_KEY_BYTES) {
      add({
        id: "pqc-key-size",
        severity: "high",
        points: 40,
        title: "Registered key is not the size of an ML-DSA-87 public key",
        detail: `The registered key is ${pqc.publicKeyBytes.toLocaleString("en-US")} bytes; an ML-DSA-87 public key is ${ML_DSA_87_PUBLIC_KEY_BYTES.toLocaleString("en-US")} (FIPS 204). A key that cannot verify signatures locks the account rather than protecting it.`,
        fix: "Rotate to a fresh ML-DSA-87 key from QoreX or `@qorechain/sdk` while the classical key still controls the account.",
      });
    }
    if (pqc.forgeable) {
      add({
        id: "pqc-key-forgeable",
        severity: "critical",
        points: 85,
        title: "Registered ML-DSA-87 key can be forged by anyone",
        detail:
          "Everything after the first 32 bytes of the registered public key (its t1 part) is zero. ML-DSA verification then no longer depends on any secret, " +
          "so anyone can make an ML-DSA-87 signature this key accepts. The account is effectively guarded by its ECDSA key alone, and the hybrid check is a formality.",
        fix: "Rotate to a fresh ML-DSA-87 key now (QoreX or `rotatePqcKeyMsg` in @qorechain/sdk), or move the funds to a new account that registers a proper key. Anyone can forge the old key's half of a rotation, so do it before someone else does.",
      });
    }
    if (pqc.classicalBinding === "differs") {
      add({
        id: "pqc-classical-mismatch",
        severity: "low",
        points: 5,
        title: "Post-quantum key bound to a different classical key",
        detail: "The secp256k1 key recorded with the ML-DSA-87 registration is not the public key the account shows on chain. Hybrid checks pair the two, so make sure the pair you sign with is the registered one.",
        fix: "Compare the key in your wallet with the registration; rotate the PQC key if they do not belong together.",
      });
    }
    if (policy && !enforcesHybrid(policy)) {
      add({
        id: "network-not-enforcing",
        severity: "medium",
        points: 20,
        title: `${net.chainId} does not require the ML-DSA-87 signature`,
        detail: `Network policy: hybrid signatures ${policy.hybridMode}, classical-only fallback ${policy.classicalFallback ? "on" : "off"}. A transaction signed with the ECDSA key alone is still accepted, so the registered key does not stop an attacker who derives that key.`,
        fix: "Nothing to change on the account: keep the key registered and watch qorechain/pqc/v1/params for hybrid mode \"required\".",
      });
    }
    if (!pqc.possessionProven) {
      add({
        id: "no-possession-proof",
        severity: "info",
        points: 3,
        title: "Registered without a proof of possession",
        detail: "The chain accepted this key without a signature proving the registrant holds its secret (wallets on SDK < 0.9 and wallet-adapter do not attach one). It still protects the account; the flag matters mainly for bridge validators.",
        fix: "Optional: a key rotation, which the new key signs, sets possession_proven.",
      });
    }
    if (pqc.migrationPending) {
      add({
        id: "migration-pending",
        severity: "info",
        points: 0,
        title: "Key migration in progress",
        detail: "A replacement post-quantum key is staged. Both keys are valid until the migration completes.",
      });
    }
  }

  if (evmWindow?.live) {
    const scoped = evmWindow.nativeOnly || evmWindow.allowedTargets.length > 0;
    add({
      id: "evm-window-open",
      severity: scoped ? "low" : "medium",
      points: scoped ? 5 : 15,
      title: `EVM window open${scoped ? " (scoped)" : ""}: classical-only signatures accepted`,
      detail:
        `For the next ${evmWindow.remainingBlocks.toLocaleString("en-US")} blocks, up to ${evmWindow.remainingTxs} EVM transactions moving up to ${formatQor(evmWindow.remainingValueUqor)} ` +
        `can be signed with the ECDSA key alone${scoped ? ", limited to " + (evmWindow.nativeOnly ? "native transfers" : evmWindow.allowedTargets.join(", ")) : ""}.`,
      fix: "Close it when you are done (MsgCloseEVMWindow), and open windows with a small value cap and allowed_targets.",
    });
  }

  const delegate = delegateFromCode ?? (raw.consent?.live || raw.consent?.current_delegate ? String(raw.consent.current_delegate || raw.consent.delegate) : undefined);
  const delegateEmpty = Boolean(delegateFromCode) && raw.delegateHasCode === false;
  if (delegate && kind !== "contract") {
    add({
      id: "7702-delegation",
      severity: delegateEmpty ? "info" : "medium",
      points: delegateEmpty ? 2 : 10,
      title: "EIP-7702 delegation active",
      detail: delegateEmpty
        ? `The account is delegated to ${delegate}, which has no code, so the delegation does nothing today. If code is ever deployed there it runs for this account.`
        : `EVM calls to this account run the code at ${delegate}, which can move the account's EVM-side funds under whatever rules it implements.`,
      fix: "Make sure you know the delegate contract; clear the delegation (MsgClearEVMDelegation) if you no longer use it.",
    });
  }

  let abstractAccount: ScanResult["abstractAccount"];
  if (raw.aa) {
    abstractAccount = {
      type: String(raw.aa.account_type ?? "abstract"),
      authenticators: Number(raw.aa.authenticators_count ?? 0),
      spendingRules: (raw.aaRules ?? []).length || Number(raw.aa.spending_rules_count ?? 0),
      sessionKeys: Number(raw.aa.session_keys_count ?? 0),
    };
    if (abstractAccount.authenticators > 0 || abstractAccount.sessionKeys > 0) {
      add({
        id: "extra-authenticators",
        severity: "low",
        points: 5,
        title: `${abstractAccount.authenticators} authenticator(s), ${abstractAccount.sessionKeys} session key(s)`,
        detail: `Extra signers can act for this account${abstractAccount.spendingRules ? `, bounded by ${abstractAccount.spendingRules} spending rule(s)` : " with no spending rules"}. Each one is only as quantum-safe as its own key type.`,
        fix: "Remove authenticators you no longer use, and give the rest a daily limit.",
      });
    }
  }

  if (raw.warnings.length) {
    add({
      id: "partial",
      severity: "info",
      points: 0,
      title: "Partial scan",
      detail: `Some reads failed: ${raw.warnings.join("; ")}. The score uses what could be read.`,
    });
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const exposure = Math.min(100, findings.reduce((s, f) => s + f.points, 0));
  const readiness = 100 - exposure;
  const grade = kind === "contract" ? "n/a" : gradeFor(readiness);
  const worst = findings[0];
  const verdict =
    kind === "contract"
      ? "Not applicable: no key controls this address."
      : pqc
        ? exposure === 0 || exposure <= 5
          ? "Quantum-ready: native transfers need the ML-DSA-87 signature."
          : worst.severity === "critical"
            ? `Exposed: ${worst.title.charAt(0).toLowerCase()}${worst.title.slice(1)}.`
            : `Quantum key in place; ${worst.title.toLowerCase()}.`
        : worst.severity === "critical"
          ? "Exposed: register a post-quantum key before someone else does."
          : worst.severity === "high"
            ? "At risk: funded with only a classical key."
            : "Not ready yet, nothing at stake today.";
  void latestHeight;
  return {
    address: addr,
    network: net.name,
    chainId: net.chainId,
    scannedAt: new Date().toISOString(),
    kind,
    classicalKeyType,
    classicalPubkeyOnChain: Boolean(pubKey),
    sequence,
    pqc,
    policy,
    evmWindow,
    liquidUqor,
    stakedUqor,
    otherBalances,
    abstractAccount,
    delegation: delegate ? { delegate, live: true } : undefined,
    exposure,
    readiness,
    grade,
    verdict,
    findings,
    warnings: raw.warnings,
  };
}

export async function scanAddress(input: string, net: Network, http: HttpOptions = {}): Promise<ScanResult> {
  const addr = parseAddress(input);
  const raw = await fetchRaw(addr, net, http);
  return assess(addr, net, raw);
}

/** Scan several addresses with a small concurrency limit so the public API is not hammered. */
export async function scanMany(
  inputs: string[],
  net: Network,
  http: HttpOptions = {},
  onResult?: (r: ScanResult | { input: string; error: string }, index: number) => void,
): Promise<(ScanResult | { input: string; error: string })[]> {
  const out: (ScanResult | { input: string; error: string })[] = new Array(inputs.length);
  let next = 0;
  const worker = async () => {
    while (next < inputs.length) {
      const i = next++;
      try {
        out[i] = await scanAddress(inputs[i], net, http);
      } catch (err) {
        out[i] = { input: inputs[i], error: err instanceof Error ? err.message : String(err) };
      }
      onResult?.(out[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(3, inputs.length) }, worker));
  return out;
}

// Tolerates the empty slots a progressive scan leaves while results arrive out of order.
export function isScanResult(r: ScanResult | { input: string; error: string } | undefined | null): r is ScanResult {
  return r != null && (r as ScanResult).findings !== undefined;
}

/**
 * The scan as it will read once the account's first transaction has registered
 * its ML-DSA-87 key (QoreX registers it inside the same approval). Used for the
 * attestation memo when the wallet registers and attests in one step.
 */
export function projectAfterRegistration(r: ScanResult): ScanResult {
  if (r.pqc || r.kind === "contract") return r;
  const findings: Finding[] = [
    {
      id: "pqc-registered",
      severity: "info",
      points: 0,
      title: "ML-DSA-87 (Dilithium5) key registered (hybrid)",
      detail: "Registered by the attestation's own approval. Native transactions from this account must carry a valid ML-DSA-87 signature next to the classical one.",
    },
    ...r.findings.filter((f) => !["no-pqc-key-exposed", "no-pqc-key", "no-pqc-key-empty", "unseen"].includes(f.id)),
  ];
  const exposure = Math.min(100, findings.reduce((s, f) => s + f.points, 0));
  return {
    ...r,
    kind: "account",
    pqc: { algorithm: "ML-DSA-87 (Dilithium5)", keyType: "hybrid", registeredAtHeight: 0, classicalKeySource: "stored", possessionProven: false, migrationPending: false },
    findings,
    exposure,
    readiness: 100 - exposure,
    grade: gradeFor(100 - exposure),
    verdict: exposure <= 5 ? "Quantum-ready: native transfers need the ML-DSA-87 signature." : r.verdict,
  };
}
