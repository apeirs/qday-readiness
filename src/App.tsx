import { ConnectButton } from "@rainbow-me/rainbowkit";
import { toQorAddress } from "@qorechain/evm";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useAccount } from "wagmi";
import { splitAddresses } from "./core/addr";
import { buildMemo, verifyAttestation, type VerifiedAttestation } from "./core/attest";
import { browserNetwork, NETWORKS, type Network } from "./core/networks";
import {
  formatQor,
  isScanResult,
  projectAfterRegistration,
  scanAddress,
  scanMany,
  type ScanResult,
} from "./core/scan";
import { connectNative, qorexState, sendAttestation } from "./qorex";

type NetName = "testnet" | "mainnet";
/** Fee headroom: registering an ML-DSA-87 key costs ~0.06-0.09 QOR, a hybrid send ~0.05. */
const NEED_UNREGISTERED_UQOR = 150_000n;
const NEED_REGISTERED_UQOR = 60_000n;
type Row = ScanResult | { input: string; error: string };

const EXAMPLES: Record<NetName, string[]> = {
  testnet: [
    "qor1p2pkkdjkg3486c87skry656ys5wharvz9hwkxm",
    "qor1ll7hhj8eskhxgsr2f6me6v0yu8du8yn5knmwxq",
    "0xffc267ab318abc548a2d1c5c955a5daf9667eae5",
  ],
  mainnet: [],
};

function readUrl() {
  const p = new URLSearchParams(window.location.search);
  const n = p.get("n") === "mainnet" ? "mainnet" : "testnet";
  return { net: n as NetName, addrs: splitAddresses((p.get("a") ?? "").replace(/,/g, " ")), tx: p.get("tx") ?? "" };
}

function writeUrl(net: NetName, addrs: string[], tx?: string) {
  const p = new URLSearchParams();
  if (net !== "testnet") p.set("n", net);
  if (addrs.length) p.set("a", addrs.join(","));
  if (tx) p.set("tx", tx);
  const q = p.toString();
  window.history.replaceState(null, "", q ? `?${q}` : window.location.pathname);
}

/** Renders `code` spans in finding text (the same strings the CLI prints). */
function Rich({ text }: { text: string }) {
  return <>{text.split(/`([^`]+)`/).map((part, i) => (i % 2 ? <code key={i}>{part}</code> : part))}</>;
}

function GradeBadge({ grade }: { grade: ScanResult["grade"] }) {
  return <span className={`grade grade-${grade === "n/a" ? "na" : grade}`}>{grade}</span>;
}

function ResultCard({ r }: { r: Row }) {
  if (!isScanResult(r)) {
    return (
      <article className="card card-error">
        <code className="addr">{r.input}</code>
        <p>{r.error}</p>
      </article>
    );
  }
  const holdings = [
    r.kind !== "unseen" ? formatQor(r.liquidUqor) : "",
    r.stakedUqor > 0n ? `${formatQor(r.stakedUqor)} staked` : "",
    ...r.otherBalances.map((t) => `${t.amount} ${t.symbol}`),
  ].filter(Boolean);
  return (
    <article className="card">
      <header className="card-head">
        <GradeBadge grade={r.grade} />
        <div>
          <code className="addr">{r.address.qor}</code>
          {r.address.evm && <code className="addr sub">{r.address.evm}</code>}
          <p className="verdict">
            {r.kind !== "contract" && <strong>{r.readiness}/100 · </strong>}
            {r.verdict}
          </p>
        </div>
      </header>
      <ul className="facts">
        <li>{r.pqc ? `PQC key: ${r.pqc.algorithm}` : "PQC key: none"}</li>
        <li>{r.classicalPubkeyOnChain ? `Classical key public (${r.classicalKeyType})` : "Classical key not on chain"}</li>
        {holdings.length > 0 && <li>Holds {holdings.join(" · ")}</li>}
      </ul>
      <ul className="findings">
        {r.findings.map((f) => (
          <li key={f.id} className={`finding sev-${f.severity}`}>
            <div className="finding-title">
              <span className="sev">{f.severity}</span> {f.title}
            </div>
            <p>
              <Rich text={f.detail} />
            </p>
            {f.fix && (
              <p className="fix">
                <span>Fix</span> <Rich text={f.fix} />
              </p>
            )}
          </li>
        ))}
      </ul>
    </article>
  );
}

function VerifyResult({ v, net }: { v: VerifiedAttestation; net: Network }) {
  return (
    <div className={`verify ${v.hybridVerified ? "ok" : "bad"}`}>
      <p className="verify-head">
        {v.hybridVerified ? "Hybrid-signed: secp256k1 + ML-DSA-87, both verified" : "Not a verified hybrid-signed transaction"}
      </p>
      <ul>
        {v.checks.map((c) => (
          <li key={c.label}>
            <span className={`mark ${c.ok === true ? "pass" : c.ok === false ? "fail" : "na"}`}>
              {c.ok === true ? "PASS" : c.ok === false ? "FAIL" : "n/a"}
            </span>
            <strong>{c.label}</strong> {c.detail}
          </li>
        ))}
      </ul>
      <a href={net.explorerTx(v.tx.txhash)} target="_blank" rel="noreferrer">
        Open {v.tx.txhash.slice(0, 10)}… in the explorer
      </a>
      {net.explorerNote && <span className="muted"> ({net.explorerNote})</span>}
      {" · "}
      <a href={net.restTx(v.tx.txhash)} target="_blank" rel="noreferrer">
        raw tx JSON
      </a>
    </div>
  );
}

export function App() {
  const initial = useMemo(readUrl, []);
  const [netName, setNetName] = useState<NetName>(initial.net);
  const net = useMemo(() => browserNetwork(netName, window.location.origin), [netName]);
  const [text, setText] = useState(initial.addrs.join("\n"));
  const [rows, setRows] = useState<Row[]>([]);
  const [scanning, setScanning] = useState(false);
  const [txInput, setTxInput] = useState(initial.tx);
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState<VerifiedAttestation | undefined>();
  const [verifyError, setVerifyError] = useState("");
  const [attestStep, setAttestStep] = useState("");
  const [attestError, setAttestError] = useState("");
  const { address: evmAddress, isConnected } = useAccount();
  const qorex = qorexState();

  const runScan = useCallback(
    async (inputs: string[]) => {
      if (!inputs.length) return;
      setScanning(true);
      setRows([]);
      writeUrl(netName, inputs);
      const acc: Row[] = new Array(inputs.length);
      await scanMany(inputs, net, {}, () => undefined).then((res) => res.forEach((r, i) => (acc[i] = r)));
      setRows(acc);
      setScanning(false);
    },
    [net, netName],
  );

  const runVerify = useCallback(
    async (hash: string) => {
      setVerifying(true);
      setVerified(undefined);
      setVerifyError("");
      try {
        const v = await verifyAttestation(hash, net);
        if (!v) setVerifyError(`${net.chainId} does not know this transaction.`);
        else setVerified(v);
      } catch (err) {
        setVerifyError(err instanceof Error ? err.message : String(err));
      } finally {
        setVerifying(false);
      }
    },
    [net],
  );

  useEffect(() => {
    if (initial.addrs.length) void runScan(initial.addrs);
    if (initial.tx) void runVerify(initial.tx);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const scanMine = async () => {
    const mine: string[] = [];
    if (evmAddress) mine.push(toQorAddress(evmAddress));
    if (qorex === "ready") {
      try {
        mine.push((await connectNative(net.chainId)).address);
      } catch {
        /* the user declined; the EVM address is enough */
      }
    }
    const list = splitAddresses(mine.join(" "));
    setText(list.join("\n"));
    void runScan(list);
  };

  const attest = async () => {
    setAttestError("");
    try {
      setAttestStep("Connecting to QoreX…");
      const { address } = await connectNative(net.chainId);
      setAttestStep("Scanning your account…");
      const before = await scanAddress(address, net);
      setRows([before]);
      setText(address);
      const need = before.pqc ? NEED_REGISTERED_UQOR : NEED_UNREGISTERED_UQOR;
      if (before.liquidUqor < need) {
        throw new Error(
          `This account holds ${formatQor(before.liquidUqor)}. Attesting needs about ${formatQor(need)} for network fees` +
            (before.pqc ? "." : " (key registration plus the attestation).") +
            (netName === "testnet" ? " Testnet QOR comes from the faucet on the QoreChain dashboard." : ""),
        );
      }
      const memo = await buildMemo(projectAfterRegistration(before));
      setAttestStep(
        before.pqc
          ? "Approve the attestation in QoreX…"
          : "Approve in QoreX: it registers your ML-DSA-87 key, then sends the attestation…",
      );
      const res = await sendAttestation(net.chainId, address, memo);
      setAttestStep(`Sent ${res.txHash.slice(0, 10)}… (${res.shield}). Verifying…`);
      setTxInput(res.txHash);
      writeUrl(netName, [address], res.txHash);
      await runVerify(res.txHash);
      void runScan([address]);
      setAttestStep("");
    } catch (err) {
      setAttestStep("");
      setAttestError(err instanceof Error ? err.message : String(err));
    }
  };

  const ok = rows.filter(isScanResult);
  const atRisk = ok.filter((r) => r.findings.some((f) => f.severity === "critical" || f.severity === "high"));

  return (
    <div className="page">
      <header className="top">
        <div>
          <h1>Q-Day Readiness Audit</h1>
          <p className="tag">Which QoreChain accounts would a quantum attacker take first? Scan, fix, and prove it on chain.</p>
        </div>
        <div className="top-right">
          <select
            aria-label="Network"
            value={netName}
            onChange={(e) => {
              setNetName(e.target.value as NetName);
              setRows([]);
              setVerified(undefined);
            }}
          >
            <option value="testnet">Testnet (Diana)</option>
            <option value="mainnet">Mainnet (Vladi)</option>
          </select>
          <ConnectButton chainStatus="none" showBalance={false} />
        </div>
      </header>

      <section className="panel">
        <label htmlFor="addrs">Addresses (qor1… or 0x…, one per line)</label>
        <textarea
          id="addrs"
          rows={4}
          spellCheck={false}
          value={text}
          placeholder="qor1… or 0x…"
          onChange={(e) => setText(e.target.value)}
        />
        <div className="actions">
          <button type="button" className="primary" disabled={scanning} onClick={() => runScan(splitAddresses(text))}>
            {scanning ? "Scanning…" : "Scan"}
          </button>
          <button type="button" disabled={scanning || (!isConnected && qorex !== "ready")} onClick={scanMine}>
            Scan my wallet
          </button>
          {EXAMPLES[netName].length > 0 && (
            <button
              type="button"
              className="link"
              onClick={() => {
                setText(EXAMPLES[netName].join("\n"));
                void runScan(EXAMPLES[netName]);
              }}
            >
              Try examples
            </button>
          )}
        </div>
      </section>

      {ok.length > 1 && (
        <p className="summary">
          {ok.length} accounts scanned · <strong>{atRisk.length}</strong> need a post-quantum key now ·{" "}
          <button type="button" className="link" onClick={() => navigator.clipboard?.writeText(window.location.href)}>
            Copy share link
          </button>
        </p>
      )}
      <div className="results">
        {rows.map((r, i) => (
          <ResultCard key={i} r={r} />
        ))}
      </div>

      <section className="panel two">
        <div>
          <h2>Prove your account is ready</h2>
          <p>
            Records your readiness grade on {NETWORKS[netName].chainId} with one transaction signed by both your
            secp256k1 key and your ML-DSA-87 key: 0.000001 QOR to yourself, plus the network fee. If your key is not
            registered yet, QoreX registers it first in the same approval.
          </p>
          {qorex === "missing" && <p className="note">Install the QoreX extension to attest. Scanning works without it.</p>}
          {qorex === "outdated" && <p className="note">Update QoreX: this build cannot send native transactions.</p>}
          <button type="button" className="primary" disabled={qorex !== "ready" || Boolean(attestStep)} onClick={attest}>
            Attest with QoreX
          </button>
          {attestStep && <p className="status">{attestStep}</p>}
          {attestError && <p className="error">{attestError}</p>}
        </div>
        <div>
          <h2>Verify an attestation</h2>
          <p>Checks both signatures of any transaction against the signer's registered key.</p>
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              void runVerify(txInput);
            }}
          >
            <input
              aria-label="Transaction hash"
              placeholder="Transaction hash"
              spellCheck={false}
              value={txInput}
              onChange={(e) => setTxInput(e.target.value)}
            />
            <button type="submit" disabled={verifying || !txInput.trim()}>
              {verifying ? "Checking…" : "Verify"}
            </button>
          </form>
          {verifyError && <p className="error">{verifyError}</p>}
          {verified && <VerifyResult v={verified} net={net} />}
        </div>
      </section>

      <footer className="foot">
        <p>
          How the score works: an account without a registered ML-DSA-87 key is protected only by ECDSA. Once its
          public key is on chain, a quantum computer can derive the private key, and the first post-quantum key
          registered for an account binds it, so an attacker could register theirs and lock the owner out. Open EVM
          windows, EIP-7702 delegations and extra authenticators add exposure. Reads are public chain data; nothing
          is stored.
        </p>
        <p>
          Command line: <code>npx tsx src/cli/qday.ts scan &lt;address&gt;</code> · MIT licence
        </p>
      </footer>
    </div>
  );
}
