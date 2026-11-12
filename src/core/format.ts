import { enforcesHybrid, formatQor, type NetworkPolicy, type ScanResult } from "./scan";

const useColor = typeof process !== "undefined" && process.stdout?.isTTY && !process.env.NO_COLOR;
const c = (code: number, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_COLOR: Record<string, number> = { critical: 31, high: 31, medium: 33, low: 36, info: 90 };
const GRADE_COLOR: Record<string, number> = { A: 32, B: 32, C: 33, D: 31, F: 31, "n/a": 90 };

function wrap(text: string, width = 88, indent = "    "): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width - indent.length) {
      lines.push(line);
      line = w;
    } else line = (line + " " + w).trim();
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join("\n");
}

/** Human-readable terminal report for one scan. */
export function formatScan(r: ScanResult): string {
  const out: string[] = [];
  const head = `${r.address.qor}${r.address.evm ? `  (${r.address.evm})` : ""}`;
  out.push(c(1, head));
  out.push(
    `  ${c(GRADE_COLOR[r.grade] ?? 0, `Grade ${r.grade}`)}  readiness ${r.readiness}/100  ·  ${r.verdict}`,
  );
  const facts: string[] = [];
  if (r.kind !== "unseen") facts.push(`holds ${formatQor(r.liquidUqor)}${r.stakedUqor > 0n ? ` + ${formatQor(r.stakedUqor)} staked` : ""}`);
  for (const t of r.otherBalances) facts.push(`${t.amount} ${t.symbol}`);
  facts.push(r.pqc ? `PQC key: ${r.pqc.algorithm}` : "PQC key: none");
  if (r.pqc?.publicKeyBytes) facts.push(`${r.pqc.publicKeyBytes.toLocaleString("en-US")}-byte key${r.pqc.fingerprint ? ` sha256:${r.pqc.fingerprint}` : ""}`);
  facts.push(r.classicalPubkeyOnChain ? `classical key on chain (${r.classicalKeyType})` : "classical key not on chain");
  out.push("  " + c(90, facts.join(" · ")));
  for (const f of r.findings) {
    out.push(`  ${c(SEV_COLOR[f.severity] ?? 0, f.severity.toUpperCase().padEnd(8))} ${f.title}`);
    out.push(c(90, wrap(f.detail, 92, "           ")));
    if (f.fix) out.push(wrap("Fix: " + f.fix, 92, "           "));
  }
  return out.join("\n");
}

/** JSON-safe copy (bigints as strings). */
export function toJson(r: unknown): unknown {
  return JSON.parse(JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
}

/** One line on what the chain enforces, e.g. "hybrid signatures required · classical-only fallback off · ML-DSA-87, level 5". */
export function describePolicy(p: NetworkPolicy): string {
  return `hybrid signatures ${p.hybridMode} · classical-only fallback ${p.classicalFallback ? "on" : "off"} · ${p.defaultAlgorithm}, level ${p.minSecurityLevel}${enforcesHybrid(p) ? "" : " · a registered key is NOT enforced"}`;
}
