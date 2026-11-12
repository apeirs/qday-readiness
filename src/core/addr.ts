import { fromBech32, fromHex, toBech32, toHex } from "@cosmjs/encoding";

export interface ParsedAddress {
  /** What the user typed, trimmed. */
  input: string;
  /** Lower-case bech32 `qor1…`. */
  qor: string;
  /** `0x…` twin (same 20 bytes) or undefined for a 32-byte contract address. */
  evm?: `0x${string}`;
  /** 20 for accounts, 32 for QoreChain Native (Wasm) contracts and module-derived addresses. */
  byteLength: number;
}

const HEX20 = /^0x[0-9a-fA-F]{40}$/;

/** Parse a `qor1…` or `0x…` address. Throws a readable error for anything else. */
export function parseAddress(raw: string): ParsedAddress {
  const input = raw.trim();
  if (!input) throw new Error("Empty address.");
  if (HEX20.test(input)) {
    const bytes = fromHex(input.slice(2));
    return { input, qor: toBech32("qor", bytes), evm: `0x${toHex(bytes)}`, byteLength: 20 };
  }
  if (/^qor1[02-9ac-hj-np-z]+$/i.test(input)) {
    let decoded;
    try {
      // Explicit length limit: cosmjs 0.39 passes Infinity to @scure/base, which now rejects it.
      decoded = fromBech32(input.toLowerCase(), 90);
    } catch {
      throw new Error(`"${input}" is not a valid qor1 address (checksum failed).`);
    }
    if (decoded.prefix !== "qor") throw new Error(`"${input}" has prefix ${decoded.prefix}, expected qor.`);
    const n = decoded.data.length;
    if (n !== 20 && n !== 32) throw new Error(`"${input}" decodes to ${n} bytes; expected 20 or 32.`);
    return {
      input,
      qor: toBech32("qor", decoded.data),
      evm: n === 20 ? (`0x${toHex(decoded.data)}` as `0x${string}`) : undefined,
      byteLength: n,
    };
  }
  if (/^qorvaloper1/i.test(input)) {
    const // Explicit length limit: cosmjs 0.39 passes Infinity to @scure/base, which now rejects it.
      decoded = fromBech32(input.toLowerCase(), 90);
    return parseAddress(toBech32("qor", decoded.data));
  }
  throw new Error(`"${input}" is not a qor1… or 0x… address.`);
}

/** Split free text (commas, spaces, new lines) into unique address candidates. */
export function splitAddresses(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  // "#" starts a comment that runs to the end of the line.
  const body = text.split(/\r?\n/).map((line) => line.replace(/#.*/, "")).join("\n");
  for (const tok of body.split(/[\s,;]+/)) {
    const t = tok.trim();
    if (!t) continue;
    const key = t.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}
