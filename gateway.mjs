// Same-origin gateway to the QoreChain REST and RPC endpoints, which send no CORS headers.
// GET only on the query paths the app reads, plus ONE write route: POST of a signed tx to
// testnet /cosmos/tx/v1beta1/txs in BROADCAST_MODE_SYNC (what QoreX-style wallets that use the
// page's REST endpoint send). The Worker (worker/index.mjs) uses the same checks.
// Used by vite.config.ts (dev + preview) and by server.mjs (production).

export const UPSTREAMS = {
  testnet: { rest: "https://api-testnet.qore.host", rpc: "https://rpc-testnet.qore.host" },
  mainnet: { rest: "https://api.qore.host", rpc: "https://rpc.qore.host" },
};

const REST_ALLOW = /^\/(cosmos\/(auth|bank|staking|tx|upgrade)\/v1beta1\/|qorechain\/(pqc|abstractaccount)\/v1\/)/;
const RPC_ALLOW = /^\/(tx|status)(\?|$)/;
const SAFE_PATH = /^[A-Za-z0-9_\-./]*$/;
const PREFIX = /^\/chain\/(testnet|mainnet)\/(rest|rpc)(\/.*)$/;

/** Map `/chain/<net>/<kind>/<path>` to an upstream URL, or undefined if not allowed. */
export function upstreamFor(url) {
  const m = PREFIX.exec(url ?? "");
  if (!m) return undefined;
  const [, net, kind, rest] = m;
  const pathOnly = rest.split("?")[0];
  // The app only reads paths made of bech32/hex ids, so allow nothing else: dot segments, any
  // percent-escape (%2e, %2f, double-encoded %252e), backslashes or empty segments would let the
  // upstream URL normalise or decode past the allowlist.
  if (!SAFE_PATH.test(pathOnly) || /\.\.|\/\//.test(pathOnly)) return undefined;
  if (kind === "rest" && !REST_ALLOW.test(pathOnly)) return undefined;
  if (kind === "rpc" && !RPC_ALLOW.test(rest)) return undefined;
  return UPSTREAMS[net][kind] + rest;
}

/** The one write route: signed-tx broadcast to testnet, exact path, no query string. */
const BROADCAST_PATH = "/chain/testnet/rest/cosmos/tx/v1beta1/txs";
export const BROADCAST_TARGET = `${UPSTREAMS.testnet.rest}/cosmos/tx/v1beta1/txs`;
export const BROADCAST_MAX_BYTES = 64 * 1024;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function isBroadcast(method, url) {
  return method === "POST" && url === BROADCAST_PATH;
}

/**
 * Check a broadcast request body (raw bytes). Returns `{ body }`, the canonical JSON to forward
 * (only `tx_bytes` and `mode`), or `{ status, error }`. Never echoes or logs the body.
 */
export function checkBroadcast(contentType, bytes) {
  if (!/^application\/json\s*(;|$)/i.test(contentType ?? "")) return { status: 415, error: "broadcast body must be application/json" };
  if (!bytes || bytes.byteLength > BROADCAST_MAX_BYTES) return { status: 413, error: `broadcast body over ${BROADCAST_MAX_BYTES} bytes` };
  let j;
  try {
    j = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return { status: 400, error: "broadcast body is not valid JSON" };
  }
  if (!j || typeof j !== "object" || Array.isArray(j) || Object.keys(j).sort().join() !== "mode,tx_bytes")
    return { status: 400, error: "broadcast body must hold exactly tx_bytes and mode" };
  if (j.mode !== "BROADCAST_MODE_SYNC") return { status: 400, error: "only BROADCAST_MODE_SYNC is relayed" };
  if (typeof j.tx_bytes !== "string" || j.tx_bytes.length % 4 !== 0 || !BASE64.test(j.tx_bytes))
    return { status: 400, error: "tx_bytes must be base64" };
  return { body: JSON.stringify({ tx_bytes: j.tx_bytes, mode: "BROADCAST_MODE_SYNC" }) };
}

/**
 * Read a request body (async iterable of byte chunks, or a ReadableStream) but stop past `max`
 * bytes. Returns a Uint8Array, or undefined when the body is larger than `max`.
 */
export async function readCapped(body, max = BROADCAST_MAX_BYTES) {
  const parts = [];
  let size = 0;
  const iter = body?.getReader ? streamChunks(body) : body ?? [];
  for await (const chunk of iter) {
    const c = typeof chunk === "string" ? new TextEncoder().encode(chunk) : new Uint8Array(chunk);
    size += c.byteLength;
    if (size > max) return undefined;
    parts.push(c);
  }
  const out = new Uint8Array(size);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.byteLength; }
  return out;
}

async function* streamChunks(stream) {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      yield value;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

/** Validate a broadcast request: `{ body }` to forward, or `{ status, error }`. */
export async function broadcastBody(headers, stream) {
  const declared = Number(headers.get("content-length") ?? 0);
  if (declared > BROADCAST_MAX_BYTES) return { status: 413, error: `broadcast body over ${BROADCAST_MAX_BYTES} bytes` };
  const bytes = await readCapped(stream);
  if (!bytes) return { status: 413, error: `broadcast body over ${BROADCAST_MAX_BYTES} bytes` };
  return checkBroadcast(headers.get("content-type"), bytes);
}

/** Connect-style middleware: `(req, res, next)`. */
export function gatewayMiddleware() {
  const fail = (res, status, error, extra = {}) => {
    res.statusCode = status;
    res.setHeader("content-type", "application/json");
    for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
    res.end(JSON.stringify({ error }));
  };
  return async (req, res, next) => {
    if (!req.url?.startsWith("/chain/")) return next();
    let target;
    let init;
    if (isBroadcast(req.method, req.url)) {
      const h = new Headers({ "content-type": req.headers["content-type"] ?? "", "content-length": req.headers["content-length"] ?? "0" });
      const checked = await broadcastBody(h, req);
      if (!checked.body) return fail(res, checked.status, checked.error);
      target = BROADCAST_TARGET;
      init = { method: "POST", body: checked.body, redirect: "manual", headers: { "content-type": "application/json" } };
    } else {
      target = upstreamFor(req.url);
      if (req.method !== "GET") return fail(res, 405, "not served by this gateway", { allow: "GET" });
      if (!target) return fail(res, 404, "not served by this gateway");
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 15_000);
    try {
      const up = await fetch(target, { ...init, signal: ctl.signal, headers: { accept: "application/json", "user-agent": "qday-gateway/1", ...init?.headers } });
      if (init && up.status >= 300 && up.status < 400) return fail(res, 502, "upstream redirected");
      res.statusCode = up.status;
      res.setHeader("content-type", up.headers.get("content-type") ?? "application/json");
      res.setHeader("cache-control", "no-store");
      res.end(Buffer.from(await up.arrayBuffer()));
    } catch (err) {
      fail(res, 502, `upstream unreachable: ${err?.name === "AbortError" ? "timeout" : err?.message}`);
    } finally {
      clearTimeout(timer);
    }
  };
}
