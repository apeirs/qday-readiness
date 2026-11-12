// Same-origin, read-only gateway to the QoreChain REST and RPC endpoints, which
// send no CORS headers. GET only, and only the query paths the app reads.
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

/** Connect-style middleware: `(req, res, next)`. */
export function gatewayMiddleware() {
  return async (req, res, next) => {
    if (!req.url?.startsWith("/chain/")) return next();
    const target = upstreamFor(req.url);
    if (req.method !== "GET" || !target) {
      res.statusCode = req.method !== "GET" ? 405 : 404;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "not served by this gateway" }));
      return;
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 15_000);
    try {
      const up = await fetch(target, { signal: ctl.signal, headers: { accept: "application/json", "user-agent": "qday-gateway/1" } });
      res.statusCode = up.status;
      res.setHeader("content-type", up.headers.get("content-type") ?? "application/json");
      res.setHeader("cache-control", "no-store");
      res.end(Buffer.from(await up.arrayBuffer()));
    } catch (err) {
      res.statusCode = 502;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: `upstream unreachable: ${err?.name === "AbortError" ? "timeout" : err?.message}` }));
    } finally {
      clearTimeout(timer);
    }
  };
}
