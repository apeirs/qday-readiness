// Cloudflare Worker: serves the built app (dist/, via Workers Static Assets) and the same
// chain gateway as gateway.mjs, on one origin, with the same (shared) checks: GET on the read
// allowlist, plus the single testnet broadcast route (POST, JSON, <= 64 KB, BROADCAST_MODE_SYNC).
//   npx wrangler dev        local, http://127.0.0.1:8787
//   ./deploy.sh             test + build + deploy
import { BROADCAST_TARGET, broadcastBody, isBroadcast, upstreamFor } from "../gateway.mjs";

const TIMEOUT_MS = 15_000;
// Seconds to cache a 200. Transactions never change once found; account state does.
const TTL_TX = 86_400;
const TTL_STATE = 15;
const TX_PATH = /^https:\/\/[^/]+\/(cosmos\/tx\/v1beta1\/txs\/[0-9A-Fa-f]{64}$|tx\?hash=)/;

const json = (status, body, extra = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra },
  });

/** Seconds a successful upstream answer may be cached for. */
export function ttlFor(target) {
  return TX_PATH.test(target) ? TTL_TX : TTL_STATE;
}

/** POST of a signed tx to testnet: body checked by the shared code, never logged or cached. */
async function broadcast(request) {
  const checked = await broadcastBody(request.headers, request.body);
  if (!checked.body) return json(checked.status, { error: checked.error });
  let up;
  try {
    up = await fetch(BROADCAST_TARGET, {
      method: "POST",
      body: checked.body,
      headers: { accept: "application/json", "content-type": "application/json", "user-agent": "qday-gateway/1" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "manual",
    });
  } catch (err) {
    const why = err?.name === "TimeoutError" || err?.name === "AbortError" ? "timeout" : String(err?.message ?? err);
    return json(502, { error: `upstream unreachable: ${why}` });
  }
  if (up.status >= 300 && up.status < 400) return json(502, { error: "upstream redirected" });
  return new Response(up.body, {
    status: up.status,
    headers: { "content-type": up.headers.get("content-type") ?? "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

export async function handleChain(request, ctx) {
  // request.url is already parsed by the runtime (dot segments resolved); the shared checks see
  // exactly the path that gets forwarded, so nothing can normalise past them upstream.
  const url = new URL(request.url);
  if (isBroadcast(request.method, url.pathname + url.search)) return broadcast(request);
  if (request.method !== "GET") return json(405, { error: "not served by this gateway" }, { allow: "GET" });
  const target = upstreamFor(url.pathname + url.search);
  if (!target) return json(404, { error: "not served by this gateway" });

  const cache = globalThis.caches?.default;
  const key = new Request(target);
  const hit = cache && (await cache.match(key).catch(() => undefined));
  if (hit) {
    const r = new Response(hit.body, hit);
    r.headers.set("x-qday-cache", "HIT");
    return r;
  }

  let up;
  try {
    up = await fetch(target, {
      headers: { accept: "application/json", "user-agent": "qday-gateway/1" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "manual",
    });
  } catch (err) {
    const why = err?.name === "TimeoutError" || err?.name === "AbortError" ? "timeout" : String(err?.message ?? err);
    return json(502, { error: `upstream unreachable: ${why}` });
  }
  if (up.status >= 300 && up.status < 400) return json(502, { error: "upstream redirected" });

  const ttl = up.status === 200 ? ttlFor(target) : 0;
  const headers = {
    "content-type": up.headers.get("content-type") ?? "application/json",
    "cache-control": ttl ? `public, max-age=${ttl}` : "no-store",
    "x-content-type-options": "nosniff",
    "x-qday-cache": "MISS",
  };
  const res = new Response(up.body, { status: up.status, headers });
  if (ttl && cache) ctx?.waitUntil?.(cache.put(key, res.clone()).catch(() => {}));
  return res;
}

export default {
  async fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);
    if (pathname === "/chain" || pathname.startsWith("/chain/")) return handleChain(request, ctx);
    return env.ASSETS.fetch(request);
  },
};
