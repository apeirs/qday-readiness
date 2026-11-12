// Worker gateway tests (plain node --test, no Cloudflare runtime needed).
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { UPSTREAMS, upstreamFor } from "../gateway.mjs";
import worker, { ttlFor } from "../worker/index.mjs";

const QOR = "qor1ay8cveqak7yx8wd4us9mk8q7eak3dj56nz545m";
const TX = "3DC0994B1BFF78D1ECA2D90CFCE02DF08CA54A0FDADAFA87BB23A6C769D2113B";
const ORIGIN = "https://qday.example";
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

const REST_ALLOW = /^\/(cosmos\/(auth|bank|staking|tx|upgrade)\/v1beta1\/|qorechain\/(pqc|abstractaccount)\/v1\/)/;
const HOSTS = new Set(Object.values(UPSTREAMS).flatMap((u) => [u.rest, u.rpc].map((x) => new URL(x).host)));

/** Every forwarded URL must stay on an upstream host and keep, after URL parsing, exactly the checked path. */
function assertSafeTarget(target, input) {
  const u = new URL(target);
  assert.ok(HOSTS.has(u.host), `host ${u.host} for ${input}`);
  assert.equal(u.username + u.password, "", `userinfo for ${input}`);
  const sent = target.slice(target.indexOf("/", 8)).split("?")[0];
  assert.equal(u.pathname, sent, `path normalised upstream for ${input}`);
  if (u.host.startsWith("rpc")) assert.match(u.pathname, /^\/(tx|status)$/, input);
  else assert.match(u.pathname, REST_ALLOW, input);
}

/** Run a request through the Worker with a fake upstream; returns the response and the upstream calls. */
async function run(path, init = {}, upstream = () => new Response('{"ok":true}', { headers: { "content-type": "application/json" } })) {
  const calls = [];
  globalThis.fetch = async (url, opts) => { calls.push(String(url)); return upstream(String(url), opts); };
  const assets = { fetch: async (req) => new Response(`asset ${new URL(req.url).pathname}`, { headers: { "content-type": "text/html" } }) };
  const res = await worker.fetch(new Request(ORIGIN + path, init), { ASSETS: assets }, { waitUntil() {} });
  return { res, calls };
}

const TRICKS = [
  "/chain/testnet/rest/cosmos/gov/v1/proposals",
  "/chain/testnet/rest/cosmos/auth/v1beta1/../../../cosmos/gov/v1/proposals",
  "/chain/testnet/rest/cosmos/auth/v1beta1/%2e%2e/%2e%2e/%2e%2e/cosmos/gov/v1/proposals",
  "/chain/testnet/rest/cosmos/auth/v1beta1/%2E%2E/x",
  "/chain/testnet/rest/cosmos/auth/v1beta1/.%2e/.%2e/.%2e/cosmos/gov/v1/proposals",
  "/chain/testnet/rest/cosmos/auth/v1beta1/%252e%252e/%252e%252e/cosmos/gov/v1/proposals",
  "/chain/testnet/rest/cosmos/auth/v1beta1/%2f..%2f..%2fcosmos/gov",
  "/chain/testnet/rest/cosmos/auth/v1beta1/..%5c..%5ccosmos/gov",
  "/chain/testnet/rest/cosmos/auth/v1beta1\\..\\..\\cosmos/gov",
  "/chain/testnet/rest/cosmos/auth/v1beta1//x",
  "/chain/testnet/rest//cosmos/auth/v1beta1/accounts/x",
  "/chain/testnet/rest/cosmos/auth/v1beta1/%0a/x",
  "/chain/testnet/rest/cosmos/auth/v1beta1/accounts/x%3f/../../../gov/v1/proposals",
  "/chain/testnet/rest/@evil.example/cosmos/auth/v1beta1/accounts/x",
  "/chain/testnet/rest/cosmos/auth/v1beta1/accounts/x@evil.example",
  "/chain/testnet/rest:443/cosmos/auth/v1beta1/accounts/x",
  "/chain/testnet/rpc/broadcast_tx_sync?tx=00",
  "/chain/testnet/rpc/broadcast_tx_commit?/status",
  "/chain/testnet/rpc/status/../broadcast_tx_sync?tx=00",
  "/chain/testnet/rpc/tx%3fhash=1/../../broadcast_tx_sync",
  "/chain/testnet/rpc/txs",
  "/chain/testnet/rpc/",
  "/chain/testnet/rpc",
  "/chain/testnet/rest",
  "/chain/devnet/rest/cosmos/auth/v1beta1/accounts/x",
  "/chain/testnet/grpc/cosmos/auth/v1beta1/accounts/x",
  "/chain/testnet/rest/../../mainnet/rest/cosmos/gov/v1/proposals",
];

test("allowlist: legitimate app reads map to the right upstream", () => {
  assert.equal(upstreamFor(`/chain/testnet/rest/cosmos/bank/v1beta1/balances/${QOR}?pagination.limit=200`),
    `https://api-testnet.qore.host/cosmos/bank/v1beta1/balances/${QOR}?pagination.limit=200`);
  assert.equal(upstreamFor(`/chain/testnet/rest/cosmos/tx/v1beta1/txs/${TX}`), `https://api-testnet.qore.host/cosmos/tx/v1beta1/txs/${TX}`);
  assert.equal(upstreamFor(`/chain/mainnet/rest/qorechain/pqc/v1/account/${QOR}`), `https://api.qore.host/qorechain/pqc/v1/account/${QOR}`);
  assert.equal(upstreamFor("/chain/testnet/rpc/tx?hash=0xAB"), "https://rpc-testnet.qore.host/tx?hash=0xAB");
  assert.equal(upstreamFor("/chain/testnet/rpc/status"), "https://rpc-testnet.qore.host/status");
});

test("allowlist: raw path tricks are rejected before any URL parsing", () => {
  for (const bad of TRICKS) assert.equal(upstreamFor(bad), undefined, bad);
});

test("allowlist: query strings cannot change the forwarded path or host", () => {
  for (const q of ["?x=/../../cosmos/gov", "?@evil.example", "?a=%2e%2e%2f", "?hash=1&x=/broadcast_tx_sync", "?#/../gov"]) {
    for (const base of [`/chain/testnet/rest/cosmos/auth/v1beta1/accounts/${QOR}`, "/chain/testnet/rpc/tx"]) {
      const t = upstreamFor(base + q);
      assert.ok(t, base + q);
      assertSafeTarget(t, base + q);
    }
  }
});

test("worker: every trick either 404s or forwards only to an allowlisted upstream path", async () => {
  for (const path of TRICKS) {
    const { res, calls } = await run(path);
    // The runtime resolves dot segments before the Worker sees them, so a trick may land on an
    // allowed path (fine) or outside /chain (served as an asset); it must never reach anything else.
    for (const c of calls) assertSafeTarget(c, path);
    if (calls.length === 0) assert.ok([404, 200].includes(res.status), `${path} -> ${res.status}`);
    if (res.status === 200 && calls.length === 0) assert.match(await res.text(), /^asset /, path);
  }
});

test("worker: GET only, nothing forwarded for other methods", async () => {
  for (const method of ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]) {
    const { res, calls } = await run("/chain/testnet/rpc/status", { method, body: ["POST", "PUT", "PATCH"].includes(method) ? "{}" : undefined });
    assert.equal(res.status, 405, method);
    assert.equal(res.headers.get("allow"), "GET");
    assert.equal(calls.length, 0, method);
  }
});

test("worker: forwards an allowed read and sets cache headers", async () => {
  let { res, calls } = await run(`/chain/testnet/rest/cosmos/tx/v1beta1/txs/${TX}`);
  assert.equal(res.status, 200);
  assert.deepEqual(calls, [`https://api-testnet.qore.host/cosmos/tx/v1beta1/txs/${TX}`]);
  assert.equal(res.headers.get("cache-control"), "public, max-age=86400");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("access-control-allow-origin"), null, "same-origin only, no CORS");

  ({ res } = await run(`/chain/testnet/rest/cosmos/bank/v1beta1/balances/${QOR}`));
  assert.equal(res.headers.get("cache-control"), "public, max-age=15");

  ({ res } = await run(`/chain/testnet/rest/cosmos/tx/v1beta1/txs/${TX}`, {}, () => new Response('{"code":5}', { status: 404 })));
  assert.equal(res.status, 404);
  assert.equal(res.headers.get("cache-control"), "no-store", "a tx not found yet may land seconds later");

  assert.equal(ttlFor("https://rpc-testnet.qore.host/tx?hash=0xAB"), 86_400);
  assert.equal(ttlFor("https://rpc-testnet.qore.host/status"), 15);
});

test("worker: upstream failures become a clean 502", async () => {
  let { res } = await run("/chain/testnet/rpc/status", {}, () => { throw new TypeError("network down"); });
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /network down/);
  ({ res } = await run("/chain/testnet/rpc/status", {}, () => { throw new DOMException("t", "TimeoutError"); }));
  assert.equal((await res.json()).error, "upstream unreachable: timeout");
  ({ res } = await run("/chain/testnet/rpc/status", {}, () => new Response(null, { status: 302, headers: { location: "https://evil.example/" } })));
  assert.equal(res.status, 502, "redirects are not followed");
});

test("worker: everything outside /chain is served from the static assets", async () => {
  for (const p of ["/", "/?tx=" + TX, "/assets/index.js", "/chainx", "/x/../chain-not"]) {
    const { res, calls } = await run(p);
    assert.equal(res.status, 200, p);
    assert.match(await res.text(), /^asset /, p);
    assert.equal(calls.length, 0, p);
  }
});
