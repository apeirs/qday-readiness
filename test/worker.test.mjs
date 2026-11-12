// Worker gateway tests (plain node --test, no Cloudflare runtime needed).
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { createServer, request } from "node:http";
import { BROADCAST_MAX_BYTES, BROADCAST_TARGET, UPSTREAMS, checkBroadcast, gatewayMiddleware, upstreamFor } from "../gateway.mjs";
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
  globalThis.fetch = async (url, opts) => { calls.push(String(url)); calls.opts = opts; return upstream(String(url), opts); };
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
  assert.deepEqual([...calls], [`https://api-testnet.qore.host/cosmos/tx/v1beta1/txs/${TX}`]);
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

// ---- The single write route: POST /chain/testnet/rest/cosmos/tx/v1beta1/txs ----
const BPATH = "/chain/testnet/rest/cosmos/tx/v1beta1/txs";
const TXB = Buffer.from("signed tx bytes, any length".repeat(40)).toString("base64");
const GOOD = JSON.stringify({ tx_bytes: TXB, mode: "BROADCAST_MODE_SYNC" });
const post = (body, type = "application/json", path = BPATH, method = "POST") =>
  ({ path, init: { method, body, headers: type ? { "content-type": type } : {} } });
const enc = (x) => new TextEncoder().encode(x);

test("broadcast check: accepts only JSON {tx_bytes, mode: SYNC} up to 64 KB", () => {
  assert.equal(checkBroadcast("application/json", enc(GOOD)).body, GOOD);
  assert.equal(checkBroadcast("application/json; charset=utf-8", enc(GOOD)).body, GOOD);
  const bad = {
    "wrong mode BLOCK": ["application/json", JSON.stringify({ tx_bytes: TXB, mode: "BROADCAST_MODE_BLOCK" })],
    "wrong mode ASYNC": ["application/json", JSON.stringify({ tx_bytes: TXB, mode: "BROADCAST_MODE_ASYNC" })],
    "mode lower case": ["application/json", JSON.stringify({ tx_bytes: TXB, mode: "broadcast_mode_sync" })],
    "mode as number": ["application/json", JSON.stringify({ tx_bytes: TXB, mode: 1 })],
    "mode missing": ["application/json", JSON.stringify({ tx_bytes: TXB })],
    "extra field": ["application/json", JSON.stringify({ tx_bytes: TXB, mode: "BROADCAST_MODE_SYNC", x: 1 })],
    "not JSON": ["application/json", "tx_bytes=" + TXB],
    "JSON array": ["application/json", JSON.stringify([TXB, "BROADCAST_MODE_SYNC"])],
    "text/plain": ["text/plain", GOOD],
    "form": ["application/x-www-form-urlencoded", GOOD],
    "no content-type": [undefined, GOOD],
    "jsonx": ["application/jsonx", GOOD],
    "tx_bytes not base64": ["application/json", JSON.stringify({ tx_bytes: "../../etc", mode: "BROADCAST_MODE_SYNC" })],
    "tx_bytes object": ["application/json", JSON.stringify({ tx_bytes: { a: 1 }, mode: "BROADCAST_MODE_SYNC" })],
    "bad utf-8": ["application/json", new Uint8Array([0x7b, 0xff, 0x7d])],
    oversize: ["application/json", JSON.stringify({ tx_bytes: "A".repeat(BROADCAST_MAX_BYTES), mode: "BROADCAST_MODE_SYNC" })],
  };
  for (const [name, [type, body]] of Object.entries(bad)) {
    const r = checkBroadcast(type, typeof body === "string" ? enc(body) : body);
    assert.equal(r.body, undefined, name);
    assert.ok([400, 413, 415].includes(r.status), `${name} -> ${r.status}`);
  }
});

test("worker broadcast: valid tx is relayed to testnet only, response passed through unchanged", async () => {
  const answer = '{"tx_response":{"txhash":"AB","code":0,"raw_log":""}}';
  const { path, init } = post(GOOD);
  const { res, calls } = await run(path, init, () => new Response(answer, { status: 200, headers: { "content-type": "application/json" } }));
  assert.deepEqual([...calls], [BROADCAST_TARGET]);
  assert.equal(BROADCAST_TARGET, "https://api-testnet.qore.host/cosmos/tx/v1beta1/txs");
  assert.equal(calls.opts.method, "POST");
  assert.equal(calls.opts.body, GOOD);
  assert.equal(calls.opts.redirect, "manual");
  assert.equal(res.status, 200);
  assert.equal(await res.text(), answer);
  assert.equal(res.headers.get("cache-control"), "no-store");

  // A refusal from the chain is passed through as-is too.
  const refusal = '{"code":3,"message":"tx parse error","details":[]}';
  const r2 = await run(path, post(GOOD).init, () => new Response(refusal, { status: 400, headers: { "content-type": "application/json" } }));
  assert.equal(r2.res.status, 400);
  assert.equal(await r2.res.text(), refusal);
});

test("worker broadcast: every other write is refused before reaching the chain", async () => {
  const cases = [
    ["wrong mode", post(JSON.stringify({ tx_bytes: TXB, mode: "BROADCAST_MODE_BLOCK" })), 400],
    ["non-JSON body", post("not json at all"), 400],
    ["non-JSON type", post(GOOD, "text/plain"), 415],
    ["no type", post(GOOD, null), 415],
    ["oversize", post(JSON.stringify({ tx_bytes: "A".repeat(BROADCAST_MAX_BYTES), mode: "BROADCAST_MODE_SYNC" })), 413],
    ["mainnet", post(GOOD, "application/json", "/chain/mainnet/rest/cosmos/tx/v1beta1/txs"), 405],
    ["query string", post(GOOD, "application/json", BPATH + "?mode=BLOCK"), 405],
    ["trailing slash", post(GOOD, "application/json", BPATH + "/"), 405],
    ["dot segment", post(GOOD, "application/json", "/chain/testnet/rest/cosmos/tx/v1beta1/txs/../txs/" + TX), 405],
    ["simulate", post(GOOD, "application/json", "/chain/testnet/rest/cosmos/tx/v1beta1/simulate"), 405],
    ["rpc broadcast", post(GOOD, "application/json", "/chain/testnet/rpc/broadcast_tx_sync"), 405],
    ["PUT", post(GOOD, "application/json", BPATH, "PUT"), 405],
    ["PATCH", post(GOOD, "application/json", BPATH, "PATCH"), 405],
    ["DELETE", { path: BPATH, init: { method: "DELETE" } }, 405],
  ];
  for (const [name, { path, init }, status] of cases) {
    const { res, calls } = await run(path, init);
    assert.equal(res.status, status, name);
    assert.equal(calls.length, 0, name);
    if (status === 405) assert.equal(res.headers.get("allow"), "GET", name);
  }
  // Oversize body streamed without a content-length is cut off at the cap.
  let sent = 0;
  const stream = new ReadableStream({ pull(c) { if (sent > 3 * BROADCAST_MAX_BYTES) return c.close(); sent += 16384; c.enqueue(new Uint8Array(16384).fill(65)); } });
  const { res, calls } = await run(BPATH, { method: "POST", body: stream, duplex: "half", headers: { "content-type": "application/json" } });
  assert.equal(res.status, 413);
  assert.equal(calls.length, 0);
  assert.ok(sent < 3 * BROADCAST_MAX_BYTES, "stopped reading early");
});

test("node gateway (vite + server.mjs) applies the same broadcast rules", async () => {
  const mw = gatewayMiddleware();
  const srv = createServer((req, res) => mw(req, res, () => { res.statusCode = 299; res.end("next"); }));
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const upstream = [];
  globalThis.fetch = async (url, opts) => { upstream.push([String(url), opts]); return new Response('{"tx_response":{"txhash":"CD","code":0}}', { headers: { "content-type": "application/json" } }); };
  const req = (path, method, body, type = "application/json") => new Promise((resolve, reject) => {
    const q = request(base + path, { method, headers: type ? { "content-type": type } : {} }, (res) => {
      let t = "";
      res.on("data", (d) => (t += d));
      res.on("end", () => resolve({ status: res.statusCode, text: t }));
    });
    q.on("error", reject);
    q.end(body ?? undefined);
  });
  try {
    let r = await req(BPATH, "POST", GOOD);
    assert.equal(r.status, 200);
    assert.equal(r.text, '{"tx_response":{"txhash":"CD","code":0}}');
    assert.equal(upstream.length, 1);
    assert.equal(upstream[0][0], BROADCAST_TARGET);
    assert.equal(upstream[0][1].body, GOOD);
    for (const [name, path, method, body, type, status] of [
      ["wrong mode", BPATH, "POST", JSON.stringify({ tx_bytes: TXB, mode: "BROADCAST_MODE_BLOCK" }), "application/json", 400],
      ["non-JSON", BPATH, "POST", "x", "text/plain", 415],
      ["oversize", BPATH, "POST", "A".repeat(BROADCAST_MAX_BYTES + 1), "application/json", 413],
      ["mainnet", "/chain/mainnet/rest/cosmos/tx/v1beta1/txs", "POST", GOOD, "application/json", 405],
      ["other path", "/chain/testnet/rpc/broadcast_tx_sync", "POST", GOOD, "application/json", 405],
      ["PUT", BPATH, "PUT", GOOD, "application/json", 405],
      ["GET trick", "/chain/testnet/rest/cosmos/auth/v1beta1/%2e%2e/x", "GET", null, null, 404],
    ]) {
      r = await req(path, method, body, type);
      assert.equal(r.status, status, name);
    }
    assert.equal(upstream.length, 1, "nothing else reached the chain");
  } finally {
    srv.close();
  }
});
