// Browser end-to-end check of the built app, keyless and read-only.
//   npm run build && npx playwright install chromium && npm run test:e2e
// Starts `server.mjs` on a free port, then: one-click examples in light and dark (mobile width), a share link,
// a never-seen address, the ?tx= verify deep link, and QoreX (the official @qorechain/qorex-wallet-mock) with a
// throwaway key made for this run: "Scan my wallet" and the "Attest with QoreX" refusal for an unfunded account.
// Every transaction broadcast is blocked at the network layer and counted; the run fails if the page tries one.
// CHROME=/path/to/chrome uses an existing browser instead of Playwright's download.
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { deriveNativeAccount, generateMnemonic } from "@qorechain/sdk";
import { createQorexMock } from "@qorechain/qorex-wallet-mock";
import { chromium } from "playwright";

const EXAMPLE_TX = "6B8EED3EC26B019CB9485BEFFC6B5F81DB04A59F54703A404DB539852ED045F8";
const UNSEEN = "qor1zg6pydqjxsfrgy35zg6pydqjxsfrgy35qvlvn7"; // 0x1234…1234, never used on Diana
const T = 60_000;

let failures = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`);
  if (!cond) failures++;
};

const port = await new Promise((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => {
    const p = s.address().port;
    s.close(() => resolve(p));
  });
});
const server = spawn(process.execPath, ["server.mjs"], { env: { ...process.env, PORT: String(port), HOST: "127.0.0.1" }, stdio: ["ignore", "pipe", "inherit"] });
await new Promise((resolve, reject) => {
  server.stdout.on("data", (d) => String(d).includes("http://") && resolve());
  server.on("exit", (c) => reject(new Error(`server.mjs exited (${c}); run \`npm run build\` first`)));
});
const BASE = `http://127.0.0.1:${port}`;

const browser = await chromium.launch({ headless: true, ...(process.env.CHROME ? { executablePath: process.env.CHROME } : {}) });
let broadcasts = 0;
async function newPage(options = {}, init) {
  const ctx = await browser.newContext(options);
  if (init) await ctx.addInitScript(init);
  // Nothing in this check may reach the chain as a write.
  await ctx.route(/\/cosmos\/tx\/v1beta1\/txs(\?|$)/, (route) => {
    if (route.request().method() !== "GET") {
      broadcasts++;
      return route.abort();
    }
    return route.continue();
  });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  return { ctx, page, errors };
}

try {
  for (const scheme of ["light", "dark"]) {
    const { ctx, page, errors } = await newPage({ colorScheme: scheme, viewport: { width: scheme === "dark" ? 390 : 1100, height: 900 } });
    await page.goto(BASE + "/");
    await page.getByRole("button", { name: /Try examples/ }).click();
    await page.waitForFunction(() => document.querySelectorAll(".card .grade").length >= 3, null, { timeout: T });
    const grades = (await page.$$eval(".card .grade", (els) => els.map((e) => e.textContent))).join("");
    ok(grades === "FDA", `${scheme}: one-click examples grade ${grades} (expected FDA)`);
    ok(page.url().includes("a=qor1p2pkk"), `${scheme}: the scan is in the share link`);
    ok(!(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)), `${scheme}: no horizontal scroll`);
    ok(errors.length === 0, `${scheme}: no page errors${errors.length ? ": " + errors.join(" | ") : ""}`);
    await ctx.close();
  }

  {
    const { ctx, page } = await newPage();
    await page.goto(`${BASE}/?a=${UNSEEN}`);
    await page.waitForSelector(".card .grade", { timeout: T });
    const grade = await page.textContent(".card .grade");
    ok(grade === "B", `never-seen address grades ${grade}: no post-quantum key, so not A`);
    await ctx.close();
  }

  {
    const { ctx, page } = await newPage();
    await page.goto(`${BASE}/?tx=${EXAMPLE_TX}`);
    await page.waitForSelector(".verify", { timeout: T });
    const head = (await page.textContent(".verify-head")) ?? "";
    ok(/both verified/.test(head), `verify deep link: ${head.trim()}`);
    const text = await page.textContent(".verify");
    ok(/Recorded in QDayRegistry/.test(text ?? ""), "verify shows the QDayRegistry row");
    await ctx.close();
  }

  {
    const mnemonic = generateMnemonic(256); // throwaway, never funded, never written anywhere
    const { address } = await deriveNativeAccount(mnemonic);
    const mock = createQorexMock({ mnemonic, chainId: "qorechain-diana", rest: `${BASE}/chain/testnet/rest` });
    const { ctx, page, errors } = await newPage({}, mock.initScript());
    await page.goto(BASE + "/");
    const attest = page.getByRole("button", { name: "Attest with QoreX" });
    await page.waitForFunction(() => [...document.querySelectorAll("button")].some((b) => b.textContent === "Attest with QoreX" && !b.disabled), null, { timeout: T });
    ok(await attest.isEnabled(), "QoreX detected: Attest enabled");
    await page.getByRole("button", { name: "Scan my wallet" }).click();
    await page.waitForSelector(".card .addr", { timeout: T });
    ok((await page.textContent(".card .addr")) === address, "Scan my wallet scans the QoreX account");
    await attest.click();
    await page.waitForSelector(".panel.two .error", { timeout: T });
    const msg = (await page.textContent(".panel.two .error")) ?? "";
    ok(/holds 0 QOR/.test(msg), `Attest refuses an unfunded account before signing: "${msg.trim()}"`);
    ok(errors.length === 0, `QoreX: no page errors${errors.length ? ": " + errors.join(" | ") : ""}`);
    await ctx.close();
  }
  ok(broadcasts === 0, `no transaction broadcast attempted (${broadcasts})`);
} finally {
  await browser.close();
  server.kill();
}
console.log(failures ? `\n${failures} check(s) failed` : "\nAll browser checks passed.");
process.exitCode = failures ? 1 : 0;
