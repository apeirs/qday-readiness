// Production server: serves dist/ and the read-only chain gateway. No dependencies.
//   npm run build && npm start      (PORT defaults to 8080, HOST to 127.0.0.1)
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { gatewayMiddleware } from "./gateway.mjs";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "dist");
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json", ".woff2": "font/woff2" };
const gateway = gatewayMiddleware();

function serveStatic(req, res) {
  const path = normalize(decodeURIComponent((req.url ?? "/").split("?")[0])).replace(/^(\.\.[/\\])+/, "");
  let file = join(root, path);
  if (!file.startsWith(root) || !existsSync(file) || statSync(file).isDirectory()) file = join(root, "index.html");
  res.setHeader("content-type", types[extname(file)] ?? "application/octet-stream");
  res.setHeader("x-content-type-options", "nosniff");
  createReadStream(file).pipe(res);
}

if (!existsSync(join(root, "index.html"))) {
  console.error("dist/ is missing: run `npm run build` first.");
  process.exit(1);
}
const port = Number(process.env.PORT ?? 8080);
const host = process.env.HOST ?? "127.0.0.1";
createServer((req, res) => gateway(req, res, () => serveStatic(req, res))).listen(port, host, () =>
  console.log(`Q-Day Readiness Audit on http://${host}:${port}`),
);
