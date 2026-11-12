/** Small fetch wrapper: timeout, one retry on network errors and 5xx, JSON body. */
export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(message);
  }
}

export type FetchLike = typeof fetch;

export interface HttpOptions {
  timeoutMs?: number;
  retries?: number;
  fetch?: FetchLike;
}

async function once(url: string, init: RequestInit, timeoutMs: number, f: FetchLike): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await f(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * GET or POST JSON. Returns `{ status, json }`; 4xx answers are returned (the
 * chain answers "not found" with 404/400 + a JSON body), 5xx and transport
 * failures are retried once and then thrown.
 */
export async function requestJson<T = unknown>(
  url: string,
  init: RequestInit = {},
  opts: HttpOptions = {},
): Promise<{ status: number; json: T | undefined; text: string }> {
  const f = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const retries = opts.retries ?? 1;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await once(url, init, opts.timeoutMs ?? 12_000, f);
      const text = await res.text();
      if (res.status >= 500 && res.status !== 501 && attempt < retries) {
        lastErr = new HttpError(`HTTP ${res.status} from ${url}`, res.status, text);
        continue;
      }
      let json: T | undefined;
      try {
        json = text ? (JSON.parse(text) as T) : undefined;
      } catch {
        json = undefined;
      }
      return { status: res.status, json, text };
    } catch (err) {
      lastErr = err;
      if (attempt >= retries) break;
    }
  }
  const msg = lastErr instanceof Error ? lastErr.message : String(lastErr);
  throw new HttpError(`Could not reach ${new URL(url).host}: ${msg}`, 0, "");
}

export async function getJson<T>(base: string, path: string, opts?: HttpOptions) {
  return requestJson<T>(base.replace(/\/$/, "") + path, { method: "GET" }, opts);
}

export async function evmCall<T>(evmRpc: string, method: string, params: unknown[], opts?: HttpOptions): Promise<T> {
  const { status, json } = await requestJson<{ result?: T; error?: { message: string } }>(
    evmRpc,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    },
    opts,
  );
  if (!json || status >= 400) throw new HttpError(`EVM RPC ${method} failed (HTTP ${status})`, status, "");
  if (json.error) throw new Error(`EVM RPC ${method}: ${json.error.message}`);
  return json.result as T;
}
