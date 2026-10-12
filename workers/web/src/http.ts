import http from "node:http";
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";

export interface HttpResult {
  status: number;
  /** Lower-cased header names; repeated headers joined with ", " (except Set-Cookie). */
  headers: Record<string, string>;
  setCookies: string[];
  /** First bytes of the body, only for matchers. Never stored. */
  bodyPrefix: string;
}

const USER_AGENT = "AegisASM/1.0 (authorized security assessment)";

/**
 * One GET to `url`, connecting to `ip` (already checked to be public) no
 * matter what DNS says now. No redirects are followed. TLS certificate errors
 * are ignored here: this client reads headers; the TLS engine judges certs.
 */
export function pinnedGet(
  url: URL,
  ip: string,
  opts: { timeoutMs: number; maxBody: number; signal?: AbortSignal },
): Promise<HttpResult> {
  const family = isIP(ip);
  if (!family) return Promise.reject(new Error(`not an IP: ${ip}`));
  const lookup: LookupFunction = (_host, options, cb) => {
    if (options.all) (cb as unknown as (e: null, a: { address: string; family: number }[]) => void)(null, [{ address: ip, family }]);
    else cb(null, ip, family);
  };
  const isHttps = url.protocol === "https:";
  const mod = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const req = mod.request(
      url,
      {
        method: "GET",
        lookup,
        timeout: opts.timeoutMs,
        signal: opts.signal,
        headers: { "user-agent": USER_AGENT, accept: "*/*" },
        ...(isHttps ? { rejectUnauthorized: false, servername: isIP(url.hostname) ? undefined : url.hostname } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        const done = () => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (k === "set-cookie" || v === undefined) continue;
            headers[k] = Array.isArray(v) ? v.join(", ") : v;
          }
          resolve({
            status: res.statusCode ?? 0,
            headers,
            setCookies: res.headers["set-cookie"] ?? [],
            bodyPrefix: Buffer.concat(chunks).subarray(0, opts.maxBody).toString("latin1"),
          });
        };
        res.on("data", (c: Buffer) => {
          if (size >= opts.maxBody) return;
          chunks.push(c);
          size += c.length;
          if (size >= opts.maxBody) {
            done();
            res.destroy();
          }
        });
        res.on("end", done);
        res.on("error", (e) => (size >= opts.maxBody ? undefined : reject(e)));
      },
    );
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    req.end();
  });
}
