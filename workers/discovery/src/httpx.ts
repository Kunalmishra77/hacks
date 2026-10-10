import { runTool } from "@aegis/worker-kit";

// httpx (ProjectDiscovery, MIT) as a liveness probe: one ordinary GET per
// host:port, the same request a browser makes. Rate-limited to the scope's
// maxRequestsPerSec. No redirect following (a redirect could lead off-scope),
// no paths, no custom payloads.

export interface HttpxResult {
  host: string;
  port: number;
  url: string;
  statusCode: number | undefined;
  title: string | undefined;
  webServer: string | undefined;
  tech: string[];
}

const MAX_THREADS = 5;

export function httpxArgs(ratePerSec: number): string[] {
  const rate = Math.max(1, Math.floor(ratePerSec));
  const threads = Math.min(MAX_THREADS, rate);
  return [
    "-silent", "-nc", "-duc", "-json",
    "-sc", "-title", "-server", "-td",
    "-rl", String(rate), "-t", String(threads), "-timeout", "10", "-retries", "1",
    "-p", "80,443",
  ];
}

export function parseHttpx(stdout: string): HttpxResult[] {
  const out: HttpxResult[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let r: Record<string, unknown>;
    try {
      r = JSON.parse(line);
    } catch {
      continue;
    }
    if (r.failed || typeof r.url !== "string" || typeof r.input !== "string") continue;
    let port = Number(r.port);
    if (!Number.isInteger(port) || port <= 0) {
      try {
        const u = new URL(r.url);
        port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
      } catch {
        continue;
      }
    }
    out.push({
      host: r.input.replace(/^https?:\/\//, "").replace(/[:/].*$/, "").toLowerCase(),
      port,
      url: r.url,
      statusCode: typeof r.status_code === "number" ? r.status_code : undefined,
      title: typeof r.title === "string" ? r.title.slice(0, 200) : undefined,
      webServer: typeof r.webserver === "string" ? r.webserver.slice(0, 100) : undefined,
      tech: Array.isArray(r.tech) ? r.tech.filter((t): t is string => typeof t === "string").slice(0, 20) : [],
    });
  }
  return out;
}

export async function runHttpx(hosts: string[], ratePerSec: number, signal: AbortSignal, bin = "httpx"): Promise<HttpxResult[]> {
  if (hosts.length === 0) return [];
  const r = await runTool({
    bin,
    args: httpxArgs(ratePerSec),
    input: hosts.join("\n") + "\n",
    timeoutMs: 20 * 60_000,
    signal,
    maxOutputBytes: 20 * 1024 * 1024,
  });
  return parseHttpx(r.stdout);
}
