import { runTool } from "@aegis/worker-kit";

// fingerprintx (Praetorian, Apache-2.0): identifies the service and version on
// already-open ports with ordinary protocol handshakes. Connect-only (no UDP),
// and we keep only the service name and version string — never raw banners or
// response headers, which can contain sensitive data.

export interface ServiceInfo {
  port: number;
  transport: string;
  service: string;
  version: string;
}

export function fingerprintxArgs(timeoutMs: number): string[] {
  return ["--json", "-w", String(timeoutMs)];
}

export function parseFingerprintx(stdout: string): ServiceInfo[] {
  const out: ServiceInfo[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as { port?: unknown; transport?: unknown; service?: unknown; metadata?: { version?: unknown } };
      if (typeof r.port !== "number") continue;
      out.push({
        port: r.port,
        transport: typeof r.transport === "string" ? r.transport : "tcp",
        service: typeof r.service === "string" ? r.service : "unknown",
        version: typeof r.metadata?.version === "string" ? r.metadata.version.slice(0, 200) : "",
      });
    } catch {
      // ignore
    }
  }
  return out;
}

export async function runFingerprintx(
  ip: string,
  ports: number[],
  signal: AbortSignal,
  bin = "fingerprintx",
): Promise<ServiceInfo[]> {
  if (ports.length === 0) return [];
  const targets = ports.map((p) => `${ip}:${p}`).join(",");
  const r = await runTool({
    bin,
    args: [...fingerprintxArgs(2000), "-t", targets],
    timeoutMs: 10 * 60_000,
    signal,
    maxOutputBytes: 4 * 1024 * 1024,
  });
  return parseFingerprintx(r.stdout);
}
