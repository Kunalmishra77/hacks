import { runTool } from "@aegis/worker-kit";

// naabu (ProjectDiscovery, MIT): a port scanner. We run it in CONNECT mode
// (a normal TCP handshake, same as any client — no raw sockets, no SYN
// scanning), rate-limited, against the top 100 ports only. Host discovery is
// skipped (the gate already proved the host is in scope). No nmap, no cloud.

const MAX_RATE = 50;

export function naabuArgs(opts: { ip: string; ratePerSec: number }): string[] {
  const rate = Math.min(MAX_RATE, Math.max(1, Math.floor(opts.ratePerSec)));
  return [
    "-host", opts.ip,
    "-s", "c", // CONNECT scan
    "-tp", "100", // nmap top 100 ports
    "-rate", String(rate),
    "-c", "25",
    "-timeout", "1500",
    "-retries", "2",
    "-Pn", // skip host discovery
    "-no-stdin",
    "-duc", // no auto-update
    "-silent",
    "-json",
  ];
}

export function parseNaabu(stdout: string, ip: string): number[] {
  const ports: number[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as { ip?: unknown; port?: unknown };
      if (r.ip === ip && typeof r.port === "number" && r.port > 0 && r.port < 65536) ports.push(r.port);
    } catch {
      // ignore
    }
  }
  return ports;
}

export async function runNaabu(ip: string, ratePerSec: number, signal: AbortSignal, bin = "naabu"): Promise<number[]> {
  const r = await runTool({ bin, args: naabuArgs({ ip, ratePerSec }), timeoutMs: 15 * 60_000, signal, maxOutputBytes: 4 * 1024 * 1024 });
  return parseNaabu(r.stdout, ip);
}
