import { runTool } from "@aegis/worker-kit";

// subfinder (ProjectDiscovery, MIT) queries passive sources (CT logs, DNS
// datasets, search engines). It does not contact the target. Installed in the
// worker image, not vendored.

export function subfinderArgs(apex: string): string[] {
  return ["-d", apex, "-silent", "-nc", "-max-time", "5", "-duc"];
}

export async function runSubfinder(apex: string, signal: AbortSignal, bin = "subfinder"): Promise<string[]> {
  const r = await runTool({ bin, args: subfinderArgs(apex), timeoutMs: 6 * 60_000, signal, maxOutputBytes: 10 * 1024 * 1024 });
  return r.stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}
