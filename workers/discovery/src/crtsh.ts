import { isWithinDomain, normalizeDomain } from "@aegis/core";

// Certificate Transparency via crt.sh: a public log of issued certificates.
// Purely passive: the query goes to crt.sh, never to the customer's hosts.

const MAX_BYTES = 25 * 1024 * 1024;

/** Extracts unique hostnames at or under `apex` from crt.sh JSON output. */
export function parseCrtSh(json: string, apex: string): string[] {
  let rows: unknown;
  try {
    rows = JSON.parse(json);
  } catch {
    return [];
  }
  if (!Array.isArray(rows)) return [];
  const out = new Set<string>();
  for (const row of rows) {
    const value = (row as { name_value?: unknown })?.name_value;
    if (typeof value !== "string") continue;
    // One certificate can list several names, newline-separated. A line with
    // spaces is malformed and is rejected whole, not split into fragments.
    for (const raw of value.split(/\r?\n/)) {
      const name = normalizeDomain(raw.trim().replace(/^\*\./, ""));
      if (name && isWithinDomain(name, apex)) out.add(name);
    }
  }
  return [...out];
}

export async function fetchCrtSh(apex: string, signal: AbortSignal): Promise<string[]> {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${apex}`)}&output=json`;
  const res = await fetch(url, {
    signal: AbortSignal.any([signal, AbortSignal.timeout(90_000)]),
    headers: { "user-agent": "AegisASM/1.0 (passive CT lookup)", accept: "application/json" },
    redirect: "error",
  });
  if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
  const len = Number(res.headers.get("content-length") ?? 0);
  if (len > MAX_BYTES) throw new Error("crt.sh response too large");
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error("crt.sh response too large");
  return parseCrtSh(text, apex);
}
