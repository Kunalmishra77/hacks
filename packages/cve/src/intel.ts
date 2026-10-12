import { fetchEpss, fetchKevSet, fetchNvdMetrics, type FetchFn } from "./sources.js";

// Caching intel service. NVD CVSS is effectively immutable per CVE, so it's
// cached indefinitely; EPSS changes daily; the KEV set is refreshed on a TTL.
// Everything fails soft: on a source error the affected fields come back null.

export interface CveIntelRecord {
  cve: string;
  cvss: number | null;
  cvssVector: string | null;
  epss: number | null;
  kev: boolean;
}

export interface CveIntelOptions {
  apiKey?: string;
  fetch?: FetchFn;
  now?: () => number;
  kevTtlMs?: number;
  /** Min gap between NVD calls (NVD asks ~0.6s with a key, more without). */
  nvdMinIntervalMs?: number;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

export interface CveIntel {
  /** Enriches a batch of CVE ids, using and filling the cache. */
  lookup(cveIds: string[], signal?: AbortSignal): Promise<Map<string, CveIntelRecord>>;
}

export function createCveIntel(opts: CveIntelOptions = {}): CveIntel {
  const doFetch = opts.fetch ?? fetch;
  const now = opts.now ?? Date.now;
  const kevTtl = opts.kevTtlMs ?? 6 * 3600_000;
  const nvdGap = opts.nvdMinIntervalMs ?? (opts.apiKey ? 700 : 6500);
  const log = opts.log ?? (() => {});

  const nvdCache = new Map<string, { cvss: number | null; cvssVector: string | null }>();
  let kev: { set: Set<string>; at: number } | null = null;
  let nvdChain: Promise<unknown> = Promise.resolve();
  let lastNvd = 0;

  async function kevSet(signal?: AbortSignal): Promise<Set<string>> {
    if (kev && now() - kev.at < kevTtl) return kev.set;
    try {
      const set = await fetchKevSet({ fetch: doFetch, signal });
      kev = { set, at: now() };
    } catch (e) {
      log("KEV refresh failed; using stale/empty set", { error: (e as Error).message });
      kev ??= { set: new Set(), at: now() };
    }
    return kev.set;
  }

  /** Serializes and paces NVD calls so we stay under its rate limit. */
  function nvd(cve: string, signal?: AbortSignal): Promise<{ cvss: number | null; cvssVector: string | null }> {
    const cached = nvdCache.get(cve);
    if (cached) return Promise.resolve(cached);
    const run = nvdChain.then(async () => {
      if (nvdCache.has(cve)) return nvdCache.get(cve)!;
      const wait = lastNvd + nvdGap - now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      lastNvd = now();
      try {
        const m = await fetchNvdMetrics(cve, { apiKey: opts.apiKey, fetch: doFetch, signal });
        const rec = { cvss: m.cvss, cvssVector: m.cvssVector };
        nvdCache.set(cve, rec);
        return rec;
      } catch (e) {
        log("NVD lookup failed", { cve, error: (e as Error).message });
        return { cvss: null, cvssVector: null };
      }
    });
    nvdChain = run.catch(() => {});
    return run;
  }

  return {
    async lookup(cveIds, signal) {
      const ids = [...new Set(cveIds.filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)))];
      const out = new Map<string, CveIntelRecord>();
      if (ids.length === 0) return out;

      const [kevIds, epss] = await Promise.all([
        kevSet(signal),
        fetchEpss(ids, { fetch: doFetch, signal }).catch((e) => {
          log("EPSS lookup failed", { error: (e as Error).message });
          return new Map<string, number>();
        }),
      ]);
      const metrics = await Promise.all(ids.map((cve) => nvd(cve, signal)));

      ids.forEach((cve, i) => {
        out.set(cve, {
          cve,
          cvss: metrics[i]!.cvss,
          cvssVector: metrics[i]!.cvssVector,
          epss: epss.get(cve) ?? null,
          kev: kevIds.has(cve),
        });
      });
      return out;
    },
  };
}
