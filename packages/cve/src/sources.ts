// Fetchers for the three CVE intel sources. All take an injected `fetch` so
// they can be tested offline, and all fail soft: enrichment is advisory, so a
// source being down leaves a finding un-enriched rather than failing a scan.

export type FetchFn = typeof fetch;

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

export interface CveMetrics {
  cvss: number | null;
  cvssVector: string | null;
  cvssSeverity: string | null;
}

/**
 * NVD CVSS lookup (one CVE per call; NVD has no useful multi-CVE query).
 * Prefers CVSS v3.1, then v3.0, then v2. Returns null fields when unknown.
 */
export async function fetchNvdMetrics(cveId: string, opts: { apiKey?: string; fetch: FetchFn; signal?: AbortSignal }): Promise<CveMetrics> {
  if (!CVE_RE.test(cveId)) return { cvss: null, cvssVector: null, cvssSeverity: null };
  const res = await opts.fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
    headers: opts.apiKey ? { apiKey: opts.apiKey } : {},
    signal: opts.signal,
  });
  if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
  const body = (await res.json()) as any;
  const cve = body?.vulnerabilities?.[0]?.cve;
  const m = cve?.metrics ?? {};
  const pick = (m.cvssMetricV31 ?? m.cvssMetricV30 ?? m.cvssMetricV2 ?? [])[0];
  const data = pick?.cvssData;
  return {
    cvss: typeof data?.baseScore === "number" ? data.baseScore : null,
    cvssVector: typeof data?.vectorString === "string" ? data.vectorString : null,
    cvssSeverity: typeof data?.baseSeverity === "string" ? data.baseSeverity : typeof pick?.baseSeverity === "string" ? pick.baseSeverity : null,
  };
}

/** EPSS probabilities for many CVEs in one call (FIRST.org, no key needed). */
export async function fetchEpss(cveIds: string[], opts: { fetch: FetchFn; signal?: AbortSignal }): Promise<Map<string, number>> {
  const ids = [...new Set(cveIds.filter((c) => CVE_RE.test(c)))];
  const out = new Map<string, number>();
  if (ids.length === 0) return out;
  // FIRST.org caps the query length; chunk to be safe.
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const res = await opts.fetch(`https://api.first.org/data/v1/epss?cve=${chunk.join(",")}`, { signal: opts.signal });
    if (!res.ok) throw new Error(`EPSS HTTP ${res.status}`);
    const body = (await res.json()) as any;
    for (const row of body?.data ?? []) {
      const score = Number(row?.epss);
      if (typeof row?.cve === "string" && Number.isFinite(score)) out.set(row.cve, score);
    }
  }
  return out;
}

/** Downloads the CISA KEV catalog and returns the set of CVE ids on it. */
export async function fetchKevSet(opts: { fetch: FetchFn; signal?: AbortSignal }): Promise<Set<string>> {
  const res = await opts.fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
    signal: opts.signal,
  });
  if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
  const body = (await res.json()) as any;
  const set = new Set<string>();
  for (const v of body?.vulnerabilities ?? []) if (typeof v?.cveID === "string") set.add(v.cveID);
  if (set.size === 0) throw new Error("KEV catalog was empty");
  return set;
}
