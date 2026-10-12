import { describe, expect, it, vi } from "vitest";
import { createCveIntel } from "../src/intel.js";
import { fetchEpss, fetchKevSet, fetchNvdMetrics, type FetchFn } from "../src/sources.js";

const json = (body: unknown, ok = true, status = 200): Response =>
  ({ ok, status, json: async () => body }) as Response;

const NVD = (score: number | null) =>
  json({ vulnerabilities: [{ cve: { metrics: score === null ? {} : { cvssMetricV31: [{ cvssData: { baseScore: score, vectorString: "CVSS:3.1/AV:N", baseSeverity: "HIGH" } }] } } }] });
const EPSS = (rows: [string, number][]) => json({ status: "OK", data: rows.map(([cve, epss]) => ({ cve, epss: String(epss) })) });
const KEV = (ids: string[]) => json({ vulnerabilities: ids.map((cveID) => ({ cveID })) });

function router(handlers: { nvd?: (cve: string) => Response; epss?: Response; kev?: Response }): { fetch: FetchFn; calls: { nvd: string[]; epss: number; kev: number } } {
  const calls = { nvd: [] as string[], epss: 0, kev: 0 };
  const fetch = (async (url: string) => {
    if (url.includes("services.nvd.nist.gov")) {
      const cve = new URL(url).searchParams.get("cveId")!;
      calls.nvd.push(cve);
      return handlers.nvd ? handlers.nvd(cve) : NVD(null);
    }
    if (url.includes("first.org")) {
      calls.epss++;
      return handlers.epss ?? EPSS([]);
    }
    calls.kev++;
    return handlers.kev ?? KEV([]);
  }) as unknown as FetchFn;
  return { fetch, calls };
}

describe("source parsers", () => {
  it("picks CVSS v3.1 over v2", async () => {
    const fetch = (async () => NVD(7.5)) as unknown as FetchFn;
    expect(await fetchNvdMetrics("CVE-2016-2183", { fetch })).toMatchObject({ cvss: 7.5, cvssSeverity: "HIGH" });
  });
  it("ignores malformed CVE ids without calling out", async () => {
    const fetch = vi.fn();
    expect(await fetchNvdMetrics("not-a-cve", { fetch: fetch as unknown as FetchFn })).toEqual({ cvss: null, cvssVector: null, cvssSeverity: null });
    expect(fetch).not.toHaveBeenCalled();
  });
  it("EPSS parses and dedupes; KEV returns the id set", async () => {
    const e = router({ epss: EPSS([["CVE-2021-44228", 0.99]]) });
    expect([...(await fetchEpss(["CVE-2021-44228", "CVE-2021-44228", "bad"], { fetch: e.fetch }))]).toEqual([["CVE-2021-44228", 0.99]]);
    const k = router({ kev: KEV(["CVE-2021-44228"]) });
    expect((await fetchKevSet({ fetch: k.fetch })).has("CVE-2021-44228")).toBe(true);
  });
  it("throws on an empty KEV catalog (so we don't cache a bad empty set as real)", async () => {
    const fetch = (async () => KEV([])) as unknown as FetchFn;
    await expect(fetchKevSet({ fetch })).rejects.toThrow(/empty/);
  });
});

describe("createCveIntel", () => {
  const opts = { now: () => 0, nvdMinIntervalMs: 0 };

  it("combines NVD, EPSS and KEV per CVE", async () => {
    const r = router({
      nvd: (cve) => NVD(cve === "CVE-2021-44228" ? 10.0 : 7.5),
      epss: EPSS([["CVE-2021-44228", 0.99], ["CVE-2016-2183", 0.9]]),
      kev: KEV(["CVE-2021-44228"]),
    });
    const intel = createCveIntel({ ...opts, fetch: r.fetch });
    const out = await intel.lookup(["CVE-2021-44228", "CVE-2016-2183"]);
    expect(out.get("CVE-2021-44228")).toMatchObject({ cvss: 10.0, epss: 0.99, kev: true });
    expect(out.get("CVE-2016-2183")).toMatchObject({ cvss: 7.5, epss: 0.9, kev: false });
  });

  it("caches NVD and the KEV set across lookups", async () => {
    const r = router({ nvd: () => NVD(7.5), epss: EPSS([]), kev: KEV([]) });
    const intel = createCveIntel({ ...opts, fetch: r.fetch });
    await intel.lookup(["CVE-2016-2183"]);
    await intel.lookup(["CVE-2016-2183"]);
    expect(r.calls.nvd).toEqual(["CVE-2016-2183"]); // NVD hit once
    expect(r.calls.kev).toBe(1); // KEV fetched once (within TTL)
  });

  it("fails soft: a broken source leaves fields null, not an error", async () => {
    const r = router({
      nvd: () => json({}, false, 503),
      epss: json({}, false, 500),
      kev: json({}, false, 500),
    });
    const intel = createCveIntel({ ...opts, fetch: r.fetch });
    const out = await intel.lookup(["CVE-2016-2183"]);
    expect(out.get("CVE-2016-2183")).toEqual({ cve: "CVE-2016-2183", cvss: null, cvssVector: null, epss: null, kev: false });
  });
});
