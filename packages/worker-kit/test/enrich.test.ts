import { describe, expect, it } from "vitest";
import { enrichScanFindings } from "../src/enrich.js";
import type { EnrichableFinding, FindingEnrichment } from "../src/store.js";

function fakeStore(findings: EnrichableFinding[]) {
  const applied = new Map<string, FindingEnrichment>();
  return {
    applied,
    store: {
      findingsForScan: async () => findings,
      applyEnrichment: async (id: string, e: FindingEnrichment) => {
        applied.set(id, e);
      },
    },
  };
}

const intel = (data: Record<string, { cvss: number | null; epss: number | null; kev: boolean }>) => ({
  lookup: async (ids: string[]) => new Map(ids.filter((i) => data[i]).map((i) => [i, { cve: i, cvssVector: null, ...data[i]! }])),
});

const NOW = new Date("2026-10-12T00:00:00Z");

describe("enrichScanFindings", () => {
  it("scores CVE findings with CVSS x EPSS x criticality and flags KEV", async () => {
    const s = fakeStore([
      { id: "f1", cveRefs: ["CVE-2021-44228"], severity: "HIGH", criticality: "MEDIUM" },
      { id: "f2", cveRefs: ["CVE-2016-2183"], severity: "LOW", criticality: "LOW" },
    ]);
    const out = await enrichScanFindings("scan-1", {
      store: s.store,
      now: () => NOW,
      intel: intel({ "CVE-2021-44228": { cvss: 10, epss: 0.99, kev: true }, "CVE-2016-2183": { cvss: 7.5, epss: 0.9, kev: false } }),
    });
    expect(out).toEqual({ findings: 2, withCve: 2, kev: 1 });
    expect(s.applied.get("f1")).toMatchObject({ kevListed: true, severity: "CRITICAL", enrichedAt: NOW });
    expect(s.applied.get("f1")!.riskScore).toBeGreaterThanOrEqual(85);
    expect(s.applied.get("f2")).toMatchObject({ kevListed: false, epss: 0.9 });
  });

  it("still scores findings that have no CVE, using engine severity", async () => {
    const s = fakeStore([{ id: "f1", cveRefs: [], severity: "HIGH", criticality: "MEDIUM" }]);
    const out = await enrichScanFindings("scan-1", { store: s.store, now: () => NOW, intel: intel({}) });
    expect(out).toEqual({ findings: 1, withCve: 0, kev: 0 });
    expect(s.applied.get("f1")).toMatchObject({ epss: null, kevListed: false, severity: "HIGH" });
    expect(s.applied.get("f1")!.riskScore).toBeGreaterThan(0);
  });

  it("takes the worst CVE when a finding lists several", async () => {
    const s = fakeStore([{ id: "f1", cveRefs: ["CVE-2016-2183", "CVE-2021-44228"], severity: "MEDIUM", criticality: "MEDIUM" }]);
    await enrichScanFindings("scan-1", {
      store: s.store,
      now: () => NOW,
      intel: intel({ "CVE-2016-2183": { cvss: 7.5, epss: 0.1, kev: false }, "CVE-2021-44228": { cvss: 10, epss: 0.99, kev: true } }),
    });
    expect(s.applied.get("f1")).toMatchObject({ epss: 0.99, kevListed: true });
  });

  it("does nothing when a scan produced no findings", async () => {
    const s = fakeStore([]);
    expect(await enrichScanFindings("scan-1", { store: s.store, intel: intel({}) })).toEqual({ findings: 0, withCve: 0, kev: 0 });
  });

  it("still scores by severity when the intel service throws", async () => {
    const s = fakeStore([{ id: "f1", cveRefs: ["CVE-2021-44228"], severity: "HIGH", criticality: "MEDIUM" }]);
    const out = await enrichScanFindings("scan-1", {
      store: s.store,
      now: () => NOW,
      intel: { lookup: async () => { throw new Error("NVD down"); } },
    });
    expect(out.findings).toBe(1);
    expect(s.applied.get("f1")).toMatchObject({ epss: null, kevListed: false, severity: "HIGH" });
  });
});
