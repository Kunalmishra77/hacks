// Hits the real NVD, EPSS and CISA KEV endpoints. Skipped unless
// CVE_LIVE=1 (CI sets NVD_API_KEY and runs it). Uses well-known CVEs.
import { describe, expect, it } from "vitest";
import { computeRisk, createCveIntel } from "../src/index.js";

describe.skipIf(process.env.CVE_LIVE !== "1")("cve intel (live)", { timeout: 60_000 }, () => {
  it("enriches Log4Shell with real CVSS, EPSS and KEV data", async () => {
    const intel = createCveIntel({ apiKey: process.env.NVD_API_KEY });
    const out = await intel.lookup(["CVE-2021-44228", "CVE-2016-2183"]);
    const log4shell = out.get("CVE-2021-44228")!;
    expect(log4shell.cvss).toBeGreaterThanOrEqual(9); // critical
    expect(log4shell.epss).toBeGreaterThan(0.5); // heavily exploited
    expect(log4shell.kev).toBe(true); // on the KEV list

    const risk = computeRisk({ ...log4shell, criticality: "MEDIUM", baseSeverity: "HIGH" });
    expect(risk.score).toBeGreaterThanOrEqual(85);
    expect(risk.severity).toBe("CRITICAL");
  });
});
