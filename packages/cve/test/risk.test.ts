import { describe, expect, it } from "vitest";
import { computeRisk, maxSeverity } from "../src/risk.js";

describe("computeRisk", () => {
  it("multiplies CVSS, EPSS and asset-criticality", () => {
    // 9.0 CVSS, 50% EPSS, MEDIUM asset → 0.9 * 0.5 * 1.0 * 100 = 45.
    const r = computeRisk({ cvss: 9.0, epss: 0.5, kev: false, criticality: "MEDIUM", baseSeverity: "HIGH" });
    expect(r.score).toBe(45);
    // HIGH-criticality asset raises it; LOW lowers it.
    expect(computeRisk({ cvss: 9.0, epss: 0.5, kev: false, criticality: "HIGH", baseSeverity: "HIGH" }).score).toBe(63);
    expect(computeRisk({ cvss: 9.0, epss: 0.5, kev: false, criticality: "LOW", baseSeverity: "HIGH" }).score).toBe(27);
  });

  it("auto-escalates KEV entries to the top and at least HIGH", () => {
    const r = computeRisk({ cvss: 4.0, epss: 0.01, kev: true, criticality: "LOW", baseSeverity: "MEDIUM" });
    expect(r.score).toBeGreaterThanOrEqual(85);
    expect(r.severity).toBe("CRITICAL");
    expect(r.kev).toBe(true);
  });

  it("never downgrades below the engine's own severity", () => {
    const r = computeRisk({ cvss: 2.0, epss: 0.001, kev: false, criticality: "LOW", baseSeverity: "HIGH" });
    expect(r.severity).toBe("HIGH");
  });

  it("falls back to engine severity when there's no CVSS, with an EPSS floor", () => {
    const r = computeRisk({ cvss: null, epss: null, kev: false, criticality: "MEDIUM", baseSeverity: "LOW" });
    // 2.5/10 * 0.02 (floor) * 1.0 * 100 = 0.5 → 1. Low score, but still LOW severity.
    expect(r.score).toBe(1);
    expect(r.severity).toBe("LOW");
    // A HIGH-severity no-CVE finding (e.g. exposed .git) still scores meaningfully.
    expect(computeRisk({ cvss: null, epss: null, kev: false, criticality: "MEDIUM", baseSeverity: "HIGH" }).severity).toBe("HIGH");
  });

  it("clamps to 0–100", () => {
    expect(computeRisk({ cvss: 10, epss: 1, kev: true, criticality: "HIGH", baseSeverity: "CRITICAL" }).score).toBe(100);
    expect(computeRisk({ cvss: 0, epss: 0, kev: false, criticality: "LOW", baseSeverity: "INFO" }).score).toBeGreaterThanOrEqual(0);
  });

  it("maxSeverity picks the worse of two", () => {
    expect(maxSeverity("LOW", "CRITICAL")).toBe("CRITICAL");
    expect(maxSeverity("HIGH", "MEDIUM")).toBe("HIGH");
  });
});
