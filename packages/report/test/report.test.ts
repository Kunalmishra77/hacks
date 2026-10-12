import { describe, expect, it } from "vitest";
import { buildReport, renderReportHtml, type ReportInput } from "../src/index.js";

const base: ReportInput = {
  org: { name: "Northwind Studio" },
  scope: null,
  generatedAt: new Date("2026-10-12T09:30:00Z"),
  generatedBy: "analyst@northwind.example",
  assets: { total: 9, byKind: { DOMAIN: 1, SUBDOMAIN: 4, SERVICE: 4 } },
  findings: [
    { type: "net.exposed-service", severity: "CRITICAL", riskScore: 88, kevListed: true, epss: 0.95, cvss: 7.5, cveRefs: ["CVE-2016-2183"], title: "OpenSSH 7.2 affected by a known-exploited vuln", assetAddress: "api.northwind.example:22", assetKind: "SERVICE", remediation: "Upgrade OpenSSH.", evidence: { port: 22, password: "secret" }, status: "OPEN", firstSeenAt: new Date("2026-10-10T00:00:00Z"), lastSeenAt: new Date("2026-10-12T00:00:00Z") },
    { type: "web.exposed-git", severity: "HIGH", riskScore: 58, kevListed: false, epss: 0.12, cvss: null, cveRefs: [], title: "Git repository is publicly downloadable", assetAddress: "staging.northwind.example:80", assetKind: "SERVICE", remediation: "Block /.git.", evidence: { url: "http://staging/.git/HEAD" }, status: "OPEN", firstSeenAt: new Date(), lastSeenAt: new Date() },
    { type: "web.missing-hsts", severity: "LOW", riskScore: 4, kevListed: false, epss: null, cvss: null, cveRefs: [], title: "No HSTS", assetAddress: "www.northwind.example:443", assetKind: "SERVICE", remediation: "Add HSTS.", evidence: null, status: "TRIAGED", firstSeenAt: new Date(), lastSeenAt: new Date() },
    { type: "web.no-security-txt", severity: "INFO", riskScore: 1, kevListed: false, epss: null, cvss: null, cveRefs: [], title: "No security.txt", assetAddress: "www.northwind.example:443", assetKind: "SERVICE", remediation: "Add one.", evidence: null, status: "FIXED", firstSeenAt: new Date(), lastSeenAt: new Date() },
  ],
};

describe("buildReport", () => {
  it("summarizes open/triaged findings by severity and counts KEV", () => {
    const m = buildReport(base);
    expect(m.title).toContain("Northwind Studio");
    expect(m.scopeLabel).toBe("All boundaries");
    expect(m.summary.bySeverity).toEqual({ CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 1, INFO: 0 });
    expect(m.summary.total).toBe(3); // the FIXED one is excluded
    expect(m.summary.kev).toBe(1);
    expect(m.summary.topRisk).toBe(88);
  });

  it("includes only actionable findings, risk-ranked, with resolved excluded", () => {
    const m = buildReport(base);
    expect(m.findings.map((f) => f.title)).toEqual([
      "OpenSSH 7.2 affected by a known-exploited vuln",
      "Git repository is publicly downloadable",
      "No HSTS",
    ]);
    expect(m.findings[0]!.riskScore).toBe(88);
  });

  it("labels a scoped report by the boundary value", () => {
    const m = buildReport({ ...base, scope: { value: "northwind.example", type: "DOMAIN" } });
    expect(m.scopeLabel).toBe("northwind.example");
  });

  it("reports a clean bill of health when nothing is open", () => {
    const m = buildReport({ ...base, findings: base.findings.filter((f) => f.status === "FIXED") });
    expect(m.summary.total).toBe(0);
    expect(m.findings).toEqual([]);
  });
});

describe("renderReportHtml", () => {
  const html = renderReportHtml(buildReport(base));

  it("is a self-contained HTML document with no external resources", () => {
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).not.toMatch(/<(script|link|img|iframe)\b/i);
    // Nothing is fetched: no external src/href/url() references.
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']https?:/i);
    expect(html).not.toMatch(/url\(\s*["']?https?:/i);
    expect(html).toContain("@media print");
  });

  it("escapes finding content so evidence can't inject markup", () => {
    const m = buildReport({
      ...base,
      findings: [{ ...base.findings[1]!, title: "<script>alert(1)</script>", assetAddress: "a<b>.example" }],
    });
    const out = renderReportHtml(m);
    expect(out).not.toContain("<script>alert(1)</script>");
    expect(out).toContain("&lt;script&gt;");
  });

  it("never leaks redacted/secret evidence values that the model carries", () => {
    // Evidence should already be redacted upstream, but the renderer must not
    // surface a raw 'password' field even if present.
    expect(html).not.toContain("secret");
  });

  it("shows the risk score, KEV flag and remediation", () => {
    expect(html).toContain("88");
    expect(html).toMatch(/known.exploited|KEV|Exploited/i);
    expect(html).toContain("Upgrade OpenSSH.");
    expect(html).toContain("Northwind Studio");
  });
});
