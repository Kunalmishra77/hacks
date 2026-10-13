import { describe, expect, it } from "vitest";
import { buildAlert, selectAlertable, type AlertFinding } from "../src/index.js";

const F = (over: Partial<AlertFinding>): AlertFinding => ({
  title: "Finding",
  severity: "HIGH",
  riskScore: 50,
  kevListed: false,
  assetAddress: "x.example.com",
  ...over,
});

describe("selectAlertable", () => {
  it("keeps findings at or above the channel's minimum severity", () => {
    const findings = [F({ severity: "LOW" }), F({ severity: "HIGH" }), F({ severity: "CRITICAL" })];
    expect(selectAlertable(findings, { minSeverity: "HIGH", kevAlways: true }).length).toBe(2);
    expect(selectAlertable(findings, { minSeverity: "CRITICAL", kevAlways: true }).length).toBe(1);
  });

  it("always includes KEV findings when kevAlways is set, even below the threshold", () => {
    const findings = [F({ severity: "LOW", kevListed: true }), F({ severity: "MEDIUM" })];
    expect(selectAlertable(findings, { minSeverity: "HIGH", kevAlways: true }).map((f) => f.severity)).toEqual(["LOW"]);
    expect(selectAlertable(findings, { minSeverity: "HIGH", kevAlways: false })).toEqual([]);
  });

  it("sorts selected findings by risk, worst first", () => {
    const sel = selectAlertable([F({ riskScore: 30 }), F({ riskScore: 90 }), F({ riskScore: 60 })], { minSeverity: "LOW", kevAlways: true });
    expect(sel.map((f) => f.riskScore)).toEqual([90, 60, 30]);
  });
});

describe("buildAlert", () => {
  const findings = [
    F({ title: "OpenSSH known-exploited", severity: "CRITICAL", riskScore: 88, kevListed: true, assetAddress: "api.example.com:22" }),
    F({ title: "Git exposed", severity: "HIGH", riskScore: 58, assetAddress: "staging.example.com:80" }),
  ];

  it("produces a plain-text summary naming the org and the worst findings", () => {
    const a = buildAlert({ orgName: "Acme", scopeLabel: "example.com", findings, dashboardUrl: "https://app/dashboard" });
    expect(a.subject).toContain("Acme");
    expect(a.subject).toMatch(/2 new/);
    expect(a.text).toContain("OpenSSH known-exploited");
    expect(a.text).toContain("api.example.com:22");
    expect(a.text).toMatch(/known.exploited|KEV/i);
    expect(a.text).toContain("https://app/dashboard");
  });

  it("caps the listed findings and notes the remainder", () => {
    const many = Array.from({ length: 12 }, (_, i) => F({ title: `Finding ${i}`, riskScore: 100 - i }));
    const a = buildAlert({ orgName: "Acme", scopeLabel: "All", findings: many });
    expect((a.text.match(/Finding \d+/g) ?? []).length).toBeLessThanOrEqual(10);
    expect(a.text).toMatch(/\+2 more|2 more/);
  });

  it("builds Slack blocks and a webhook JSON payload too", () => {
    const a = buildAlert({ orgName: "Acme", scopeLabel: "example.com", findings });
    expect(a.slack.text).toContain("Acme");
    expect(a.webhook).toMatchObject({ org: "Acme", scope: "example.com", newFindings: 2 });
    expect(a.webhook.findings[0]).toMatchObject({ title: "OpenSSH known-exploited", kev: true });
  });
});
