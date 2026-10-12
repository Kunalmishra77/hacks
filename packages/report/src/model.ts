import type { Severity } from "@aegis/core";

// Point-in-time report model. Pure: the API fills ReportInput from the DB,
// buildReport shapes it, renderReportHtml turns it into a document. Reports
// snapshot the actionable (OPEN/TRIAGED) findings, ranked by risk.

export type FindingStatus = "OPEN" | "TRIAGED" | "FIXED" | "FALSE_POSITIVE";

export interface ReportFinding {
  type: string;
  severity: Severity;
  riskScore: number | null;
  kevListed: boolean;
  epss: number | null;
  cvss: number | null;
  cveRefs: string[];
  title: string;
  assetAddress: string;
  assetKind: string;
  remediation: string | null;
  evidence: Record<string, unknown> | null;
  status: FindingStatus;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

export interface ReportInput {
  org: { name: string };
  /** null = a whole-organization report. */
  scope?: { value: string; type: string } | null;
  generatedAt: Date;
  generatedBy: string;
  assets: { total: number; byKind: Record<string, number> };
  findings: ReportFinding[];
}

export interface ReportSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  kev: number;
  topRisk: number;
}

export interface ReportModel {
  title: string;
  org: string;
  scopeLabel: string;
  generatedAt: Date;
  generatedBy: string;
  assets: { total: number; byKind: Record<string, number> };
  summary: ReportSummary;
  findings: ReportFinding[];
}

const SEVERITY_RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const ACTIONABLE: ReadonlySet<FindingStatus> = new Set(["OPEN", "TRIAGED"]);

export function buildReport(input: ReportInput): ReportModel {
  const findings = input.findings
    .filter((f) => ACTIONABLE.has(f.status))
    .sort(
      (a, b) =>
        (b.riskScore ?? -1) - (a.riskScore ?? -1) ||
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.lastSeenAt.getTime() - a.lastSeenAt.getTime(),
    );

  const bySeverity: Record<Severity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  let kev = 0;
  let topRisk = 0;
  for (const f of findings) {
    bySeverity[f.severity]++;
    if (f.kevListed) kev++;
    topRisk = Math.max(topRisk, f.riskScore ?? 0);
  }

  const scopeLabel = input.scope ? input.scope.value : "All boundaries";
  return {
    title: `${input.org.name} — security assessment (${scopeLabel})`,
    org: input.org.name,
    scopeLabel,
    generatedAt: input.generatedAt,
    generatedBy: input.generatedBy,
    assets: input.assets,
    summary: { total: findings.length, bySeverity, kev, topRisk },
    findings,
  };
}
