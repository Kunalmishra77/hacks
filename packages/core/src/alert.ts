import type { Severity } from "./findings.js";

// Builds new-exposure alert content (Phase 6). Pure: the API decides which
// findings are "new", this turns them into the text / Slack / webhook payloads
// the senders deliver. No secrets or evidence here — just titles and severity.

export interface AlertFinding {
  title: string;
  severity: Severity;
  riskScore: number | null;
  kevListed: boolean;
  assetAddress: string;
}

export interface AlertPolicy {
  minSeverity: Severity;
  kevAlways: boolean;
}

const RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const MAX_LISTED = 10;

/** Findings that clear a channel's threshold (or are KEV), worst-risk first. */
export function selectAlertable(findings: AlertFinding[], policy: AlertPolicy): AlertFinding[] {
  return findings
    .filter((f) => RANK[f.severity]! >= RANK[policy.minSeverity]! || (policy.kevAlways && f.kevListed))
    .sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || RANK[b.severity]! - RANK[a.severity]!);
}

export interface AlertInput {
  orgName: string;
  scopeLabel: string;
  findings: AlertFinding[];
  dashboardUrl?: string;
}

export interface Alert {
  subject: string;
  text: string;
  slack: { text: string };
  webhook: {
    org: string;
    scope: string;
    newFindings: number;
    findings: { title: string; severity: Severity; riskScore: number | null; kev: boolean; asset: string }[];
  };
}

function line(f: AlertFinding): string {
  const risk = f.riskScore !== null ? ` (risk ${f.riskScore})` : "";
  const kev = f.kevListed ? " [known-exploited]" : "";
  return `• ${f.severity}${risk}${kev}: ${f.title} — ${f.assetAddress}`;
}

export function buildAlert(input: AlertInput): Alert {
  const n = input.findings.length;
  const shown = input.findings.slice(0, MAX_LISTED);
  const remainder = n - shown.length;
  const subject = `Aegis: ${n} new ${n === 1 ? "finding" : "findings"} for ${input.orgName} (${input.scopeLabel})`;

  const bodyLines = [
    `${n} new ${n === 1 ? "finding" : "findings"} in ${input.scopeLabel}:`,
    "",
    ...shown.map(line),
    ...(remainder > 0 ? ["", `…and ${remainder} more.`] : []),
    ...(input.dashboardUrl ? ["", `Review: ${input.dashboardUrl}`] : []),
  ];
  const text = bodyLines.join("\n");

  return {
    subject,
    text,
    slack: { text: `*${subject}*\n${shown.map(line).join("\n")}${remainder > 0 ? `\n…and ${remainder} more.` : ""}` },
    webhook: {
      org: input.orgName,
      scope: input.scopeLabel,
      newFindings: n,
      findings: shown.map((f) => ({ title: f.title, severity: f.severity, riskScore: f.riskScore, kev: f.kevListed, asset: f.assetAddress })),
    },
  };
}
