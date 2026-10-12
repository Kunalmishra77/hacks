// Combined risk scoring (PRD §8 Phase 3.5):
//   risk = CVSS × EPSS × asset-criticality, with KEV auto-escalating.
//
// A raw CVSS score says how bad a flaw *could* be; EPSS says how likely it is
// to actually be exploited; KEV says it already is being exploited in the wild;
// asset-criticality says how much this particular asset matters. Multiplying
// them turns a flat CVE list into a ranked worklist.

import type { Severity } from "@aegis/core";

export type Criticality = "LOW" | "MEDIUM" | "HIGH";

/** How much an asset's importance scales its findings' risk. */
const CRITICALITY_WEIGHT: Record<Criticality, number> = {
  LOW: 0.6,
  MEDIUM: 1.0,
  HIGH: 1.4,
};

export interface RiskInputs {
  /** CVSS base score 0–10, if known. */
  cvss: number | null;
  /** EPSS probability 0–1, if known. */
  epss: number | null;
  /** On the CISA Known-Exploited-Vulnerabilities list. */
  kev: boolean;
  criticality: Criticality;
  /** The engine's own severity, used as a fallback when there's no CVSS. */
  baseSeverity: Severity;
}

export interface RiskResult {
  /** 0–100, higher = handle sooner. */
  score: number;
  /** Severity after KEV escalation, for display and sorting. */
  severity: Severity;
  kev: boolean;
}

const SEVERITY_SCORE: Record<Severity, number> = { INFO: 0, LOW: 2.5, MEDIUM: 5, HIGH: 7.5, CRITICAL: 9.5 };
const ORDER: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function severityFromScore(score: number): Severity {
  if (score >= 80) return "CRITICAL";
  if (score >= 55) return "HIGH";
  if (score >= 25) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFO";
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b;
}

export function computeRisk(input: RiskInputs): RiskResult {
  // Fall back to the engine's severity when CVSS is missing, so header/cookie
  // findings (which have no CVE) still get a sensible score.
  const cvss = input.cvss ?? SEVERITY_SCORE[input.baseSeverity];
  // A small EPSS floor so a serious flaw with an unknown/near-zero probability
  // doesn't collapse to zero risk.
  const epss = Math.max(input.epss ?? 0.02, 0.02);
  const weight = CRITICALITY_WEIGHT[input.criticality];

  let score = Math.round((cvss / 10) * epss * weight * 100);
  let kevFlag = input.kev;
  if (input.kev) {
    // Known-exploited: never below 85, so it rises to the top regardless of EPSS.
    score = Math.max(score, 85);
  }
  score = Math.min(100, Math.max(0, score));

  // Severity is the worse of the engine's own call and the score-derived band,
  // so KEV / high EPSS can escalate but never quietly downgrade a finding.
  const severity = maxSeverity(input.baseSeverity, severityFromScore(score));
  return { score, severity, kev: kevFlag };
}
