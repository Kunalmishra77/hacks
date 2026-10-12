import { computeRisk, type CveIntel } from "@aegis/cve";
import type { EnrichableFinding, FindingEnrichment, WorkerStore } from "./store.js";

// Enrichment pass for one scan's findings (PRD §8 Phase 3.5). Advisory and
// idempotent: it reads the findings a scan just wrote, pulls CVSS/EPSS/KEV for
// their CVEs, computes a combined risk score (including no-CVE findings, via
// the engine severity), and writes it back. It never changes a finding's
// triage status and never fails the scan.

export interface EnrichDeps {
  store: Pick<WorkerStore, "findingsForScan" | "applyEnrichment">;
  intel: CveIntel;
  now?: () => Date;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

export interface EnrichOutcome {
  findings: number;
  withCve: number;
  kev: number;
}

export async function enrichScanFindings(scanId: string, deps: EnrichDeps, signal?: AbortSignal): Promise<EnrichOutcome> {
  const now = deps.now ?? (() => new Date());
  const log = deps.log ?? (() => {});
  const findings = await deps.store.findingsForScan(scanId);
  if (findings.length === 0) return { findings: 0, withCve: 0, kev: 0 };

  const allCves = [...new Set(findings.flatMap((f) => f.cveRefs))];
  const intel = allCves.length > 0 ? await deps.intel.lookup(allCves, signal).catch((e) => {
    log("intel lookup failed; scoring without CVE data", { error: (e as Error).message });
    return new Map();
  }) : new Map();

  let withCve = 0;
  let kevCount = 0;
  for (const f of findings) {
    const enr = enrichOne(f, intel);
    if (f.cveRefs.length > 0) withCve++;
    if (enr.kevListed) kevCount++;
    await deps.store.applyEnrichment(f.id, { ...enr, enrichedAt: now() });
  }
  return { findings: findings.length, withCve, kev: kevCount };
}

/** Picks the worst CVE across a finding's refs and folds it into a risk score. */
export function enrichOne(
  f: EnrichableFinding,
  intel: Map<string, { cvss: number | null; epss: number | null; kev: boolean }>,
): Omit<FindingEnrichment, "enrichedAt"> {
  let cvss: number | null = null;
  let epss: number | null = null;
  let kev = false;
  for (const cve of f.cveRefs) {
    const rec = intel.get(cve);
    if (!rec) continue;
    if (rec.cvss !== null) cvss = Math.max(cvss ?? 0, rec.cvss);
    if (rec.epss !== null) epss = Math.max(epss ?? 0, rec.epss);
    if (rec.kev) kev = true;
  }
  const risk = computeRisk({ cvss, epss, kev, criticality: f.criticality, baseSeverity: f.severity });
  return { epss, kevListed: kev, riskScore: risk.score, severity: risk.severity };
}
