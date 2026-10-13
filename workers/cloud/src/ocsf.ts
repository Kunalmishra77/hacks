import type { Severity } from "@aegis/core";

/**
 * A prowler check that FAILed, reduced to the fields Aegis records. Prowler
 * emits OCSF Detection Findings (one JSON object per check result); we keep
 * only failures and translate them into findings on the cloud-account asset.
 */
export interface CloudFinding {
  /** prowler check id, e.g. "s3_bucket_public_access" (metadata.event_code). */
  checkId: string;
  title: string;
  severity: Severity;
  /** The failing resource's ARN or, when prowler has none, its name/id. */
  resourceUid: string;
  resourceName: string;
  resourceType: string;
  region: string;
  remediation: string;
  accountUid: string;
}

// OCSF severity_id is the stable field, but prowler also writes a human
// `severity` string. We read the string (lower-cased) and fall back to INFO.
const SEVERITY: Record<string, Severity> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  informational: "INFO",
  info: "INFO",
};

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function firstResource(row: Record<string, unknown>): Record<string, unknown> {
  const resources = row.resources;
  if (Array.isArray(resources) && resources.length > 0 && typeof resources[0] === "object" && resources[0]) {
    return resources[0] as Record<string, unknown>;
  }
  return {};
}

/**
 * Parses a prowler OCSF JSON array (the `--output-formats json-ocsf` file) and
 * returns only the FAILed checks. Pure and defensive: the input is attacker-
 * influenced scan output, so every field is treated as untrusted and optional.
 */
export function parseProwlerOcsf(input: unknown): CloudFinding[] {
  const rows: unknown[] = Array.isArray(input) ? input : [];
  const out: CloudFinding[] = [];
  for (const raw of rows) {
    if (typeof raw !== "object" || raw === null) continue;
    const row = raw as Record<string, unknown>;
    // status_code is "PASS" | "FAIL" | "MANUAL" | ...; keep only real failures.
    if (str(row.status_code).toUpperCase() !== "FAIL") continue;

    const resource = firstResource(row);
    const findingInfo = (row.finding_info ?? {}) as Record<string, unknown>;
    const metadata = (row.metadata ?? {}) as Record<string, unknown>;
    const remediation = (row.remediation ?? {}) as Record<string, unknown>;
    const cloud = (row.cloud ?? {}) as Record<string, unknown>;
    const account = (cloud.account ?? {}) as Record<string, unknown>;

    const checkId = str(metadata.event_code) || str(findingInfo.uid) || "unknown";
    const resourceUid = str(resource.uid) || str(resource.name) || str(findingInfo.uid);
    if (!resourceUid) continue; // can't key or evidence a finding without a resource

    out.push({
      checkId,
      title: str(findingInfo.title) || checkId,
      severity: SEVERITY[str(row.severity).toLowerCase()] ?? "INFO",
      resourceUid,
      resourceName: str(resource.name),
      resourceType: str(resource.type),
      region: str(resource.region) || str(cloud.region),
      remediation: str(remediation.desc),
      accountUid: str(account.uid),
    });
  }
  return out;
}
