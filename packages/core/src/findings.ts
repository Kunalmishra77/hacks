import { createHash } from "node:crypto";
import type { Engine } from "./types.js";

export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** What an engine reports. The worker turns it into a stored, deduplicated Finding. */
export interface FindingDraft {
  /** Asset the finding is about. Defaults to the scan's target asset. */
  assetId?: string;
  /** Stable machine id, e.g. "web.missing-hsts" or "tls.SWEET32". */
  type: string;
  /** Distinguishes several findings of one type on one asset (e.g. a cookie name). */
  key?: string;
  severity: Severity;
  title: string;
  remediation: string;
  /** Small structured facts. Never raw response bodies or secrets. */
  evidence?: Record<string, unknown>;
  cveRefs?: string[];
  cvss?: number;
}

export function findingFingerprint(engine: Engine, type: string, key = ""): string {
  return createHash("sha256").update(`${engine}\u0000${type}\u0000${key}`).digest("hex");
}

const SECRET_KEY = /pass(word)?|secret|token|authorization|cookie|api[-_]?key|private|credential|session|set-cookie|body|content|extracted/i;
const MAX_STRING = 500;
const MAX_ARRAY = 50;
const MAX_JSON_BYTES = 8 * 1024;

function clean(value: unknown, depth: number): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (depth > 4) return "[TRUNCATED]";
  if (Array.isArray(value)) return value.slice(0, MAX_ARRAY).map((v) => clean(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY.test(k) ? "[REDACTED]" : clean(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/**
 * Evidence is stored and shown to every Viewer, so it is redacted (secret-ish
 * keys, response bodies, extracted values), truncated, and size-capped here,
 * regardless of what an engine passes in.
 */
export function sanitizeEvidence(evidence: Record<string, unknown> | undefined): Record<string, unknown> | null {
  if (!evidence) return null;
  const cleaned = clean(evidence, 0) as Record<string, unknown>;
  const json = JSON.stringify(cleaned);
  if (Buffer.byteLength(json) <= MAX_JSON_BYTES) return cleaned;
  return { truncated: true, keys: Object.keys(cleaned).slice(0, 20) };
}
