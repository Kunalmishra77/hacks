import { mkdtemp, readFile, rm } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import type { FindingDraft, Severity } from "@aegis/core";
import { runTool } from "@aegis/worker-kit";

// testssl.sh (GPLv2), invoked as a separate program, never vendored.
// Only checks that work by negotiating handshakes and reading the
// certificate. Checks that make a server leak memory (Heartbleed,
// Ticketbleed), or that need many crafted handshakes (ROBOT, CCS injection,
// client renegotiation), are not run.

export function testsslArgs(t: { host: string; port: number; ip: string; jsonFile: string }): string[] {
  const hostPart = isIP(t.host) === 6 ? `[${t.host}]` : t.host;
  return [
    "--quiet", "--color", "0", "--warnings", "off", "--nodns", "min",
    "--connect-timeout", "10", "--openssl-timeout", "10",
    "--jsonfile", t.jsonFile,
    "--protocols", "--std", "--server-defaults", "--server-preference", "--fs",
    "--poodle", "--sweet32", "--beast", "--lucky13", "--logjam", "--drown", "--freak", "--crime",
    ...(isIP(t.host) ? [] : ["--ip", t.ip]),
    `${hostPart}:${t.port}`,
  ];
}

const SEVERITY: Record<string, Severity> = { LOW: "LOW", MEDIUM: "MEDIUM", HIGH: "HIGH", CRITICAL: "CRITICAL" };

const GENERIC = "Review the TLS configuration. Mozilla's SSL Configuration Generator (\"intermediate\" profile) is a good baseline.";

/** Plain-language title and fix per testssl check id (or id prefix). */
const CATALOG: [RegExp, string, string][] = [
  [/^SSLv2$/, "SSLv2 is enabled", "Disable SSLv2. It is broken and no client needs it."],
  [/^SSLv3$/, "SSLv3 is enabled", "Disable SSLv3; allow only TLS 1.2 and TLS 1.3."],
  [/^TLS1(_1)?$/, "Outdated TLS version is enabled", "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and TLS 1.3."],
  [/^SWEET32$/, "64-bit block ciphers allowed (SWEET32)", "Disable 3DES and IDEA cipher suites."],
  [/^POODLE/, "Vulnerable to POODLE", "Disable SSLv3 (and CBC ciphers on SSLv3)."],
  [/^BEAST/, "CBC ciphers on TLS 1.0 (BEAST)", "Disable TLS 1.0, or prefer AEAD ciphers (AES-GCM, ChaCha20)."],
  [/^LUCKY13$/, "CBC ciphers in use (LUCKY13)", "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) and remove CBC suites where possible."],
  [/^LOGJAM/, "Weak Diffie-Hellman parameters (Logjam)", "Use ECDHE key exchange, or DH groups of 2048 bits or more."],
  [/^FREAK$/, "Export-grade RSA ciphers (FREAK)", "Disable EXPORT cipher suites."],
  [/^DROWN/, "SSLv2 exposure of this key (DROWN)", "Disable SSLv2 on every server that uses this certificate or key."],
  [/^CRIME/, "TLS compression enabled (CRIME)", "Disable TLS-level compression."],
  [/^cert_(expirationStatus|notAfter)/, "Certificate expired or about to expire", "Renew the certificate and automate renewal (e.g. with an ACME client)."],
  [/^cert_(chain_of_trust|trust)/, "Certificate isn't trusted by browsers", "Use a certificate from a public CA and serve the full intermediate chain."],
  [/^cert_(commonName|subjectAltName)/, "Certificate doesn't match the hostname", "Issue a certificate whose subjectAltName includes this hostname."],
  [/^cert_keySize/, "Certificate key is too small", "Use RSA keys of at least 2048 bits, or ECDSA P-256."],
  [/^cert_signatureAlgorithm/, "Weak certificate signature algorithm", "Reissue the certificate signed with SHA-256 or stronger."],
  [/^cipherlist_(NULL|aNULL)/, "Unauthenticated or unencrypted ciphers offered", "Disable NULL and anonymous (aNULL) cipher suites."],
  [/^cipherlist_EXPORT/, "Export ciphers offered", "Disable EXPORT cipher suites."],
  [/^cipherlist_(LOW|3DES|OBSOLETED)/, "Weak cipher suites offered", "Disable LOW-strength, 3DES and obsolete cipher suites."],
  [/^FS/, "Forward secrecy isn't enforced", "Prefer ECDHE key exchange so past traffic stays safe if the key leaks."],
  [/^cipher_order/, "Server doesn't enforce its cipher order", "Enable server cipher preference so strong suites are chosen."],
];

export function parseTestssl(json: string): FindingDraft[] {
  let rows: unknown;
  try {
    rows = JSON.parse(json);
  } catch {
    return [];
  }
  if (!Array.isArray(rows)) return [];
  const out: FindingDraft[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const r = row as Record<string, unknown>;
    if (typeof r.id !== "string") continue;
    const severity = SEVERITY[String(r.severity).toUpperCase()];
    if (!severity) continue; // OK, INFO, WARN, FATAL, DEBUG: not findings
    const [, baseId = r.id, suffix] = /^(\S+)(?:\s+<([^>]+)>)?$/.exec(r.id.trim()) ?? [];
    const id = baseId.replace(/[^\w.-]/g, "_").slice(0, 80);
    const entry = CATALOG.find(([re]) => re.test(id));
    const finding = typeof r.finding === "string" ? r.finding.slice(0, 300) : "";
    out.push({
      type: `tls.${id}`,
      key: suffix,
      severity,
      title: entry ? entry[1] : `${id}: ${finding}`.slice(0, 200),
      remediation: entry ? entry[2] : GENERIC,
      evidence: { check: r.id, result: finding },
      cveRefs: typeof r.cve === "string" ? r.cve.split(/\s+/).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)) : [],
    });
  }
  return out;
}

export async function runTestssl(
  t: { host: string; port: number; ip: string },
  signal: AbortSignal,
  bin = "/opt/testssl/testssl.sh",
): Promise<FindingDraft[]> {
  const dir = await mkdtemp(path.join(tmpdir(), "aegis-tls-"));
  const jsonFile = path.join(dir, "out.json");
  try {
    const r = await runTool({ bin, args: testsslArgs({ ...t, jsonFile }), timeoutMs: 15 * 60_000, signal, maxOutputBytes: 5 * 1024 * 1024 });
    const json = await readFile(jsonFile, "utf8").catch(() => "");
    if (!json.trim()) throw new Error(`testssl produced no results: ${r.stderr.slice(0, 300) || `exit ${r.exitCode}`}`);
    return parseTestssl(json);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
