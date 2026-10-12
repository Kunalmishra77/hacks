import type { Severity } from "@aegis/core";
import type { ReportFinding, ReportModel } from "./model.js";

// Self-contained HTML report: inline CSS, system fonts, no scripts, no external
// resources. Prints cleanly (browser "Save as PDF" gives the PDF export). All
// dynamic text is escaped, and evidence is filtered again here so a secret can
// never reach the page even if upstream redaction missed it.

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_LABEL: Record<Severity, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info" };
const KIND_LABEL: Record<string, string> = { DOMAIN: "Domains", SUBDOMAIN: "Subdomains", IP: "IPs", SERVICE: "Web services", CLOUD_RESOURCE: "Cloud resources" };
const SECRET_KEY = /pass(word)?|secret|token|authorization|cookie|api[-_]?key|private|credential|session|body/i;

function esc(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const fmtDate = (d: Date) => d.toISOString().slice(0, 10);
const fmtDateTime = (d: Date) => `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;

function evidenceRows(evidence: Record<string, unknown> | null): string {
  if (!evidence) return "";
  const rows = Object.entries(evidence)
    .filter(([k, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => {
      const value = SECRET_KEY.test(k) ? "[redacted]" : typeof v === "object" ? JSON.stringify(v) : String(v);
      return `<tr><td class="ek">${esc(k)}</td><td class="ev">${esc(value)}</td></tr>`;
    });
  return rows.length ? `<table class="evi">${rows.join("")}</table>` : "";
}

function findingBlock(f: ReportFinding): string {
  const sev = f.severity.toLowerCase();
  const intel: string[] = [];
  if (f.cveRefs.length) intel.push(esc(f.cveRefs.join(", ")));
  if (f.cvss !== null) intel.push(`CVSS ${esc(f.cvss)}`);
  if (f.epss !== null) intel.push(`${Math.round(f.epss * 100)}% exploit probability (EPSS)`);
  if (f.kevListed) intel.push(`<strong class="kev">on CISA's Known Exploited list</strong>`);
  return `
    <article class="finding sev-${sev}">
      <div class="fhead">
        <span class="chip chip-${sev}">${SEV_LABEL[f.severity]}</span>
        ${f.riskScore !== null ? `<span class="risk">risk ${f.riskScore}</span>` : ""}
        <h3>${esc(f.title)}</h3>
      </div>
      <div class="fmeta">${esc(f.assetAddress)}${f.status === "TRIAGED" ? ` · <em>triaged</em>` : ""}</div>
      ${intel.length ? `<p class="intel">${intel.join(" · ")}</p>` : ""}
      ${f.remediation ? `<p class="remediation"><strong>Fix:</strong> ${esc(f.remediation)}</p>` : ""}
      ${evidenceRows(f.evidence)}
      <div class="seen">First seen ${fmtDate(f.firstSeenAt)} · last seen ${fmtDate(f.lastSeenAt)}</div>
    </article>`;
}

export function renderReportHtml(m: ReportModel): string {
  const s = m.summary;
  const sevCards = SEV_ORDER.map(
    (sev) => `<div class="card card-${sev.toLowerCase()}"><span class="n">${s.bySeverity[sev]}</span><span class="l">${SEV_LABEL[sev]}</span></div>`,
  ).join("");
  const assetRows = Object.entries(m.assets.byKind)
    .filter(([, n]) => n > 0)
    .map(([kind, n]) => `<li><span>${esc(KIND_LABEL[kind] ?? kind)}</span><span>${n}</span></li>`)
    .join("");

  const body =
    s.total === 0
      ? `<p class="clean">No open findings. Everything assessed is clean, or has been fixed or dismissed.</p>`
      : m.findings.map(findingBlock).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(m.title)}</title>
<style>
  :root {
    --ink:#13221d; --muted:#55665e; --line:#c9d3ce; --sheet:#fff; --ground:#f3f6f4; --boundary:#b8326b;
    --critical:#c42021; --high:#d65a3a; --medium:#8a6609; --low:#55665e; --info:#8a978f;
  }
  * { box-sizing:border-box; }
  body { margin:0; color:var(--ink); background:var(--ground); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .page { max-width:880px; margin:0 auto; padding:40px 32px 64px; background:var(--sheet); }
  header.cover { border-left:5px solid var(--boundary); padding-left:20px; margin-bottom:36px; }
  header.cover h1 { font-size:26px; margin:0 0 6px; letter-spacing:-.01em; }
  header.cover .sub { color:var(--muted); font-size:14px; }
  h2 { font-size:17px; margin:36px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px; }
  .cards { display:flex; flex-wrap:wrap; gap:10px; }
  .card { flex:1 1 90px; border:1px solid var(--line); border-radius:6px; padding:12px; text-align:center; }
  .card .n { display:block; font-size:24px; font-weight:700; }
  .card .l { display:block; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
  .card-critical .n { color:var(--critical); } .card-high .n { color:var(--high); } .card-medium .n { color:var(--medium); }
  .kevline { margin-top:12px; font-size:14px; }
  .kevline strong { color:var(--critical); }
  ul.assets { list-style:none; padding:0; margin:0; max-width:320px; }
  ul.assets li { display:flex; justify-content:space-between; border-bottom:1px solid var(--line); padding:5px 0; }
  .finding { border:1px solid var(--line); border-left-width:4px; border-radius:6px; padding:14px 16px; margin:12px 0; page-break-inside:avoid; }
  .finding.sev-critical { border-left-color:var(--critical); } .finding.sev-high { border-left-color:var(--high); }
  .finding.sev-medium { border-left-color:var(--medium); } .finding.sev-low { border-left-color:var(--low); } .finding.sev-info { border-left-color:var(--info); }
  .fhead { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .fhead h3 { font-size:16px; margin:0; flex:1 1 auto; }
  .chip { font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px; text-transform:uppercase; letter-spacing:.03em; }
  .chip-critical { background:var(--critical); color:#fff; } .chip-high { background:#f6e3dc; color:var(--high); }
  .chip-medium { background:#f3ecd5; color:var(--medium); } .chip-low { background:var(--ground); color:var(--ink); } .chip-info { background:var(--ground); color:var(--muted); }
  .risk { font-size:12px; color:var(--muted); }
  .fmeta { font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:13px; color:var(--muted); margin:4px 0; word-break:break-all; }
  .intel { font-size:13px; color:var(--muted); margin:6px 0; }
  .kev { color:var(--critical); }
  .remediation { margin:8px 0; }
  table.evi { border-collapse:collapse; margin:8px 0; font-size:12.5px; width:100%; }
  table.evi td { border:1px solid var(--line); padding:3px 8px; vertical-align:top; }
  td.ek { color:var(--muted); width:30%; } td.ev { font-family:ui-monospace,monospace; word-break:break-all; }
  .seen { font-size:12px; color:var(--muted); margin-top:8px; }
  .clean { padding:24px; background:var(--ground); border-radius:6px; color:var(--muted); }
  footer { margin-top:40px; border-top:1px solid var(--line); padding-top:12px; color:var(--muted); font-size:12px; }
  @page { margin:18mm 14mm; }
  @media print {
    body { background:#fff; }
    .page { max-width:none; padding:0; }
    .finding, .card { box-shadow:none; }
  }
</style>
</head>
<body>
<div class="page">
  <header class="cover">
    <h1>${esc(m.org)} — security assessment</h1>
    <div class="sub">${esc(m.scopeLabel)} · generated ${fmtDateTime(m.generatedAt)} · by ${esc(m.generatedBy)}</div>
  </header>

  <h2>Summary</h2>
  <div class="cards">${sevCards}</div>
  <p class="kevline">
    ${s.total} open finding${s.total === 1 ? "" : "s"} across ${m.assets.total} asset${m.assets.total === 1 ? "" : "s"}.
    ${s.kev > 0 ? `<strong>${s.kev} ${s.kev === 1 ? "is" : "are"} on CISA's Known Exploited Vulnerabilities list — fix ${s.kev === 1 ? "it" : "these"} first.</strong>` : ""}
  </p>

  <h2>Assets covered</h2>
  <ul class="assets">${assetRows || "<li><span>No assets yet</span><span>0</span></li>"}</ul>

  <h2>Findings</h2>
  ${body}

  <footer>
    Aegis ASM — authorized, defensive assessment. This report reflects what the selected non-intrusive checks observed at the
    time of generation. It is not a guarantee that no other issues exist. Share only with people authorized to see it.
  </footer>
</div>
</body>
</html>`;
}
