import type { Severity } from "@aegis/core";
import type { HttpResult } from "./http.js";

// A short, curated list of files that should never be public. Each probe is
// one GET to a fixed path with a strict matcher, so soft-404 pages and HTML
// error pages don't produce false alarms. Response bodies are only matched,
// never stored.

export interface ExposureProbe {
  path: string;
  type: string;
  severity: Severity;
  title: string;
  remediation: string;
  matches(res: HttpResult): boolean;
}

const isHtml = (r: HttpResult) => /html/i.test(r.headers["content-type"] ?? "") || /^\s*</.test(r.bodyPrefix);

export const EXPOSURE_PROBES: ExposureProbe[] = [
  {
    path: "/.git/HEAD",
    type: "web.exposed-git",
    severity: "HIGH",
    title: "Git repository is publicly downloadable",
    remediation: "Block access to /.git on the web server (or stop deploying it). Anyone can rebuild your source code, often including credentials, from it.",
    matches: (r) => r.status === 200 && !isHtml(r) && /^ref: refs\/heads\/\S+/.test(r.bodyPrefix),
  },
  {
    path: "/.env",
    type: "web.exposed-env",
    severity: "HIGH",
    title: "Environment file (.env) is publicly readable",
    remediation: "Remove .env from the web root and block dotfiles. Treat every secret in it as leaked and rotate them.",
    matches: (r) => r.status === 200 && !isHtml(r) && (r.bodyPrefix.match(/^[A-Z][A-Z0-9_]{1,63}=/gm)?.length ?? 0) >= 2,
  },
  {
    path: "/.DS_Store",
    type: "web.exposed-ds-store",
    severity: "LOW",
    title: ".DS_Store file reveals directory contents",
    remediation: "Delete .DS_Store files from the web root and block dotfiles.",
    matches: (r) => r.status === 200 && r.bodyPrefix.startsWith("\u0000\u0000\u0000\u0001Bud1"),
  },
  {
    path: "/server-status",
    type: "web.exposed-server-status",
    severity: "MEDIUM",
    title: "Apache server-status page is public",
    remediation: "Restrict mod_status to localhost or your admin network (`Require local`).",
    matches: (r) => r.status === 200 && r.bodyPrefix.includes("Apache Server Status for"),
  },
  {
    path: "/phpinfo.php",
    type: "web.exposed-phpinfo",
    severity: "MEDIUM",
    title: "phpinfo() page is public",
    remediation: "Delete phpinfo.php; it reveals versions, paths and configuration.",
    matches: (r) => r.status === 200 && r.bodyPrefix.includes("phpinfo()") && r.bodyPrefix.includes("PHP Version"),
  },
];
