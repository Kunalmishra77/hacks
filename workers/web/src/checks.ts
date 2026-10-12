import type { FindingDraft } from "@aegis/core";
import type { HttpResult } from "./http.js";

// Passive checks on one ordinary response: no extra requests, no payloads.

const HSTS_MIN_SECONDS = 15_552_000; // 180 days

export function analyzeHeaders(res: HttpResult, scheme: "http" | "https"): FindingDraft[] {
  const h = res.headers;
  const out: FindingDraft[] = [];

  if (scheme === "https") {
    const hsts = h["strict-transport-security"];
    if (!hsts) {
      out.push({
        type: "web.missing-hsts",
        severity: "LOW",
        title: "HTTPS site doesn't set Strict-Transport-Security",
        remediation:
          "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses so browsers never fall back to HTTP.",
      });
    } else {
      const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0);
      if (maxAge < HSTS_MIN_SECONDS) {
        out.push({
          type: "web.weak-hsts",
          severity: "LOW",
          title: "HSTS max-age is shorter than 180 days",
          remediation: "Raise the HSTS max-age to at least 15552000 seconds (one year, 31536000, is common).",
          evidence: { header: hsts },
        });
      }
    }
  }

  const csp = h["content-security-policy"];
  if (!csp) {
    out.push({
      type: "web.missing-csp",
      severity: "LOW",
      title: "No Content-Security-Policy",
      remediation: "Add a Content-Security-Policy that limits where scripts, styles and frames can load from. Start with `default-src 'self'` in report-only mode.",
    });
  }
  if (h["x-content-type-options"]?.toLowerCase() !== "nosniff") {
    out.push({
      type: "web.missing-x-content-type-options",
      severity: "LOW",
      title: "Missing X-Content-Type-Options: nosniff",
      remediation: "Send `X-Content-Type-Options: nosniff` so browsers don't guess content types.",
    });
  }
  const framesBlocked = !!h["x-frame-options"] || /frame-ancestors/i.test(csp ?? "");
  if (!framesBlocked) {
    out.push({
      type: "web.clickjacking",
      severity: "LOW",
      title: "Page can be embedded in frames on other sites (clickjacking)",
      remediation: "Send `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`).",
    });
  }
  if (!h["referrer-policy"]) {
    out.push({
      type: "web.missing-referrer-policy",
      severity: "INFO",
      title: "No Referrer-Policy",
      remediation: "Send `Referrer-Policy: strict-origin-when-cross-origin` to avoid leaking full URLs to other sites.",
    });
  }

  const disclosed: Record<string, string> = {};
  if (h.server && /\d/.test(h.server)) disclosed.server = h.server;
  for (const k of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) if (h[k]) disclosed[k] = h[k]!;
  if (Object.keys(disclosed).length > 0) {
    out.push({
      type: "web.version-disclosure",
      severity: "LOW",
      title: "Server software versions are disclosed in headers",
      remediation: "Remove version numbers from Server and drop X-Powered-By / X-AspNet-Version headers; they help attackers pick exploits.",
      evidence: { headers: disclosed },
    });
  }
  return out;
}

const SESSION_LIKE = /sess|sid|auth|token|jwt|login|remember|csrf|xsrf/i;

export function analyzeCookies(setCookies: string[], scheme: "http" | "https"): FindingDraft[] {
  const out: FindingDraft[] = [];
  for (const raw of setCookies.slice(0, 30)) {
    const [pair = "", ...attrs] = raw.split(";");
    const name = pair.split("=")[0]!.trim().slice(0, 100);
    if (!name) continue;
    const flags = attrs.map((a) => a.trim().toLowerCase());
    const has = (f: string) => flags.some((x) => x === f || x.startsWith(`${f}=`));
    const sensitive = SESSION_LIKE.test(name);
    const evidence = { cookie: name, secure: has("secure"), httpOnly: has("httponly"), sameSite: has("samesite") };

    if (scheme === "https" && !has("secure")) {
      out.push({
        type: "web.cookie-not-secure",
        key: name,
        severity: sensitive ? "MEDIUM" : "LOW",
        title: `Cookie "${name}" can be sent over plain HTTP`,
        remediation: `Set the Secure attribute on "${name}" so it is only sent over HTTPS.`,
        evidence,
      });
    }
    if (!has("httponly")) {
      out.push({
        type: "web.cookie-not-httponly",
        key: name,
        severity: sensitive ? "MEDIUM" : "LOW",
        title: `Cookie "${name}" is readable by JavaScript`,
        remediation: `Set HttpOnly on "${name}" unless your scripts truly need to read it.`,
        evidence,
      });
    }
    if (!has("samesite")) {
      out.push({
        type: "web.cookie-no-samesite",
        key: name,
        severity: "INFO",
        title: `Cookie "${name}" has no SameSite attribute`,
        remediation: `Set SameSite=Lax (or Strict) on "${name}" to limit cross-site request forgery.`,
        evidence,
      });
    }
  }
  return out;
}
