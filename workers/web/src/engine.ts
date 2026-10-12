import { isIP } from "node:net";
import { resolvePublicHost, splitHostPort, type EngineContext, type EngineImpl, type ResolveResult } from "@aegis/worker-kit";
import { analyzeCookies, analyzeHeaders } from "./checks.js";
import { EXPOSURE_PROBES } from "./exposures.js";
import type { HttpResult } from "./http.js";

/**
 * WEB engine (PRD §7 "Web"): security headers, cookie flags, a curated list
 * of exposed files. Every request is an
 * ordinary GET to the authorized host, paced to the scope's rate limit, and
 * connects to a pre-checked public IP.
 */
export interface WebDeps {
  resolve(name: string): Promise<ResolveResult | null>;
  request(url: URL, ip: string, signal: AbortSignal): Promise<HttpResult>;
}

const HTTP_PORTS = new Set([80, 8000, 8008, 8080]);
const HTTPS_PORTS = new Set([443, 8443]);

function baseUrl(scheme: "http" | "https", host: string, port?: number): string {
  const h = isIP(host) === 6 ? `[${host}]` : host;
  const defaultPort = scheme === "https" ? 443 : 80;
  return `${scheme}://${h}${port && port !== defaultPort ? `:${port}` : ""}`;
}

export function createWebEngine(deps: WebDeps): EngineImpl {
  return {
    engine: "WEB",
    async run(ctx: EngineContext) {
      const { target, signal } = ctx;
      if (!["DOMAIN", "SUBDOMAIN", "IP", "SERVICE"].includes(target.kind)) {
        ctx.log("web checks don't apply to this asset kind", { kind: target.kind });
        return;
      }
      const { host, port } = target.kind === "SERVICE" ? splitHostPort(target.address) : { host: target.address, port: undefined };
      const ips = await resolvePublicHost(host, deps.resolve);
      const ip = ips.find((a) => isIP(a) === 4) ?? ips[0]!;

      const gapMs = Math.ceil(1000 / Math.max(1, target.maxRequestsPerSec));
      let last = 0;
      const get = async (url: string) => {
        if (signal.aborted) throw signal.reason;
        const wait = last + gapMs - Date.now();
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));
        last = Date.now();
        return deps.request(new URL(url), ip, signal);
      };

      const schemes: ("http" | "https")[] =
        port && HTTP_PORTS.has(port) ? ["http"] : port && HTTPS_PORTS.has(port) ? ["https"] : ["https", "http"];

      let scheme: "http" | "https" | null = null;
      let root: HttpResult | null = null;
      for (const s of schemes) {
        try {
          root = await get(`${baseUrl(s, host, port)}/`);
          scheme = s;
          break;
        } catch (e) {
          if (signal.aborted) throw signal.reason;
          ctx.log("no answer", { scheme: s, error: (e as Error).message });
        }
      }
      if (!scheme || !root) {
        ctx.log("no web server answered; nothing to check");
        return;
      }
      const base = baseUrl(scheme, host, port);

      if (scheme === "http" && schemes.includes("https")) {
        const toHttps = root.status >= 300 && root.status < 400 && /^https:\/\//i.test(root.headers.location ?? "");
        if (!toHttps) {
          await ctx.emitFinding({
            type: "web.no-https",
            severity: "MEDIUM",
            title: "Site is only available over unencrypted HTTP",
            remediation: "Serve the site over HTTPS (a free certificate from Let's Encrypt works) and redirect all HTTP requests to it.",
            evidence: { url: `${base}/`, status: root.status },
          });
        }
      }

      for (const f of [...analyzeHeaders(root, scheme), ...analyzeCookies(root.setCookies, scheme)]) {
        await ctx.emitFinding({ ...f, evidence: { url: `${base}/`, ...(f.evidence ?? {}) } });
      }

      for (const probe of EXPOSURE_PROBES) {
        let r: HttpResult;
        try {
          r = await get(`${base}${probe.path}`);
        } catch (e) {
          if (signal.aborted) throw signal.reason;
          continue;
        }
        if (probe.matches(r)) {
          await ctx.emitFinding({
            type: probe.type,
            severity: probe.severity,
            title: probe.title,
            remediation: probe.remediation,
            evidence: { url: `${base}${probe.path}`, status: r.status },
          });
        }
      }

      try {
        const st = await get(`${base}/.well-known/security.txt`);
        const ok = st.status === 200 && !/html/i.test(st.headers["content-type"] ?? "") && /^contact:/im.test(st.bodyPrefix);
        if (!ok) {
          await ctx.emitFinding({
            type: "web.no-security-txt",
            severity: "INFO",
            title: "No security.txt to tell researchers how to report issues",
            remediation: "Publish /.well-known/security.txt with a Contact line (see securitytxt.org).",
          });
        }
      } catch (e) {
        if (signal.aborted) throw signal.reason;
      }
    },
  };
}
