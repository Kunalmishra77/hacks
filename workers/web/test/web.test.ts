import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import type { AuthorizedTarget, FindingDraft } from "@aegis/core";
import type { EngineContext } from "@aegis/worker-kit";
import { analyzeCookies, analyzeHeaders } from "../src/checks.js";
import { EXPOSURE_PROBES } from "../src/exposures.js";
import { createWebEngine, type WebDeps } from "../src/engine.js";
import { pinnedGet, type HttpResult } from "../src/http.js";

const res = (status: number, headers: Record<string, string> = {}, body = "", setCookies: string[] = []): HttpResult => ({
  status,
  headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
  setCookies,
  bodyPrefix: body,
});

const GOOD_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  server: "nginx",
};

describe("header and cookie checks", () => {
  it("reports nothing for a well-configured HTTPS response", () => {
    expect(analyzeHeaders(res(200, GOOD_HEADERS), "https")).toEqual([]);
  });

  it("flags missing protections and version disclosure", () => {
    const types = analyzeHeaders(res(200, { server: "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24" }), "https").map((f) => f.type);
    expect(types.sort()).toEqual(
      [
        "web.missing-hsts",
        "web.missing-csp",
        "web.missing-x-content-type-options",
        "web.clickjacking",
        "web.missing-referrer-policy",
        "web.version-disclosure",
      ].sort(),
    );
  });

  it("accepts X-Frame-Options instead of frame-ancestors, and flags a short HSTS max-age", () => {
    const f = analyzeHeaders(res(200, { ...GOOD_HEADERS, "content-security-policy": "default-src 'self'", "x-frame-options": "DENY", "strict-transport-security": "max-age=600" }), "https");
    expect(f.map((x) => x.type)).toEqual(["web.weak-hsts"]);
  });

  it("does not ask plain-HTTP responses for HSTS", () => {
    expect(analyzeHeaders(res(200, GOOD_HEADERS), "http").map((f) => f.type)).not.toContain("web.missing-hsts");
  });

  it("checks cookie flags per cookie, without recording values", () => {
    const f = analyzeCookies(["sessionid=SECRET123; Path=/", "prefs=dark; Secure; HttpOnly; SameSite=Lax"], "https");
    expect(f.map((x) => [x.type, x.key])).toEqual([
      ["web.cookie-not-secure", "sessionid"],
      ["web.cookie-not-httponly", "sessionid"],
      ["web.cookie-no-samesite", "sessionid"],
    ]);
    expect(JSON.stringify(f)).not.toContain("SECRET123");
    expect(f[0]!.severity).toBe("MEDIUM"); // session-like cookie
  });
});

describe("exposed-file probes", () => {
  const probe = (path: string) => EXPOSURE_PROBES.find((p) => p.path === path)!;

  it("match real exposures", () => {
    expect(probe("/.git/HEAD").matches(res(200, {}, "ref: refs/heads/main\n"))).toBe(true);
    expect(probe("/.env").matches(res(200, { "content-type": "text/plain" }, "APP_KEY=base64:x\nDB_PASSWORD=y\n"))).toBe(true);
    expect(probe("/.DS_Store").matches(res(200, {}, "\u0000\u0000\u0000\u0001Bud1\u0000"))).toBe(true);
    expect(probe("/server-status").matches(res(200, {}, "<h1>Apache Server Status for example.com</h1>"))).toBe(true);
  });

  it("ignore soft-404 pages and HTML that merely mentions the path", () => {
    const soft404 = res(200, { "content-type": "text/html" }, "<html><title>Not found</title>ref: refs/heads? APP_KEY=x</html>");
    for (const p of EXPOSURE_PROBES) expect(p.matches(soft404), p.path).toBe(false);
    expect(probe("/.git/HEAD").matches(res(404, {}, "ref: refs/heads/main"))).toBe(false);
    expect(probe("/.env").matches(res(200, { "content-type": "text/plain" }, "just one=line"))).toBe(false);
  });

  it("only ever uses GET on fixed paths", () => {
    for (const p of EXPOSURE_PROBES) expect(p.path).toMatch(/^\/[\w./-]+$/);
  });
});

describe("pinned HTTP client", () => {
  it("connects to the pinned IP even for a hostname that resolves elsewhere", async () => {
    let hostHeader = "";
    const server = createServer((req, r) => {
      hostHeader = req.headers.host ?? "";
      r.setHeader("set-cookie", ["a=1; Secure", "b=2"]);
      r.end("hello");
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    const { port } = server.address() as AddressInfo;
    try {
      const out = await pinnedGet(new URL(`http://www.example.com:${port}/`), "127.0.0.1", { timeoutMs: 5000, maxBody: 3 });
      expect(out.status).toBe(200);
      expect(out.bodyPrefix).toBe("hel"); // capped
      expect(out.setCookies).toEqual(["a=1; Secure", "b=2"]);
      expect(hostHeader).toBe(`www.example.com:${port}`);
    } finally {
      server.close();
    }
  });
});

// ── Engine wiring ───────────────────────────────────────────────────

const target: AuthorizedTarget = {
  orgId: "o",
  scopeId: "s",
  scopeType: "DOMAIN",
  scopeValue: "example.com",
  assetId: "a",
  kind: "SUBDOMAIN",
  address: "shop.example.com",
  engine: "WEB",
  maxRequestsPerSec: 100,
};

function ctxFor(t: AuthorizedTarget) {
  const findings: FindingDraft[] = [];
  const ctx: EngineContext = {
    target: t,
    signal: new AbortController().signal,
    log: () => {},
    emitAsset: async () => "x",
    async emitFinding(f) {
      findings.push(f);
      return true;
    },
  };
  return { ctx, findings };
}

function deps(over: Partial<WebDeps> = {}): WebDeps & { calls: { url: string; ip: string }[] } {
  const calls: { url: string; ip: string }[] = [];
  return {
    calls,
    resolve: async () => ({ addresses: ["93.184.216.34"] }),
    request: async (url, ip) => {
      calls.push({ url: url.toString(), ip });
      if (url.pathname === "/") return res(200, { server: "nginx" }, "<html>", ["sid=abc; Path=/"]);
      if (url.pathname === "/.git/HEAD") return res(200, {}, "ref: refs/heads/main\n");
      return res(404, { "content-type": "text/html" }, "<html>nope</html>");
    },
    ...over,
  };
}

describe("web engine", () => {
  it("checks the site over HTTPS via the pinned public IP and reports findings", async () => {
    const d = deps();
    const { ctx, findings } = ctxFor(target);
    await createWebEngine(d).run(ctx);
    expect(new Set(d.calls.map((c) => c.ip))).toEqual(new Set(["93.184.216.34"]));
    expect(d.calls[0]!.url).toBe("https://shop.example.com/");
    const types = findings.map((f) => f.type);
    expect(types).toContain("web.missing-hsts");
    expect(types).toContain("web.exposed-git");
    expect(types).toContain("web.cookie-not-secure");
    expect(types).toContain("web.no-security-txt");
    const git = findings.find((f) => f.type === "web.exposed-git")!;
    expect(git.evidence).toEqual({ url: "https://shop.example.com/.git/HEAD", status: 200 });
  });

  it("refuses targets that resolve to private addresses", async () => {
    const d = deps({ resolve: async () => ({ addresses: ["10.0.0.7"] }) });
    const { ctx } = ctxFor(target);
    await expect(createWebEngine(d).run(ctx)).rejects.toThrow(/non-public/);
    expect(d.calls).toEqual([]);
  });

  it("flags plain HTTP that doesn't redirect to HTTPS", async () => {
    const d = deps({
      request: async (url) => {
        if (url.protocol === "https:") throw new Error("ECONNREFUSED");
        return url.pathname === "/" ? res(200, {}, "<html>") : res(404);
      },
    });
    const { ctx, findings } = ctxFor(target);
    await createWebEngine(d).run(ctx);
    expect(findings.map((f) => f.type)).toContain("web.no-https");
  });

  it("uses the service's port and scheme for SERVICE assets", async () => {
    const d = deps();
    const { ctx } = ctxFor({ ...target, kind: "SERVICE", address: "shop.example.com:8443" });
    await createWebEngine(d).run(ctx);
    expect(d.calls[0]!.url).toBe("https://shop.example.com:8443/");
  });
});
