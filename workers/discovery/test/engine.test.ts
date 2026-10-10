import { describe, expect, it } from "vitest";
import type { AuthorizedTarget } from "@aegis/core";
import { ToolMissingError, type EmittedAsset, type EngineContext } from "@aegis/worker-kit";
import { createDiscoveryEngine, type DiscoveryDeps } from "../src/engine.js";
import { httpxArgs, parseHttpx } from "../src/httpx.js";
import { parseCrtSh } from "../src/crtsh.js";
import { subfinderArgs } from "../src/subfinder.js";

const domainTarget: AuthorizedTarget = {
  orgId: "o",
  scopeId: "s",
  scopeType: "DOMAIN",
  scopeValue: "example.com",
  assetId: "a",
  kind: "DOMAIN",
  address: "example.com",
  engine: "DISCOVERY",
  maxRequestsPerSec: 4,
};

function ctxFor(target: AuthorizedTarget, signal = new AbortController().signal) {
  const emitted: EmittedAsset[] = [];
  const ctx: EngineContext = {
    target,
    signal,
    log: () => {},
    async emitAsset(a) {
      emitted.push(a);
      return true;
    },
  };
  return { ctx, emitted };
}

const DNS: Record<string, { addresses: string[]; cname?: string }> = {
  "example.com": { addresses: ["93.184.216.34"] },
  "api.example.com": { addresses: ["93.184.216.34"] },
  "www.example.com": { addresses: ["151.101.1.1"], cname: "example.cdn.net" },
  "dev.example.com": { addresses: ["10.0.0.5"] },
};

function deps(over: Partial<DiscoveryDeps> = {}): DiscoveryDeps & { httpxInputs: string[][] } {
  const httpxInputs: string[][] = [];
  return {
    httpxInputs,
    crtsh: async () => ["api.example.com", "*.example.com", "evil.com", "mail.example.com.evil.net", "API.example.com"],
    subfinder: async () => ["dev.example.com", "www.example.com", "gone.example.com"],
    resolve: async (name) => DNS[name] ?? null,
    httpx: async (hosts) => {
      httpxInputs.push(hosts);
      return hosts
        .filter((h) => h !== "93.184.216.99")
        .map((h) => ({ host: h, port: 443, url: `https://${h}`, statusCode: 200, title: "Hi", webServer: "nginx", tech: ["Nginx"] }));
    },
    randomLabel: () => "aegis-wc-test",
    ...over,
  };
}

describe("discovery engine", () => {
  it("enumerates in-scope subdomains, resolves them, and probes only public hosts", async () => {
    const d = deps();
    const { ctx, emitted } = ctxFor(domainTarget);
    await createDiscoveryEngine(d).run(ctx);

    const subs = emitted.filter((a) => a.kind === "SUBDOMAIN");
    expect(subs.map((a) => a.address).sort()).toEqual(["api.example.com", "dev.example.com", "www.example.com"]);
    expect(subs.find((a) => a.address === "www.example.com")!.metadata).toMatchObject({
      ips: ["151.101.1.1"],
      cname: "example.cdn.net",
    });
    // Private-IP names are recorded (useful inventory) but never contacted.
    expect(subs.find((a) => a.address === "dev.example.com")!.metadata).toMatchObject({ private: true, probed: false });
    expect(d.httpxInputs).toEqual([["example.com", "api.example.com", "www.example.com"]]);

    const services = emitted.filter((a) => a.kind === "SERVICE").map((a) => a.address);
    expect(services).toEqual(["example.com:443", "api.example.com:443", "www.example.com:443"]);
  });

  it("drops names that only exist because of wildcard DNS", async () => {
    const d = deps({
      resolve: async (name) => (name === "aegis-wc-test.example.com" ? { addresses: ["151.101.1.1"] } : DNS[name] ?? null),
    });
    const { ctx, emitted } = ctxFor(domainTarget);
    await createDiscoveryEngine(d).run(ctx);
    const subs = emitted.filter((a) => a.kind === "SUBDOMAIN").map((a) => a.address);
    expect(subs).not.toContain("www.example.com"); // same IPs as the wildcard
    expect(subs).toContain("api.example.com");
  });

  it("keeps going when a passive source fails or subfinder isn't installed", async () => {
    const d = deps({
      crtsh: async () => {
        throw new Error("crt.sh 502");
      },
      subfinder: async () => {
        throw new ToolMissingError("subfinder");
      },
    });
    const { ctx, emitted } = ctxFor(domainTarget);
    await createDiscoveryEngine(d).run(ctx);
    expect(emitted.map((a) => a.address)).toEqual(["example.com:443"]); // apex is still probed
  });

  it("for an IP scope, skips enumeration and probes the IP itself", async () => {
    let enumerated = false;
    const d = deps({
      crtsh: async () => {
        enumerated = true;
        return [];
      },
    });
    const { ctx, emitted } = ctxFor({ ...domainTarget, scopeType: "IP_RANGE", scopeValue: "8.8.8.8/32", kind: "IP", address: "8.8.8.8" });
    await createDiscoveryEngine(d).run(ctx);
    expect(enumerated).toBe(false);
    expect(d.httpxInputs).toEqual([["8.8.8.8"]]);
    expect(emitted.map((a) => a.address)).toEqual(["8.8.8.8:443"]);
  });

  it("stops when aborted", async () => {
    const ac = new AbortController();
    ac.abort(new Error("killed"));
    const { ctx } = ctxFor(domainTarget, ac.signal);
    await expect(createDiscoveryEngine(deps()).run(ctx)).rejects.toThrow("killed");
  });
});

describe("tool arguments and parsers", () => {
  it("runs subfinder in passive mode only", () => {
    expect(subfinderArgs("example.com")).toEqual(["-d", "example.com", "-silent", "-nc", "-max-time", "5", "-duc"]);
  });

  it("runs httpx as a light, rate-limited liveness probe with no redirects or fuzzing", () => {
    const args = httpxArgs(4);
    expect(args).toEqual([
      "-silent", "-nc", "-duc", "-json",
      "-sc", "-title", "-server", "-td",
      "-rl", "4", "-t", "4", "-timeout", "10", "-retries", "1",
      "-p", "80,443",
    ]);
    for (const flag of ["-fr", "-follow-redirects", "-path", "-x", "-body", "-H"]) expect(args).not.toContain(flag);
    expect(httpxArgs(100)).toContain("5"); // threads capped
  });

  it("parses crt.sh names, stripping wildcards and splitting multi-name entries", () => {
    const json = JSON.stringify([
      { name_value: "*.example.com\nwww.example.com" },
      { name_value: "API.example.com" },
      { name_value: "other.org" },
      { name_value: "bad name.example.com" },
    ]);
    expect(parseCrtSh(json, "example.com").sort()).toEqual(["api.example.com", "example.com", "www.example.com"]);
  });

  it("parses httpx JSON lines and ignores junk", () => {
    const out = [
      JSON.stringify({ input: "api.example.com", port: "443", url: "https://api.example.com", status_code: 200, title: "API", webserver: "nginx", tech: ["Nginx"] }),
      "not json",
      JSON.stringify({ input: "x.example.com", failed: true }),
      JSON.stringify({ input: "www.example.com", url: "http://www.example.com", status_code: 301 }),
    ].join("\n");
    expect(parseHttpx(out)).toEqual([
      { host: "api.example.com", port: 443, url: "https://api.example.com", statusCode: 200, title: "API", webServer: "nginx", tech: ["Nginx"] },
      { host: "www.example.com", port: 80, url: "http://www.example.com", statusCode: 301, title: undefined, webServer: undefined, tech: [] },
    ]);
  });
});
