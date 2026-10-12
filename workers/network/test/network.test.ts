import { describe, expect, it } from "vitest";
import type { AuthorizedTarget, FindingDraft } from "@aegis/core";
import type { EngineContext, EmittedAsset } from "@aegis/worker-kit";
import { createNetworkEngine, type NetworkDeps } from "../src/engine.js";
import { naabuArgs, parseNaabu } from "../src/naabu.js";
import { fingerprintxArgs, parseFingerprintx } from "../src/fingerprintx.js";

describe("naabu arguments", () => {
  it("runs a connect scan (no raw sockets), rate-limited, top 100 ports, no update/cloud", () => {
    const args = naabuArgs({ ip: "93.184.216.34", ratePerSec: 20 });
    expect(args.slice(args.indexOf("-host"), args.indexOf("-host") + 2)).toEqual(["-host", "93.184.216.34"]);
    expect(args.slice(args.indexOf("-s"), args.indexOf("-s") + 2)).toEqual(["-s", "c"]); // CONNECT, not SYN
    expect(args.slice(args.indexOf("-tp"), args.indexOf("-tp") + 2)).toEqual(["-tp", "100"]);
    expect(args.slice(args.indexOf("-rate"), args.indexOf("-rate") + 2)).toEqual(["-rate", "20"]);
    for (const f of ["-json", "-silent", "-duc", "-no-stdin", "-Pn"]) expect(args).toContain(f);
    expect(args).not.toContain("-nmap"); // never shell out to nmap
    expect(args).not.toContain("-pd"); // no cloud upload
    expect(args).not.toContain("-sn"); // not host-discovery-only
  });

  it("caps the rate at a polite ceiling", () => {
    expect(naabuArgs({ ip: "1.1.1.1", ratePerSec: 99999 })[naabuArgs({ ip: "1.1.1.1", ratePerSec: 99999 }).indexOf("-rate") + 1]).toBe("50");
  });
});

describe("naabu parsing", () => {
  it("keeps only ports for the scanned IP", () => {
    const out = [
      JSON.stringify({ ip: "93.184.216.34", port: 443 }),
      JSON.stringify({ ip: "93.184.216.34", port: 22 }),
      "junk",
      JSON.stringify({ ip: "10.0.0.1", port: 3306 }),
      JSON.stringify({ host: "x", ip: "93.184.216.34", port: 80 }),
    ].join("\n");
    expect(parseNaabu(out, "93.184.216.34")).toEqual([443, 22, 80]);
  });
});

describe("fingerprintx", () => {
  it("runs connect-only with JSON and a timeout; no UDP", () => {
    const args = fingerprintxArgs(500);
    expect(args).toContain("--json");
    expect(args.slice(args.indexOf("-w"), args.indexOf("-w") + 2)).toEqual(["-w", "500"]);
    expect(args).not.toContain("-U");
    expect(args).not.toContain("--udp");
  });

  it("parses service, version and only safe metadata", () => {
    const out = [
      JSON.stringify({ ip: "93.184.216.34", port: 22, service: "ssh", transport: "tcp", metadata: { version: "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3", banner: "root:x:0:0" } }),
      JSON.stringify({ ip: "93.184.216.34", port: 443, service: "http", transport: "tcp", metadata: { version: "nginx", responseHeaders: { Server: ["nginx"] }, password: "x" } }),
    ].join("\n");
    const svcs = parseFingerprintx(out);
    expect(svcs).toEqual([
      { port: 22, transport: "tcp", service: "ssh", version: "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3" },
      { port: 443, transport: "tcp", service: "http", version: "nginx" },
    ]);
    expect(JSON.stringify(svcs)).not.toContain("root:x"); // raw banner dropped
    expect(JSON.stringify(svcs)).not.toContain("password");
  });
});

const target: AuthorizedTarget = {
  orgId: "o",
  scopeId: "s",
  scopeType: "IP_RANGE",
  scopeValue: "93.184.216.34/32",
  assetId: "a",
  kind: "IP",
  address: "93.184.216.34",
  engine: "NETWORK",
  maxRequestsPerSec: 10,
};

function ctxFor(t: AuthorizedTarget) {
  const findings: FindingDraft[] = [];
  const assets: EmittedAsset[] = [];
  const ctx: EngineContext = {
    target: t,
    signal: new AbortController().signal,
    log: () => {},
    async emitAsset(a) {
      assets.push(a);
      return `svc-${assets.length}`;
    },
    async emitFinding(f) {
      findings.push(f);
      return true;
    },
  };
  return { ctx, findings, assets };
}

function deps(over: Partial<NetworkDeps> = {}): NetworkDeps {
  return {
    resolve: async () => ({ addresses: ["93.184.216.34"] }),
    naabu: async () => [22, 443],
    fingerprintx: async (_ip, ports) =>
      ports.map((p) => ({ port: p, transport: "tcp", service: p === 22 ? "ssh" : "http", version: p === 22 ? "OpenSSH 7.6" : "nginx" })),
    ...over,
  };
}

describe("network engine", () => {
  it("scans the pinned IP, records each open service as an asset, and flags risky exposures", async () => {
    const d = deps();
    const { ctx, findings, assets } = ctxFor(target);
    await createNetworkEngine(d).run(ctx);

    expect(assets.map((a) => a.address)).toEqual(["93.184.216.34:22", "93.184.216.34:443"]);
    expect(assets[0]!.metadata).toMatchObject({ service: "ssh", version: "OpenSSH 7.6", port: 22, transport: "tcp" });
    // SSH on a public host is informational; an exposed admin/db port is higher.
    const ssh = findings.find((f) => f.type === "net.exposed-service" && f.key === "22");
    expect(ssh?.severity).toBe("INFO");
  });

  it("raises severity for sensitive services like databases and RDP", async () => {
    const d = deps({
      naabu: async () => [3306, 3389, 6379],
      fingerprintx: async (_ip, ports) => ports.map((p) => ({ port: p, transport: "tcp", service: { 3306: "mysql", 3389: "rdp", 6379: "redis" }[p] ?? "unknown", version: "" })),
    });
    const { ctx, findings } = ctxFor(target);
    await createNetworkEngine(d).run(ctx);
    const sev = Object.fromEntries(findings.filter((f) => f.type === "net.exposed-service").map((f) => [f.key, f.severity]));
    expect(sev).toMatchObject({ "3306": "HIGH", "3389": "HIGH", "6379": "HIGH" });
  });

  it("reports nothing and probes nothing further when no ports are open", async () => {
    let fpCalled = false;
    const d = deps({ naabu: async () => [], fingerprintx: async (ip, ports) => ((fpCalled = true), []) });
    const { ctx, findings, assets } = ctxFor(target);
    await createNetworkEngine(d).run(ctx);
    expect(assets).toEqual([]);
    expect(findings).toEqual([]);
    expect(fpCalled).toBe(false);
  });

  it("refuses to scan a hostname that resolves to a private IP", async () => {
    const d = deps({ resolve: async () => ({ addresses: ["192.168.1.10"] }) });
    const { ctx } = ctxFor({ ...target, kind: "SUBDOMAIN", address: "intranet.example.com" });
    await expect(createNetworkEngine(d).run(ctx)).rejects.toThrow(/non-public/);
  });
});
