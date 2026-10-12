import { describe, expect, it } from "vitest";
import type { AuthorizedTarget, FindingDraft } from "@aegis/core";
import type { EngineContext } from "@aegis/worker-kit";
import { createTlsEngine, type TlsDeps } from "../src/engine.js";
import { parseTestssl, testsslArgs } from "../src/testssl.js";

// Shape of `testssl.sh --jsonfile` output: a flat array of findings.
const SAMPLE = JSON.stringify([
  { id: "engine_problem", ip: "/", port: "443", severity: "WARN", finding: "No engine or GOST support" },
  { id: "SSLv3", ip: "shop.example.com/93.184.216.34", port: "443", severity: "HIGH", finding: "offered", cve: "", cwe: "CWE-327" },
  { id: "TLS1", ip: "shop.example.com/93.184.216.34", port: "443", severity: "LOW", finding: "offered (deprecated)" },
  { id: "TLS1_2", ip: "shop.example.com/93.184.216.34", port: "443", severity: "OK", finding: "offered" },
  { id: "SWEET32", ip: "shop.example.com/93.184.216.34", port: "443", severity: "LOW", finding: "uses 64 bit block ciphers", cve: "CVE-2016-2183 CVE-2016-6329", cwe: "CWE-327" },
  { id: "cert_expirationStatus <cert#1>", ip: "shop.example.com/93.184.216.34", port: "443", severity: "CRITICAL", finding: "expired" },
  { id: "cert_chain_of_trust", ip: "shop.example.com/93.184.216.34", port: "443", severity: "CRITICAL", finding: "failed (self signed)." },
  { id: "DROWN", ip: "shop.example.com/93.184.216.34", port: "443", severity: "OK", finding: "not vulnerable on this host and port" },
  { id: "cipher_order", ip: "shop.example.com/93.184.216.34", port: "443", severity: "INFO", finding: "server" },
]);

describe("testssl arguments", () => {
  it("runs only protocol, cipher, certificate and negotiation checks against the pinned IP", () => {
    const args = testsslArgs({ host: "shop.example.com", port: 443, ip: "93.184.216.34", jsonFile: "/tmp/x.json" });
    expect(args.slice(-1)).toEqual(["shop.example.com:443"]);
    expect(args.slice(args.indexOf("--ip"), args.indexOf("--ip") + 2)).toEqual(["--ip", "93.184.216.34"]);
    for (const f of ["--protocols", "--std", "--server-defaults", "--server-preference", "--fs", "--poodle", "--sweet32", "--beast", "--lucky13", "--logjam", "--drown", "--freak", "--crime"]) {
      expect(args).toContain(f);
    }
    // Checks that read server memory or hammer it with handshakes stay off.
    for (const f of ["--heartbleed", "-H", "--ccs-injection", "-I", "--ticketbleed", "-T", "--robot", "-BB", "--renegotiation", "-R", "--vulnerable", "-U", "--each-cipher", "-e", "--full", "--ids-friendly"]) {
      expect(args).not.toContain(f);
    }
  });

  it("targets an IP directly without --ip", () => {
    const args = testsslArgs({ host: "8.8.8.8", port: 443, ip: "8.8.8.8", jsonFile: "/tmp/x.json" });
    expect(args).not.toContain("--ip");
    expect(args.at(-1)).toBe("8.8.8.8:443");
  });
});

describe("testssl parsing", () => {
  it("keeps LOW and above, maps severities, and attaches remediation and CVEs", () => {
    const out = parseTestssl(SAMPLE);
    expect(out.map((f) => [f.type, f.severity])).toEqual([
      ["tls.SSLv3", "HIGH"],
      ["tls.TLS1", "LOW"],
      ["tls.SWEET32", "LOW"],
      ["tls.cert_expirationStatus", "CRITICAL"],
      ["tls.cert_chain_of_trust", "CRITICAL"],
    ]);
    const sweet = out.find((f) => f.type === "tls.SWEET32")!;
    expect(sweet.cveRefs).toEqual(["CVE-2016-2183", "CVE-2016-6329"]);
    expect(sweet.remediation).toMatch(/3DES/);
    expect(out.find((f) => f.type === "tls.SSLv3")!.remediation).toMatch(/Disable SSLv3/);
    expect(out.find((f) => f.type === "tls.cert_expirationStatus")!.key).toBe("cert#1");
    for (const f of out) expect(f.remediation.length).toBeGreaterThan(10);
  });

  it("tolerates junk and empty output", () => {
    expect(parseTestssl("")).toEqual([]);
    expect(parseTestssl("not json")).toEqual([]);
    expect(parseTestssl(JSON.stringify([{ id: 5 }, null, { id: "x", severity: "HIGH" }]))).toEqual([
      expect.objectContaining({ type: "tls.x", severity: "HIGH" }),
    ]);
  });
});

const target: AuthorizedTarget = {
  orgId: "o",
  scopeId: "s",
  scopeType: "DOMAIN",
  scopeValue: "example.com",
  assetId: "a",
  kind: "SUBDOMAIN",
  address: "shop.example.com",
  engine: "TLS",
  maxRequestsPerSec: 5,
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

describe("tls engine", () => {
  it("scans port 443 of the pinned public IP and records findings", async () => {
    const calls: { host: string; port: number; ip: string }[] = [];
    const deps: TlsDeps = {
      resolve: async () => ({ addresses: ["93.184.216.34"] }),
      testssl: async (t) => {
        calls.push(t);
        return parseTestssl(SAMPLE);
      },
    };
    const { ctx, findings } = ctxFor(target);
    await createTlsEngine(deps).run(ctx);
    expect(calls).toEqual([{ host: "shop.example.com", port: 443, ip: "93.184.216.34" }]);
    expect(findings).toHaveLength(5);
    expect(findings[0]!.evidence).toMatchObject({ endpoint: "shop.example.com:443" });
  });

  it("uses the service's port, skips plain-HTTP ports, and refuses private targets", async () => {
    const calls: number[] = [];
    const deps: TlsDeps = {
      resolve: async (n) => ({ addresses: [n === "intranet.example.com" ? "192.168.1.5" : "93.184.216.34"] }),
      testssl: async (t) => (calls.push(t.port), []),
    };
    await createTlsEngine(deps).run(ctxFor({ ...target, kind: "SERVICE", address: "shop.example.com:8443" }).ctx);
    await createTlsEngine(deps).run(ctxFor({ ...target, kind: "SERVICE", address: "shop.example.com:80" }).ctx);
    expect(calls).toEqual([8443]);
    await expect(createTlsEngine(deps).run(ctxFor({ ...target, address: "intranet.example.com" }).ctx)).rejects.toThrow(/non-public/);
  });
});
