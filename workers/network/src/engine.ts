import { isIP } from "node:net";
import type { FindingDraft, Severity } from "@aegis/core";
import { resolvePublicHost, type EngineContext, type EngineImpl, type ResolveResult } from "@aegis/worker-kit";
import type { ServiceInfo } from "./fingerprintx.js";

/**
 * NETWORK engine (PRD §7 "Network"): which TCP ports are open on a host, and
 * what service each is. Admin-approved (the gate requires it). It identifies
 * exposure; it never logs in, brute-forces, or sends attack payloads.
 */
export interface NetworkDeps {
  resolve(name: string): Promise<ResolveResult | null>;
  naabu(ip: string, ratePerSec: number, signal: AbortSignal): Promise<number[]>;
  fingerprintx(ip: string, ports: number[], signal: AbortSignal): Promise<ServiceInfo[]>;
}

// Services that shouldn't normally face the public internet. Finding one open
// isn't proof of a hole, but it's worth a human's attention.
const SENSITIVE: Record<string, { severity: Severity; what: string }> = {
  mysql: { severity: "HIGH", what: "MySQL database" },
  postgresql: { severity: "HIGH", what: "PostgreSQL database" },
  postgres: { severity: "HIGH", what: "PostgreSQL database" },
  redis: { severity: "HIGH", what: "Redis" },
  mongodb: { severity: "HIGH", what: "MongoDB" },
  mssql: { severity: "HIGH", what: "Microsoft SQL Server" },
  rdp: { severity: "HIGH", what: "Remote Desktop (RDP)" },
  vnc: { severity: "HIGH", what: "VNC remote desktop" },
  elasticsearch: { severity: "HIGH", what: "Elasticsearch" },
  memcached: { severity: "HIGH", what: "Memcached" },
  ftp: { severity: "MEDIUM", what: "FTP" },
  telnet: { severity: "HIGH", what: "Telnet (unencrypted remote login)" },
  smb: { severity: "HIGH", what: "SMB file sharing" },
  ldap: { severity: "MEDIUM", what: "LDAP directory" },
  docker: { severity: "HIGH", what: "Docker API" },
  kubernetes: { severity: "HIGH", what: "Kubernetes API" },
};

// Services whose exposure is expected for a web host: just inventory, INFO.
const EXPECTED = new Set(["http", "https", "ssh", "smtp", "smtps", "imaps", "pop3s", "dns", "ntp"]);

function assess(service: string): { severity: Severity; what: string } {
  const s = service.toLowerCase();
  if (SENSITIVE[s]) return SENSITIVE[s]!;
  if (EXPECTED.has(s)) return { severity: "INFO", what: service };
  return { severity: "LOW", what: service === "unknown" ? "an unidentified service" : service };
}

export function createNetworkEngine(deps: NetworkDeps): EngineImpl {
  return {
    engine: "NETWORK",
    async run(ctx: EngineContext) {
      const { target, signal } = ctx;
      if (!["DOMAIN", "SUBDOMAIN", "IP", "SERVICE"].includes(target.kind)) {
        ctx.log("network scan doesn't apply to this asset kind", { kind: target.kind });
        return;
      }
      const host = target.kind === "SERVICE" ? target.address.replace(/:\d+$/, "") : target.address;
      const ips = await resolvePublicHost(host, deps.resolve);
      const ip = ips.find((a) => isIP(a) === 4) ?? ips[0]!;
      if (signal.aborted) throw signal.reason;

      const ports = await deps.naabu(ip, target.maxRequestsPerSec, signal);
      if (ports.length === 0) {
        ctx.log("no open ports found", { ip });
        return;
      }
      if (signal.aborted) throw signal.reason;

      const services = await deps.fingerprintx(ip, ports, signal);
      const byPort = new Map(services.map((s) => [s.port, s]));

      for (const port of ports.sort((a, b) => a - b)) {
        if (signal.aborted) throw signal.reason;
        const svc = byPort.get(port) ?? { port, transport: "tcp", service: "unknown", version: "" };
        const assetId = await ctx.emitAsset({
          kind: "SERVICE",
          address: `${ip}:${port}`,
          metadata: { port, transport: svc.transport, service: svc.service, version: svc.version, viaHost: host },
        });
        const { severity, what } = assess(svc.service);
        await ctx.emitFinding({
          assetId: assetId ?? undefined,
          type: "net.exposed-service",
          key: String(port),
          severity,
          title: severity === "INFO" ? `Port ${port} open: ${what}` : `${what} is reachable from the internet on port ${port}`,
          remediation:
            severity === "INFO"
              ? "Expected for a public web host. Keep the service patched and limit access where you can."
              : `If ${what} doesn't need to be public, restrict it to a firewall allow-list or VPN. If it does, make sure it's patched and requires authentication.`,
          evidence: { ip, port, service: svc.service, version: svc.version || undefined, transport: svc.transport },
        });
      }
    },
  };
}
