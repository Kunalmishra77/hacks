import { isIP } from "node:net";
import type { FindingDraft } from "@aegis/core";
import { resolvePublicHost, splitHostPort, type EngineContext, type EngineImpl, type ResolveResult } from "@aegis/worker-kit";

/**
 * TLS engine (PRD §7 "TLS"): protocol, cipher and certificate hygiene for one
 * endpoint, via testssl.sh against a pre-checked public IP.
 */
export interface TlsDeps {
  resolve(name: string): Promise<ResolveResult | null>;
  testssl(t: { host: string; port: number; ip: string }, signal: AbortSignal): Promise<FindingDraft[]>;
}

/** Ports that are plain HTTP by convention; TLS checks there only waste time. */
const PLAIN_PORTS = new Set([80, 8000, 8008, 8080]);

export function createTlsEngine(deps: TlsDeps): EngineImpl {
  return {
    engine: "TLS",
    async run(ctx: EngineContext) {
      const { target, signal } = ctx;
      if (!["DOMAIN", "SUBDOMAIN", "IP", "SERVICE"].includes(target.kind)) {
        ctx.log("TLS checks don't apply to this asset kind", { kind: target.kind });
        return;
      }
      const { host, port: p } = target.kind === "SERVICE" ? splitHostPort(target.address) : { host: target.address, port: undefined };
      const port = p ?? 443;
      if (PLAIN_PORTS.has(port)) {
        ctx.log("plain-HTTP port; no TLS to check", { port });
        return;
      }
      const ips = await resolvePublicHost(host, deps.resolve);
      const ip = ips.find((a) => isIP(a) === 4) ?? ips[0]!;
      if (signal.aborted) throw signal.reason;

      const findings = await deps.testssl({ host, port, ip }, signal);
      for (const f of findings) {
        await ctx.emitFinding({ ...f, evidence: { endpoint: `${host}:${port}`, ...(f.evidence ?? {}) } });
      }
    },
  };
}
