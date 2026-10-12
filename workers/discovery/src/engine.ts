import { randomBytes } from "node:crypto";
import { isPublicAddress, isWithinDomain, normalizeDomain } from "@aegis/core";
import type { EngineContext, EngineImpl } from "@aegis/worker-kit";
import type { ResolveResult } from "@aegis/worker-kit";
import type { HttpxResult } from "./httpx.js";

/**
 * DISCOVERY engine (PRD Phase 2):
 *   1. passive subdomain enumeration (crt.sh + subfinder) — no target contact
 *   2. DNS resolution via public resolvers, with wildcard-DNS filtering
 *   3. HTTP(S) liveness on 80/443 via httpx, rate-limited per scope
 *
 * Port scanning is deliberately NOT here: it belongs to the NETWORK engine,
 * which needs Admin approval. Hosts that resolve to private/reserved IPs are
 * recorded but never contacted (that would turn the worker into an SSRF
 * proxy into its own network).
 */

export interface DiscoveryDeps {
  crtsh(apex: string, signal: AbortSignal): Promise<string[]>;
  subfinder(apex: string, signal: AbortSignal): Promise<string[]>;
  resolve(name: string): Promise<ResolveResult | null>;
  httpx(hosts: string[], ratePerSec: number, signal: AbortSignal): Promise<HttpxResult[]>;
  randomLabel?(): string;
}

const MAX_NAMES = 1000;
const RESOLVE_CONCURRENCY = 10;

function check(signal: AbortSignal) {
  if (signal.aborted) throw signal.reason ?? new Error("aborted");
}

async function mapLimit<T, R>(items: T[], limit: number, signal: AbortSignal, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      check(signal);
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return out;
}

const allPublic = (ips: string[]) => ips.length > 0 && ips.every(isPublicAddress);
const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

export function createDiscoveryEngine(deps: DiscoveryDeps): EngineImpl {
  const randomLabel = deps.randomLabel ?? (() => `aegis-wc-${randomBytes(6).toString("hex")}`);

  return {
    engine: "DISCOVERY",
    async run(ctx: EngineContext) {
      const { target, signal } = ctx;
      check(signal);
      const probe: string[] = [];

      if (target.kind === "DOMAIN" || target.kind === "SUBDOMAIN") {
        const root = normalizeDomain(target.address);
        if (!root) throw new Error(`invalid domain target ${target.address}`);

        // 1. Passive enumeration. A failing source is logged, not fatal.
        const sources = await Promise.allSettled([deps.crtsh(root, signal), deps.subfinder(root, signal)]);
        check(signal);
        const names: string[] = [];
        const seen = new Set<string>([root]);
        sources.forEach((s, i) => {
          if (s.status === "rejected") {
            ctx.log("passive source failed", { source: i === 0 ? "crt.sh" : "subfinder", error: String((s.reason as Error)?.message ?? s.reason) });
            return;
          }
          for (const raw of s.value) {
            const n = normalizeDomain(raw);
            if (n && isWithinDomain(n, root) && !seen.has(n) && names.length < MAX_NAMES) {
              seen.add(n);
              names.push(n);
            }
          }
        });

        // 2. Resolve (apex + names), filtering wildcard DNS.
        const wildcard = await deps.resolve(`${randomLabel()}.${root}`);
        const apex = await deps.resolve(root);
        if (apex && allPublic(apex.addresses)) probe.push(root);
        const resolved = await mapLimit(names, RESOLVE_CONCURRENCY, signal, (n) => deps.resolve(n));

        for (let i = 0; i < names.length; i++) {
          check(signal);
          const r = resolved[i];
          if (!r) continue;
          if (wildcard && sameSet(r.addresses, wildcard.addresses)) continue;
          const isPrivate = !allPublic(r.addresses);
          await ctx.emitAsset({
            kind: "SUBDOMAIN",
            address: names[i]!,
            metadata: {
              ips: r.addresses,
              ...(r.cname ? { cname: r.cname } : {}),
              private: isPrivate,
              probed: !isPrivate,
            },
          });
          if (!isPrivate) probe.push(names[i]!);
        }
      } else if (target.kind === "IP") {
        if (isPublicAddress(target.address)) probe.push(target.address);
      } else {
        ctx.log("discovery does not apply to this asset kind", { kind: target.kind });
        return;
      }

      // 3. Liveness. httpx missing or failing is a real failure (surfaced as FAILED).
      check(signal);
      const allowed = new Set(probe);
      const results = await deps.httpx(probe, target.maxRequestsPerSec, signal);
      for (const r of results) {
        check(signal);
        if (!allowed.has(r.host)) continue; // ignore anything we didn't ask about
        await ctx.emitAsset({
          kind: "SERVICE",
          address: `${r.host}:${r.port}`,
          metadata: { url: r.url, statusCode: r.statusCode, title: r.title, webServer: r.webServer, tech: r.tech },
        });
      }
    },
  };
}
