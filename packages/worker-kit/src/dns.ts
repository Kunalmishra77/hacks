import { isIP } from "node:net";
import { isPublicAddress } from "@aegis/core";
import { Resolver } from "node:dns/promises";

export interface ResolveResult {
  addresses: string[];
  cname?: string;
}

/**
 * Resolves A/AAAA (+ CNAME) through public resolvers, so the worker host's
 * own DNS (which might know internal names) never answers for customer data.
 * Returns null when the name doesn't resolve.
 */
export function createPublicResolver(servers = ["1.1.1.1", "8.8.8.8"]) {
  const r = new Resolver({ timeout: 4000, tries: 2 });
  r.setServers(servers);
  const safe = <T>(p: Promise<T>, fallback: T) => p.catch(() => fallback);

  return async function resolve(name: string): Promise<ResolveResult | null> {
    const [v4, v6, cname] = await Promise.all([
      safe(r.resolve4(name), [] as string[]),
      safe(r.resolve6(name), [] as string[]),
      safe(r.resolveCname(name), [] as string[]),
    ]);
    const addresses = [...v4, ...v6].sort();
    if (addresses.length === 0) return null;
    return cname[0] ? { addresses, cname: cname[0].toLowerCase() } : { addresses };
  };
}

export class NonPublicTargetError extends Error {
  constructor(public readonly host: string, public readonly addresses: string[]) {
    super(`${host} resolves to non-public addresses; refusing to contact it`);
    this.name = "NonPublicTargetError";
  }
}

/**
 * Resolves `host` (or accepts an IP literal) and returns its addresses only if
 * every one is public. Engines connect to these pinned IPs, never re-resolving,
 * so a DNS answer can't steer them into private networks.
 */
export async function resolvePublicHost(
  host: string,
  resolve: (name: string) => Promise<ResolveResult | null>,
): Promise<string[]> {
  if (isIP(host)) {
    if (!isPublicAddress(host)) throw new NonPublicTargetError(host, [host]);
    return [host];
  }
  const r = await resolve(host);
  if (!r || r.addresses.length === 0) throw new Error(`${host} does not resolve`);
  if (!r.addresses.every(isPublicAddress)) throw new NonPublicTargetError(host, r.addresses);
  return r.addresses;
}

/** Splits a target address into host and optional port ("host:443", "[v6]:443", "host"). */
export function splitHostPort(address: string): { host: string; port?: number } {
  const v6 = /^\[([^\]]+)\]:(\d{1,5})$/.exec(address);
  if (v6) return { host: v6[1]!, port: Number(v6[2]) };
  const m = /^([^:]+):(\d{1,5})$/.exec(address);
  if (m) return { host: m[1]!, port: Number(m[2]) };
  return { host: address };
}
