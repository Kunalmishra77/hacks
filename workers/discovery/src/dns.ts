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
