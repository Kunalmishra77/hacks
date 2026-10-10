import { BlockList, isIP } from "node:net";
import type { AssetKind, ScopeType } from "./types.js";

// Strict target-in-scope matching and scope-value validation
// (docs/SCOPE_AUTHORIZATION.md, "Target-in-scope matching (be strict)").

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Lower-cases and validates a hostname. Rejects IPs, wildcards, single-label
 * names, and anything that isn't plain LDH labels. Returns null if invalid.
 */
export function normalizeDomain(input: string): string | null {
  const d = input.trim().toLowerCase().replace(/\.$/, "");
  if (d.length === 0 || d.length > 253 || isIP(d)) return null;
  const labels = d.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((l) => LABEL.test(l))) return null;
  if (/^[0-9]+$/.test(labels.at(-1)!)) return null; // numeric TLD
  return d;
}

/** True when `host` equals `apex` or is a subdomain of it. */
export function isWithinDomain(host: string, apex: string): boolean {
  return host === apex || host.endsWith(`.${apex}`);
}

export interface ParsedCidr {
  address: string;
  prefix: number;
  family: "ipv4" | "ipv6";
}

export function parseCidr(value: string): ParsedCidr | null {
  const [address, prefixStr, ...rest] = value.trim().split("/");
  if (!address || rest.length) return null;
  const v = isIP(address);
  if (!v) return null;
  const family = v === 4 ? "ipv4" : "ipv6";
  const max = v === 4 ? 32 : 128;
  const prefix = prefixStr === undefined ? max : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return null;
  return { address, prefix, family };
}

export function ipInCidr(ip: string, cidr: ParsedCidr): boolean {
  const v = isIP(ip);
  if (!v || (v === 4 ? "ipv4" : "ipv6") !== cidr.family) return false;
  const bl = new BlockList();
  bl.addSubnet(cidr.address, cidr.prefix, cidr.family);
  return bl.check(ip, cidr.family);
}

/** Splits "host:port" / "[v6]:port" service addresses; returns the host part. */
export function serviceHost(address: string): string | null {
  const v6 = /^\[([^\]]+)\]:(\d{1,5})$/.exec(address);
  if (v6) return v6[1]!;
  const m = /^([^:]+):(\d{1,5})$/.exec(address);
  return m ? m[1]! : null;
}

const AWS_ACCOUNT = /^aws:(\d{12})$/;

export function parseAwsAccountScope(value: string): string | null {
  return AWS_ACCOUNT.exec(value)?.[1] ?? null;
}

/**
 * Whether an asset's address is inside its scope's value. Called by the gate
 * on every decision so a mis-filed or tampered asset row can't widen a scope.
 */
export function targetInScope(
  scope: { type: ScopeType; value: string },
  asset: { kind: AssetKind; address: string },
): boolean {
  switch (scope.type) {
    case "DOMAIN": {
      const apex = normalizeDomain(scope.value);
      if (!apex) return false;
      const host =
        asset.kind === "SERVICE" ? serviceHost(asset.address) : asset.kind === "DOMAIN" || asset.kind === "SUBDOMAIN" ? asset.address : null;
      const normalized = host && normalizeDomain(host);
      return !!normalized && normalized === host && isWithinDomain(normalized, apex);
    }
    case "IP_RANGE": {
      const cidr = parseCidr(scope.value);
      if (!cidr) return false;
      const ip = asset.kind === "SERVICE" ? serviceHost(asset.address) : asset.kind === "IP" ? asset.address : null;
      return !!ip && ipInCidr(ip, cidr);
    }
    case "CLOUD_ACCOUNT": {
      const account = parseAwsAccountScope(scope.value);
      if (!account || asset.kind !== "CLOUD_RESOURCE") return false;
      if (asset.address === scope.value) return true;
      // arn:partition:service:region:ACCOUNT:resource
      const arn = /^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):.+$/.exec(asset.address);
      return arn?.[1] === account;
    }
  }
}
