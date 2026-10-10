import { describe, expect, it } from "vitest";
import { ipInCidr, normalizeDomain, parseCidr, targetInScope } from "../src/index.js";

describe("target matching", () => {
  it("normalizes domains strictly", () => {
    expect(normalizeDomain(" Example.COM. ")).toBe("example.com");
    expect(normalizeDomain("sub.example.co.uk")).toBe("sub.example.co.uk");
    for (const bad of ["", "com", "*.example.com", "exa mple.com", "1.2.3.4", "-a.example.com", "a..b", "example.123", "x".repeat(64) + ".com"]) {
      expect(normalizeDomain(bad)).toBeNull();
    }
  });

  it("parses CIDRs and matches IPs within them", () => {
    const c = parseCidr("198.51.100.0/24")!;
    expect(ipInCidr("198.51.100.200", c)).toBe(true);
    expect(ipInCidr("198.51.101.1", c)).toBe(false);
    expect(ipInCidr("2001:db8::1", c)).toBe(false);
    expect(parseCidr("8.8.8.8")).toEqual({ address: "8.8.8.8", prefix: 32, family: "ipv4" });
    expect(parseCidr("2001:db8::/32")?.family).toBe("ipv6");
    for (const bad of ["8.8.8.8/33", "nope/24", "8.8.8.8/x", "8.8.8.8/24/1"]) expect(parseCidr(bad)).toBeNull();
  });

  it("matches only exact apex or true subdomains for domain scopes", () => {
    const scope = { type: "DOMAIN" as const, value: "example.com" };
    expect(targetInScope(scope, { kind: "DOMAIN", address: "example.com" })).toBe(true);
    expect(targetInScope(scope, { kind: "SUBDOMAIN", address: "a.b.example.com" })).toBe(true);
    expect(targetInScope(scope, { kind: "SERVICE", address: "api.example.com:443" })).toBe(true);
    expect(targetInScope(scope, { kind: "SUBDOMAIN", address: "badexample.com" })).toBe(false);
    expect(targetInScope(scope, { kind: "SUBDOMAIN", address: "example.com.evil.io" })).toBe(false);
    expect(targetInScope(scope, { kind: "SUBDOMAIN", address: "API.example.com" })).toBe(false); // not normalized
    expect(targetInScope(scope, { kind: "IP", address: "93.184.216.34" })).toBe(false);
  });

  it("matches cloud resources only in the same AWS account", () => {
    const scope = { type: "CLOUD_ACCOUNT" as const, value: "aws:123456789012" };
    expect(targetInScope(scope, { kind: "CLOUD_RESOURCE", address: "aws:123456789012" })).toBe(true);
    expect(targetInScope(scope, { kind: "CLOUD_RESOURCE", address: "arn:aws:s3:us-east-1:123456789012:bucket/x" })).toBe(true);
    expect(targetInScope(scope, { kind: "CLOUD_RESOURCE", address: "arn:aws:s3:us-east-1:999999999999:bucket/x" })).toBe(false);
    expect(targetInScope(scope, { kind: "DOMAIN", address: "aws:123456789012" })).toBe(false);
  });
});
