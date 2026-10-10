import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { BlockedAddressError, guardedLookup, isPublicAddress } from "@aegis/core";
import { createVerifier, fetchWellKnown, type VerificationDeps } from "../src/verification/verifiers.js";

const TOKEN = "aegis-verify=abc123";

function verifierWith(deps: Partial<VerificationDeps>) {
  return createVerifier({
    resolveTxt: async () => [],
    fetchWellKnown: async () => "",
    assumeRoleAccount: async () => "000000000000",
    ...deps,
  });
}

describe("SSRF guard", () => {
  it("allows only public unicast addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]) expect(isPublicAddress(ip)).toBe(true);
    for (const ip of [
      "127.0.0.1",
      "10.1.2.3",
      "172.16.5.4",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "255.255.255.255",
      "::1",
      "::",
      "fe80::1",
      "fd00::1",
      "::ffff:127.0.0.1", // v4-mapped loopback
      "::ffff:10.0.0.1",
      "64:ff9b::a00:1", // NAT64 to 10.0.0.1
      "not-an-ip",
    ]) {
      expect(isPublicAddress(ip), ip).toBe(false);
    }
  });

  it("refuses to resolve hostnames that point at private addresses", async () => {
    const err = await new Promise<Error | null>((resolve) =>
      guardedLookup("localhost", {}, (e) => resolve(e as Error | null)),
    );
    expect(err).toBeInstanceOf(BlockedAddressError);
  });

  it("never connects to a local server, even one serving the right token", async () => {
    let hits = 0;
    const server = createServer((_req, res) => {
      hits++;
      res.end(TOKEN);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    try {
      await expect(fetchWellKnown("127.0.0.1")).rejects.toThrow(/non-public/);
      await expect(fetchWellKnown(`localhost:${port}`)).rejects.toThrow();
      expect(hits).toBe(0);
    } finally {
      server.close();
    }
  });
});

describe("ownership verifiers", () => {
  it("DNS TXT: matches the exact token, joining split TXT chunks", async () => {
    const ok = verifierWith({ resolveTxt: async () => [["v=spf1 -all"], ["aegis-verify=", "abc123"]] });
    expect(await ok.verify({ method: "DNS_TXT", host: "example.com", token: TOKEN })).toEqual({ ok: true });

    const wrong = verifierWith({ resolveTxt: async () => [["aegis-verify=abc1234"]] });
    expect((await wrong.verify({ method: "DNS_TXT", host: "example.com", token: TOKEN })).ok).toBe(false);

    const missing = verifierWith({
      resolveTxt: async () => {
        throw Object.assign(new Error("nope"), { code: "ENODATA" });
      },
    });
    expect(await missing.verify({ method: "DNS_TXT", host: "example.com", token: TOKEN })).toEqual({
      ok: false,
      reason: "TXT record not found",
    });
  });

  it("HTTP file: accepts the token on its own line only", async () => {
    const ok = verifierWith({ fetchWellKnown: async () => `# aegis\n${TOKEN}\n` });
    expect(await ok.verify({ method: "HTTP_FILE", host: "example.com", token: TOKEN })).toEqual({ ok: true });

    const embedded = verifierWith({ fetchWellKnown: async () => `<html>${TOKEN}</html>` });
    expect((await embedded.verify({ method: "HTTP_FILE", host: "example.com", token: TOKEN })).ok).toBe(false);

    const failing = verifierWith({
      fetchWellKnown: async () => {
        throw new Error("HTTP 302 (redirects are not followed)");
      },
    });
    expect(await failing.verify({ method: "HTTP_FILE", host: "example.com", token: TOKEN })).toEqual({
      ok: false,
      reason: "HTTP 302 (redirects are not followed)",
    });
  });

  it("cloud role: requires the assumed role to be in the scoped account", async () => {
    const calls: [string, string][] = [];
    const v = verifierWith({
      assumeRoleAccount: async (arn, ext) => {
        calls.push([arn, ext]);
        return "123456789012";
      },
    });
    const base = {
      method: "CLOUD_ROLE" as const,
      token: TOKEN,
      cloudRoleArn: "arn:aws:iam::123456789012:role/AegisReadOnly",
      externalId: "aegis-ext-1",
    };
    expect(await v.verify({ ...base, host: "aws:123456789012" })).toMatchObject({ ok: true });
    expect(calls).toEqual([["arn:aws:iam::123456789012:role/AegisReadOnly", "aegis-ext-1"]]);
    expect((await v.verify({ ...base, host: "aws:999999999999" })).ok).toBe(false);
    expect((await v.verify({ ...base, host: "aws:123456789012", externalId: null })).ok).toBe(false);
  });
});
