import { describe, expect, it } from "vitest";
import { findingFingerprint, sanitizeEvidence } from "../src/index.js";

describe("findings", () => {
  it("fingerprints are stable per engine/type/key and differ otherwise", () => {
    const a = findingFingerprint("WEB", "web.insecure-cookie", "session");
    expect(findingFingerprint("WEB", "web.insecure-cookie", "session")).toBe(a);
    expect(findingFingerprint("WEB", "web.insecure-cookie", "csrf")).not.toBe(a);
    expect(findingFingerprint("TLS", "web.insecure-cookie", "session")).not.toBe(a);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("redacts secrets, bodies and extracted values from evidence", () => {
    expect(
      sanitizeEvidence({
        path: "/.env",
        status: 200,
        body: "DB_PASSWORD=hunter2",
        extractedResults: ["AKIA..."],
        headers: { "set-cookie": "sid=abc", server: "nginx" },
        apiKey: "x",
      }),
    ).toEqual({
      path: "/.env",
      status: 200,
      body: "[REDACTED]",
      extractedResults: "[REDACTED]",
      headers: { "set-cookie": "[REDACTED]", server: "nginx" },
      apiKey: "[REDACTED]",
    });
  });

  it("truncates long strings and caps total size", () => {
    const e = sanitizeEvidence({ title: "x".repeat(2000) })!;
    expect((e.title as string).length).toBeLessThanOrEqual(501);
    const huge = sanitizeEvidence(Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`k${i}`, "y".repeat(400)])))!;
    expect(huge.truncated).toBe(true);
    expect(sanitizeEvidence(undefined)).toBeNull();
  });
});
