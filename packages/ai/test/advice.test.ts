import { describe, expect, it, vi } from "vitest";
import { adviseFinding, buildAdvicePrompt, parseAdvice, type AdviceFinding, type AiProvider } from "../src/index.js";

const finding: AdviceFinding = {
  type: "net.exposed-service",
  severity: "CRITICAL",
  title: "OpenSSH 7.2 is affected by a known-exploited vulnerability",
  assetAddress: "api.example.com:22",
  cveRefs: ["CVE-2016-2183"],
  cvss: 7.5,
  epss: 0.95,
  kevListed: true,
  riskScore: 88,
  remediation: "Upgrade OpenSSH.",
  evidence: { ip: "93.184.216.34", port: 22, service: "ssh", version: "OpenSSH 7.2" },
};

describe("buildAdvicePrompt", () => {
  it("frames finding data as untrusted and forbids actioning model output", () => {
    const { system, user } = buildAdvicePrompt(finding);
    expect(system).toMatch(/advisor/i);
    expect(system).toMatch(/do not (run|execute|perform)|never.*(scan|command)/i);
    expect(system).toMatch(/untrusted|data, not instructions/i);
    // The finding is wrapped so injected instructions in evidence can't be followed.
    expect(user).toContain("api.example.com:22");
    expect(user).toContain("CVE-2016-2183");
    expect(user).toMatch(/<finding>[\s\S]*<\/finding>/);
  });

  it("does not instruct the model to emit shell commands or scan targets", () => {
    const { system } = buildAdvicePrompt(finding);
    expect(system).not.toMatch(/\bnmap\b|\bcurl\b|run this command/i);
  });
});

describe("parseAdvice", () => {
  it("parses a well-formed JSON advice object", () => {
    const raw = JSON.stringify({
      explanation: "SSH is old and exploitable.",
      impact: "An attacker could intercept traffic.",
      falsePositiveLikelihood: "low",
      falsePositiveReason: "Banner clearly shows 7.2.",
      remediationSteps: ["Upgrade OpenSSH", "Restart sshd"],
      confidence: "high",
    });
    const a = parseAdvice(raw);
    expect(a).toMatchObject({ falsePositiveLikelihood: "low", confidence: "high" });
    expect(a.remediationSteps).toHaveLength(2);
  });

  it("extracts JSON even when wrapped in prose or code fences", () => {
    const raw = "Here is my analysis:\n```json\n{\"explanation\":\"x\",\"impact\":\"y\",\"falsePositiveLikelihood\":\"medium\",\"confidence\":\"medium\",\"remediationSteps\":[\"do z\"]}\n```\nHope that helps!";
    expect(parseAdvice(raw)).toMatchObject({ explanation: "x", falsePositiveLikelihood: "medium" });
  });

  it("falls back to treating free text as the explanation when JSON is absent", () => {
    const a = parseAdvice("This looks like a real issue; patch SSH.");
    expect(a.explanation).toContain("patch SSH");
    expect(a.confidence).toBe("low");
    expect(a.falsePositiveLikelihood).toBe("unknown");
  });

  it("clamps unknown enum values and caps list lengths", () => {
    const a = parseAdvice(JSON.stringify({ explanation: "x", falsePositiveLikelihood: "maybe", confidence: "VERY", remediationSteps: Array(50).fill("step") }));
    expect(a.falsePositiveLikelihood).toBe("unknown");
    expect(a.confidence).toBe("low");
    expect(a.remediationSteps.length).toBeLessThanOrEqual(10);
  });
});

describe("adviseFinding", () => {
  it("calls the provider and returns parsed, labeled advice", async () => {
    const provider: AiProvider = {
      name: "fake",
      model: "fake-1",
      complete: vi.fn(async () => JSON.stringify({ explanation: "e", impact: "i", falsePositiveLikelihood: "low", confidence: "high", remediationSteps: ["s"] })),
    };
    const advice = await adviseFinding(provider, finding);
    expect(provider.complete).toHaveBeenCalledOnce();
    expect(advice).toMatchObject({ explanation: "e", confidence: "high", model: "fake-1" });
    expect(advice.advisory).toBe(true);
  });

  it("surfaces provider errors", async () => {
    const provider: AiProvider = { name: "fake", model: "fake-1", complete: async () => { throw new Error("rate limited"); } };
    await expect(adviseFinding(provider, finding)).rejects.toThrow("rate limited");
  });
});
