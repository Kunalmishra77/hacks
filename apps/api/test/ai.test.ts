import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import type { AiProvider } from "@aegis/ai";
import { buildApp } from "../src/app.js";
import { createMemoryStore } from "../src/store/memory.js";
import { createMemoryScanQueue } from "../src/queue.js";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, register, testConfig } from "./helpers.js";

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

const ADVICE_JSON = JSON.stringify({
  explanation: "An old SSH is exposed.",
  impact: "Traffic could be decrypted.",
  falsePositiveLikelihood: "low",
  falsePositiveReason: "Banner is explicit.",
  remediationSteps: ["Upgrade OpenSSH", "Restart the service"],
  confidence: "high",
});

async function setup(provider?: AiProvider) {
  const published = new Map<string, string>();
  const verifier = createVerifier({
    resolveTxt: async (h) => (published.has(h) ? [[published.get(h)!]] : []),
    fetchWellKnown: async () => "",
    assumeRoleAccount: async () => "",
  });
  const store = createMemoryStore();
  app = await buildApp({ config: testConfig, store, queue: createMemoryScanQueue(), verifier, aiProvider: provider });

  const owner = await register(app, "owner@acme.io", "Acme");
  const orgId = owner.org!.id;
  const T = owner.accessToken;
  const post = (url: string, token = T, payload?: object) => app.inject({ method: "POST", url, headers: bearer(token), payload });
  const scope = (await post(`/orgs/${orgId}/scopes`, T, { type: "DOMAIN", value: "acme.example" })).json().scope;
  published.set("acme.example", scope.verification.DNS_TXT.value);
  await post(`/orgs/${orgId}/scopes/${scope.id}/verify`, T, { method: "DNS_TXT" });
  const asset = store.raw.assets[0]!;
  const now = new Date();
  const fid = randomUUID();
  store.raw.findings.push({
    id: fid, assetId: asset.id, scanId: "s", lastScanId: "s", type: "net.exposed-service", severity: "CRITICAL" as never,
    cvss: 7.5, cveRefs: ["CVE-2016-2183"], title: "OpenSSH 7.2 exposed", evidence: { port: 22 }, remediation: "Upgrade",
    status: "OPEN" as never, epss: 0.9, kevListed: true, riskScore: 88, enrichedAt: now, aiAdvice: null, aiAdviceAt: null, aiModel: null, firstSeenAt: now, lastSeenAt: now,
  });

  async function member(email: string, role: string) {
    const inv = await post(`/orgs/${orgId}/invites`, T, { email, role });
    const u = await register(app, email);
    await post("/invites/accept", u.accessToken, { token: inv.json().token });
    return u.accessToken;
  }
  return { store, orgId, T, post, fid, member };
}

describe("AI advisory", () => {
  it("returns 501 when no AI provider is configured", async () => {
    const s = await setup(undefined);
    expect((await s.post(`/orgs/${s.orgId}/findings/${s.fid}/advise`)).statusCode).toBe(501);
  });

  it("generates advice, stores it, audits it (without the advice text), and caches it", async () => {
    const complete = vi.fn(async (_input: { system: string; user: string; maxTokens?: number }) => ADVICE_JSON);
    const provider: AiProvider = { name: "fake", model: "fake-1", complete };
    const s = await setup(provider);

    const res = await s.post(`/orgs/${s.orgId}/findings/${s.fid}/advise`);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ cached: false, model: "fake-1", advice: { confidence: "high", advisory: true } });
    expect(complete).toHaveBeenCalledOnce();
    // The prompt carried the finding; the audit did not carry the advice text.
    expect((complete.mock.calls[0]![0] as { user: string }).user).toContain("OpenSSH 7.2 exposed");
    const audit = s.store.auditEvents.at(-1);
    expect(audit).toMatchObject({ action: "finding.ai_advised", payload: { model: "fake-1" } });
    expect(JSON.stringify(audit)).not.toContain("decrypted");

    // Second call is served from cache (no second provider call).
    const again = await s.post(`/orgs/${s.orgId}/findings/${s.fid}/advise`);
    expect(again.json().cached).toBe(true);
    expect(complete).toHaveBeenCalledOnce();

    // ?refresh=1 regenerates.
    await s.post(`/orgs/${s.orgId}/findings/${s.fid}/advise?refresh=1`);
    expect(complete).toHaveBeenCalledTimes(2);
  });

  it("surfaces a provider failure as 502 and does not store advice", async () => {
    const provider: AiProvider = { name: "fake", model: "fake-1", complete: async () => { throw new Error("boom"); } };
    const s = await setup(provider);
    expect((await s.post(`/orgs/${s.orgId}/findings/${s.fid}/advise`)).statusCode).toBe(502);
    expect(s.store.raw.findings[0]!.aiAdvice).toBeNull();
  });

  it("requires Analyst+ and isolates tenants", async () => {
    const provider: AiProvider = { name: "fake", model: "fake-1", complete: async () => ADVICE_JSON };
    const s = await setup(provider);
    const viewer = await s.member("v@acme.io", "VIEWER");
    expect((await s.post(`/orgs/${s.orgId}/findings/${s.fid}/advise`, viewer)).statusCode).toBe(403);
    const other = await register(app, "eve@other.io", "Other");
    expect((await app.inject({ method: "POST", url: `/orgs/${other.org!.id}/findings/${s.fid}/advise`, headers: bearer(other.accessToken) })).statusCode).toBe(404);
  });
});
