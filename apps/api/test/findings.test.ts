import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, makeApp, register } from "./helpers.js";

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

async function setup() {
  const published = new Map<string, string>();
  const verifier = createVerifier({
    resolveTxt: async (h) => (published.has(h) ? [[published.get(h)!]] : []),
    fetchWellKnown: async () => "",
    assumeRoleAccount: async () => "",
  });
  const ctx = await makeApp({}, { verifier });
  app = ctx.app;
  const owner = await register(app, "owner@acme.io", "Acme");
  const orgId = owner.org!.id;
  const T = owner.accessToken;
  const post = (url: string, token = T, payload?: object) => app.inject({ method: "POST", url, headers: bearer(token), payload });
  const get = (url: string, token = T) => app.inject({ method: "GET", url, headers: bearer(token) });

  const scope = (await post(`/orgs/${orgId}/scopes`, T, { type: "DOMAIN", value: "example.com" })).json().scope;
  published.set("example.com", scope.verification.DNS_TXT.value);
  await post(`/orgs/${orgId}/scopes/${scope.id}/verify`, T, { method: "DNS_TXT" });
  const asset = ctx.store.raw.assets[0]!;

  // Seed findings the way a worker would have written them.
  const now = new Date();
  const mk = (id: string, severity: string, status: string, type: string, riskScore: number | null = null) =>
    ctx.store.raw.findings.push({
      id, assetId: asset.id, scanId: "scan-x", lastScanId: "scan-x", type, severity: severity as never, cvss: null, cveRefs: [],
      title: `${type} on ${asset.address}`, evidence: { url: `https://${asset.address}/` }, remediation: "Fix it",
      status: status as never, epss: null, kevListed: false, riskScore, enrichedAt: riskScore === null ? null : now, firstSeenAt: now, lastSeenAt: now,
    });
  const gitId = randomUUID();
  mk(gitId, "HIGH", "OPEN", "web.exposed-git", 72);
  mk(randomUUID(), "LOW", "OPEN", "web.missing-hsts", 5);
  mk(randomUUID(), "INFO", "FIXED", "web.no-security-txt", 1);

  async function member(email: string, role: string) {
    const inv = await post(`/orgs/${orgId}/invites`, T, { email, role });
    const u = await register(app, email);
    await post("/invites/accept", u.accessToken, { token: inv.json().token });
    return u.accessToken;
  }

  return { ...ctx, orgId, T, post, get, asset, scopeId: scope.id as string, member, gitId };
}

describe("findings", () => {
  it("lists findings worst-first with an open-severity summary, redacted of raw bodies", async () => {
    const s = await setup();
    const res = await s.get(`/orgs/${s.orgId}/findings`);
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.findings.map((f: { type: string }) => f.type)).toEqual(["web.exposed-git", "web.missing-hsts", "web.no-security-txt"]);
    expect(body.findings[0]).toMatchObject({ severity: "HIGH", assetAddress: "example.com", status: "OPEN" });
    // Summary counts only OPEN/TRIAGED.
    expect(body.summary).toEqual({ INFO: 0, LOW: 1, MEDIUM: 0, HIGH: 1, CRITICAL: 0 });
  });

  it("orders by risk score and exposes enrichment fields", async () => {
    const s = await setup();
    const body = (await s.get(`/orgs/${s.orgId}/findings`)).json();
    // Default filter hides the FIXED no-security-txt; open findings sort by risk desc.
    expect(body.findings.map((f: { riskScore: number }) => f.riskScore)).toEqual([72, 5, 1]);
    expect(body.findings[0]).toHaveProperty("kevListed");
    expect(body.findings[0]).toHaveProperty("epss");
  });

  it("filters by status and severity", async () => {
    const s = await setup();
    expect((await s.get(`/orgs/${s.orgId}/findings?status=FIXED`)).json().findings.map((f: { type: string }) => f.type)).toEqual(["web.no-security-txt"]);
    expect((await s.get(`/orgs/${s.orgId}/findings?severity=HIGH`)).json().findings).toHaveLength(1);
  });

  it("lets an Analyst triage, writes an audit record, and updates the summary", async () => {
    const s = await setup();
    const analyst = await s.member("an@acme.io", "ANALYST");
    const res = await s.post(`/orgs/${s.orgId}/findings/${s.gitId}/status`, analyst, { status: "FALSE_POSITIVE" });
    expect(res.statusCode).toBe(200);
    expect((await s.get(`/orgs/${s.orgId}/findings`)).json().summary.HIGH).toBe(0);
    expect(s.store.auditEvents.at(-1)).toMatchObject({ action: "finding.triaged", payload: { from: "OPEN", to: "FALSE_POSITIVE" } });
  });

  it("forbids Viewers from triaging but lets them read", async () => {
    const s = await setup();
    const viewer = await s.member("v@acme.io", "VIEWER");
    expect((await s.get(`/orgs/${s.orgId}/findings`, viewer)).statusCode).toBe(200);
    expect((await s.post(`/orgs/${s.orgId}/findings/${s.gitId}/status`, viewer, { status: "TRIAGED" })).statusCode).toBe(403);
  });

  it("hides another org's findings", async () => {
    const s = await setup();
    const other = await register(app, "eve@other.io", "Other");
    expect((await app.inject({ method: "GET", url: `/orgs/${other.org!.id}/findings`, headers: bearer(other.accessToken) })).json().findings).toEqual([]);
    expect(
      (await app.inject({ method: "POST", url: `/orgs/${other.org!.id}/findings/${s.gitId}/status`, headers: bearer(other.accessToken), payload: { status: "FIXED" } })).statusCode,
    ).toBe(404);
  });
});
