import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { signDownloadToken, verifyDownloadToken } from "../src/security.js";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, makeApp, register, testConfig } from "./helpers.js";

describe("download token", () => {
  const key = "a-signing-key-that-is-long-enough-xxxxxxxx";
  it("round-trips a valid, unexpired token", () => {
    const id = randomUUID();
    const tok = signDownloadToken(id, Math.floor(Date.now() / 1000) + 60, key);
    expect(verifyDownloadToken(tok, key)).toBe(id);
  });
  it("rejects expired, tampered, foreign-key and malformed tokens", () => {
    const id = randomUUID();
    const exp = Math.floor(Date.now() / 1000) + 60;
    expect(verifyDownloadToken(signDownloadToken(id, Math.floor(Date.now() / 1000) - 1, key), key)).toBeNull();
    expect(verifyDownloadToken(signDownloadToken(id, exp, key), "different-key-also-long-enough-xxxxxxxx")).toBeNull();
    const tok = signDownloadToken(id, exp, key);
    expect(verifyDownloadToken(tok.slice(0, -2) + "xy", key)).toBeNull();
    expect(verifyDownloadToken(`${id}.${exp}`, key)).toBeNull();
    expect(verifyDownloadToken(`not-a-uuid.${exp}.sig`, key)).toBeNull();
  });
});

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
  const owner = await register(app, "owner@acme.io", "Acme Security");
  const orgId = owner.org!.id;
  const T = owner.accessToken;
  const post = (url: string, token = T, payload?: object) => app.inject({ method: "POST", url, headers: bearer(token), payload });
  const get = (url: string, token = T) => app.inject({ method: "GET", url, headers: bearer(token) });

  const scope = (await post(`/orgs/${orgId}/scopes`, T, { type: "DOMAIN", value: "acme.example" })).json().scope;
  published.set("acme.example", scope.verification.DNS_TXT.value);
  await post(`/orgs/${orgId}/scopes/${scope.id}/verify`, T, { method: "DNS_TXT" });
  const asset = ctx.store.raw.assets[0]!;

  const now = new Date();
  const mkf = (type: string, severity: string, status: string, risk: number | null, kev = false, evidence: object | null = null) =>
    ctx.store.raw.findings.push({
      id: randomUUID(), assetId: asset.id, scanId: "scan-x", lastScanId: "scan-x", type, severity: severity as never, cvss: null, cveRefs: [],
      title: `${type} finding`, evidence, remediation: "Do the fix.", status: status as never,
      epss: null, kevListed: kev, riskScore: risk, enrichedAt: risk === null ? null : now, firstSeenAt: now, lastSeenAt: now,
    });
  mkf("net.exposed-service", "CRITICAL", "OPEN", 88, true, { port: 22, password: "topsecret" });
  mkf("web.missing-hsts", "LOW", "OPEN", 5);
  mkf("web.no-security-txt", "INFO", "FIXED", 1);

  async function member(email: string, role: string) {
    const inv = await post(`/orgs/${orgId}/invites`, T, { email, role });
    const u = await register(app, email);
    await post("/invites/accept", u.accessToken, { token: inv.json().token });
    return u.accessToken;
  }

  return { ...ctx, orgId, T, post, get, scopeId: scope.id as string, member };
}

describe("reports", () => {
  it("generates a report snapshotting open findings, with a severity summary", async () => {
    const s = await setup();
    const res = await s.post(`/orgs/${s.orgId}/reports`, s.T);
    expect(res.statusCode).toBe(201);
    const report = res.json().report;
    expect(report.title).toContain("Acme Security");
    expect(report.summary).toMatchObject({ total: 2, kev: 1, bySeverity: { CRITICAL: 1, LOW: 1 } });
    expect(s.store.auditEvents.at(-1)).toMatchObject({ action: "report.create", payload: { findings: 2, kev: 1 } });
  });

  it("serves the report HTML in-app, self-contained and with secrets redacted", async () => {
    const s = await setup();
    const id = (await s.post(`/orgs/${s.orgId}/reports`, s.T)).json().report.id;
    const dl = await s.get(`/orgs/${s.orgId}/reports/${id}/download`);
    expect(dl.statusCode).toBe(200);
    expect(dl.headers["content-type"]).toMatch(/text\/html/);
    expect(dl.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(dl.body).toContain("<!doctype html>");
    expect(dl.body).toContain("Acme Security");
    expect(dl.body).not.toContain("topsecret"); // evidence secret redacted
    expect(dl.body).not.toMatch(/<script\b/i);
  });

  it("mints a signed share link that opens without login and expires", async () => {
    const s = await setup();
    const id = (await s.post(`/orgs/${s.orgId}/reports`, s.T)).json().report.id;
    const share = await s.post(`/orgs/${s.orgId}/reports/${id}/share`, s.T);
    expect(share.statusCode).toBe(200);
    const url = share.json().url as string;
    expect(url).toMatch(/\/reports\/download\?token=/);
    const token = new URL(url).searchParams.get("token")!;

    // No Authorization header — the token is the capability.
    const open = await app.inject({ method: "GET", url: `/reports/download?token=${token}` });
    expect(open.statusCode).toBe(200);
    expect(open.body).toContain("Acme Security");

    // A token signed with the wrong key (or expired) is refused.
    const forged = signDownloadToken(id, Math.floor(Date.now() / 1000) + 60, "some-other-key-long-enough-xxxxxxxxxxx");
    expect((await app.inject({ method: "GET", url: `/reports/download?token=${forged}` })).statusCode).toBe(403);
    const expired = signDownloadToken(id, Math.floor(Date.now() / 1000) - 1, testConfig.refreshSecret);
    expect((await app.inject({ method: "GET", url: `/reports/download?token=${expired}` })).statusCode).toBe(403);
    expect(s.store.auditEvents.some((e) => e.action === "report.shared")).toBe(true);
  });

  it("scopes a report to one boundary and lists reports", async () => {
    const s = await setup();
    const scoped = await s.post(`/orgs/${s.orgId}/reports`, s.T, { scopeId: s.scopeId });
    expect(scoped.json().report.scopeId).toBe(s.scopeId);
    expect(scoped.json().report.summary.scopeLabel).toBe("acme.example");
    const list = await s.get(`/orgs/${s.orgId}/reports`);
    expect(list.json().reports.length).toBe(1);
  });

  it("enforces roles and tenant isolation", async () => {
    const s = await setup();
    const viewer = await s.member("v@acme.io", "VIEWER");
    // Viewer can read/list but not generate or share.
    expect((await s.post(`/orgs/${s.orgId}/reports`, viewer)).statusCode).toBe(403);
    const id = (await s.post(`/orgs/${s.orgId}/reports`, s.T)).json().report.id;
    expect((await s.get(`/orgs/${s.orgId}/reports`, viewer)).statusCode).toBe(200);
    expect((await s.post(`/orgs/${s.orgId}/reports/${id}/share`, viewer)).statusCode).toBe(403);

    const other = await register(app, "eve@other.io", "Other");
    expect((await app.inject({ method: "GET", url: `/orgs/${other.org!.id}/reports/${id}/download`, headers: bearer(other.accessToken) })).statusCode).toBe(404);
  });
});
