// Runs against a real, migrated Postgres. Skipped unless TEST_DATABASE_URL is
// set (CI provides one; locally: docker compose up -d && npm run db:deploy).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PrismaClient } from "@aegis/db";
import { buildApp } from "../src/app.js";
import { createPrismaStore } from "../src/store/prisma.js";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, PASSWORD, testConfig } from "./helpers.js";

const url = process.env.TEST_DATABASE_URL;

describe.skipIf(!url)("prisma store (integration)", { timeout: 30_000 }, () => {
  let prisma: PrismaClient;

  beforeAll(() => {
    prisma = new PrismaClient({ datasources: { db: { url } } });
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("runs register → login → invite end-to-end and persists audit rows", async () => {
    const app = await buildApp({ config: testConfig, store: createPrismaStore(prisma) });
    const suffix = Date.now();
    const email = `owner-${suffix}@example.com`;

    const reg = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: { email, password: PASSWORD, orgName: "Integration Co" },
    });
    expect(reg.statusCode).toBe(201);
    const { accessToken, org } = reg.json() as { accessToken: string; org: { id: string } };

    const login = await app.inject({ method: "POST", url: "/auth/login", payload: { email, password: PASSWORD } });
    expect(login.statusCode).toBe(200);

    const inv = await app.inject({
      method: "POST",
      url: `/orgs/${org.id}/invites`,
      headers: bearer(accessToken),
      payload: { email: `analyst-${suffix}@example.com`, role: "ANALYST" },
    });
    expect(inv.statusCode).toBe(201);
    await app.close();

    const actions = (await prisma.auditEvent.findMany({ where: { orgId: org.id }, orderBy: { createdAt: "asc" } })).map(
      (e) => e.action,
    );
    expect(actions).toEqual(["org.create", "member.invite"]);
  });

  it("runs scope → verify → scan → kill-switch through the gate on Postgres", async () => {
    const verifier = createVerifier({
      resolveTxt: async () => [[token]],
      fetchWellKnown: async () => "",
      assumeRoleAccount: async () => "",
    });
    let token = "";
    const app = await buildApp({ config: testConfig, store: createPrismaStore(prisma), verifier });
    const suffix = Date.now();
    const reg = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: { email: `gate-${suffix}@example.com`, password: PASSWORD, orgName: "Gate Co" },
    });
    const { accessToken, org } = reg.json() as { accessToken: string; org: { id: string } };
    const post = (url: string, payload?: object) =>
      app.inject({ method: "POST", url, headers: bearer(accessToken), payload });

    const scope = (await post(`/orgs/${org.id}/scopes`, { type: "DOMAIN", value: `gate-${suffix}.example.com` })).json().scope;
    token = scope.verification.DNS_TXT.value;
    expect((await post(`/orgs/${org.id}/scopes/${scope.id}/verify`, { method: "DNS_TXT" })).statusCode).toBe(200);
    const asset = await prisma.asset.findFirstOrThrow({ where: { scopeId: scope.id } });

    const scan = await post(`/orgs/${org.id}/scans`, { assetId: asset.id, engine: "TLS" });
    expect(scan.statusCode).toBe(201);
    const scanId = scan.json().scan.id as string;
    expect(
      await app.scopeGate.authorize({
        mode: "job_start",
        orgId: org.id,
        scanId,
        assetId: asset.id,
        engine: "TLS",
        targetAddress: asset.address,
        actor: { type: "system" },
      }),
    ).toMatchObject({ decision: "ALLOW" });

    expect((await post(`/orgs/${org.id}/kill-switch`, { engaged: true })).json()).toEqual({
      killSwitchEngaged: true,
      killedScans: 1,
    });
    expect((await prisma.scan.findUniqueOrThrow({ where: { id: scanId } })).status).toBe("KILLED");
    await app.close();

    const actions = (await prisma.auditEvent.findMany({ where: { orgId: org.id }, orderBy: { createdAt: "asc" } })).map(
      (e) => e.action,
    );
    expect(actions).toEqual(
      expect.arrayContaining(["scope.create", "scope.verify", "scan.authorized", "scan.requested", "killswitch.engaged"]),
    );
  });

  it("generates a report, stores it, and serves it by signed link on Postgres", async () => {
    let token = "";
    const verifier = createVerifier({ resolveTxt: async () => [[token]], fetchWellKnown: async () => "", assumeRoleAccount: async () => "" });
    const app = await buildApp({ config: testConfig, store: createPrismaStore(prisma), verifier });
    const suffix = Date.now();
    const reg = await app.inject({ method: "POST", url: "/auth/register", payload: { email: `rep-${suffix}@example.com`, password: PASSWORD, orgName: "Report Co" } });
    const { accessToken, org } = reg.json() as { accessToken: string; org: { id: string } };
    const post = (url: string, payload?: object) => app.inject({ method: "POST", url, headers: bearer(accessToken), payload });

    const scope = (await post(`/orgs/${org.id}/scopes`, { type: "DOMAIN", value: `rep-${suffix}.example.com` })).json().scope;
    token = scope.verification.DNS_TXT.value;
    await post(`/orgs/${org.id}/scopes/${scope.id}/verify`, { method: "DNS_TXT" });
    const asset = await prisma.asset.findFirstOrThrow({ where: { scopeId: scope.id } });
    await prisma.finding.create({
      data: { assetId: asset.id, scanId: (await prisma.scan.create({ data: { orgId: org.id, scopeId: scope.id, assetId: asset.id, engine: "WEB", status: "SUCCEEDED", requestedById: reg.json().user.id } })).id,
        fingerprint: "fp-rep-1", type: "web.exposed-git", severity: "HIGH", title: "Git exposed", remediation: "Block it", status: "OPEN", cveRefs: [], riskScore: 58 },
    });

    const gen = await post(`/orgs/${org.id}/reports`);
    expect(gen.statusCode).toBe(201);
    const reportId = gen.json().report.id as string;
    expect(gen.json().report.summary.total).toBe(1);

    const stored = await prisma.report.findUniqueOrThrow({ where: { id: reportId } });
    expect(stored.content).toContain("<!doctype html>");
    expect(stored.byteSize).toBeGreaterThan(0);

    const share = await post(`/orgs/${org.id}/reports/${reportId}/share`);
    const shareToken = new URL(share.json().url).searchParams.get("token")!;
    const open = await app.inject({ method: "GET", url: `/reports/download?token=${shareToken}` });
    expect(open.statusCode).toBe(200);
    expect(open.body).toContain("Git exposed");
    await app.close();

    const actions = (await prisma.auditEvent.findMany({ where: { orgId: org.id } })).map((e) => e.action);
    expect(actions).toEqual(expect.arrayContaining(["report.create", "report.shared"]));
  });

  it("rejects UPDATE, DELETE and TRUNCATE on AuditEvent at the database level", async () => {
    const ev = await prisma.auditEvent.create({ data: { actorType: "system", action: "auth.login" } });

    await expect(prisma.auditEvent.update({ where: { id: ev.id }, data: { action: "tampered" } })).rejects.toThrow(
      /append-only/,
    );
    await expect(prisma.auditEvent.delete({ where: { id: ev.id } })).rejects.toThrow(/append-only/);
    await expect(prisma.$executeRawUnsafe('TRUNCATE "AuditEvent"')).rejects.toThrow(/append-only/);

    const still = await prisma.auditEvent.findUnique({ where: { id: ev.id } });
    expect(still?.action).toBe("auth.login");
  });
});
