// Runs against a real, migrated Postgres. Skipped unless TEST_DATABASE_URL is
// set (CI provides one; locally: docker compose up -d && npm run db:deploy).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PrismaClient } from "@aegis/db";
import { buildApp } from "../src/app.js";
import { createPrismaStore } from "../src/store/prisma.js";
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
