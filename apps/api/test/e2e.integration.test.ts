// Full path on real infrastructure: API → gate → BullMQ (Redis) → worker →
// gate re-check → engine → assets in Postgres. Needs TEST_DATABASE_URL (a
// migrated Postgres) and TEST_REDIS_URL. The discovery engine runs with fake
// tools, so nothing on the internet is contacted.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PrismaClient } from "@aegis/db";
import { startEngineWorker } from "@aegis/worker-kit";
import { createDiscoveryEngine } from "@aegis/worker-discovery/engine";
import { createWebEngine } from "@aegis/worker-web/engine";
import { buildApp } from "../src/app.js";
import { createBullScanQueue } from "../src/queue.js";
import { connectRedis } from "../src/redis.js";
import { createPrismaStore } from "../src/store/prisma.js";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, PASSWORD, testConfig } from "./helpers.js";

const dbUrl = process.env.TEST_DATABASE_URL;
const redisUrl = process.env.TEST_REDIS_URL;

describe.skipIf(!dbUrl || !redisUrl)("end-to-end discovery (integration)", { timeout: 60_000 }, () => {
  let prisma: PrismaClient;
  beforeAll(() => {
    prisma = new PrismaClient({ datasources: { db: { url: dbUrl } } });
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("queues an authorized scan and a worker completes it, writing only in-scope assets", async () => {
    const redis = connectRedis(redisUrl!);
    await redis.connect();
    const queue = createBullScanQueue(redis);
    let token = "";
    const verifier = createVerifier({ resolveTxt: async () => [[token]], fetchWellKnown: async () => "", assumeRoleAccount: async () => "" });
    const app = await buildApp({ config: testConfig, store: createPrismaStore(prisma), verifier, queue });

    const suffix = Date.now();
    const apex = `e2e-${suffix}.example.com`;
    const reg = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: { email: `e2e-${suffix}@example.com`, password: PASSWORD, orgName: "E2E Co" },
    });
    const { accessToken, org } = reg.json() as { accessToken: string; org: { id: string } };
    const post = (url: string, payload?: object) => app.inject({ method: "POST", url, headers: bearer(accessToken), payload });

    const scope = (await post(`/orgs/${org.id}/scopes`, { type: "DOMAIN", value: apex })).json().scope;
    token = scope.verification.DNS_TXT.value;
    await post(`/orgs/${org.id}/scopes/${scope.id}/verify`, { method: "DNS_TXT" });
    const apexAsset = await prisma.asset.findFirstOrThrow({ where: { scopeId: scope.id } });

    const engine = createDiscoveryEngine({
      crtsh: async () => [`api.${apex}`, "evil.com", `${apex}.evil.net`],
      subfinder: async () => [`internal.${apex}`],
      resolve: async (n) =>
        n === `internal.${apex}` ? { addresses: ["10.1.2.3"] } : n.startsWith("aegis-wc-") ? null : { addresses: ["93.184.216.34"] },
      httpx: async (hosts) => hosts.map((h) => ({ host: h, port: 443, url: `https://${h}`, statusCode: 200, title: "ok", webServer: "nginx", tech: [] })),
    });
    const worker = startEngineWorker({ engine, redisUrl: redisUrl!, prisma, log: () => {} });

    try {
      const res = await post(`/orgs/${org.id}/scans`, { assetId: apexAsset.id, engine: "DISCOVERY" });
      expect(res.statusCode).toBe(201);
      const scanId = res.json().scan.id as string;

      let status = "QUEUED";
      for (let i = 0; i < 100 && (status === "QUEUED" || status === "RUNNING"); i++) {
        await new Promise((r) => setTimeout(r, 200));
        status = (await prisma.scan.findUniqueOrThrow({ where: { id: scanId } })).status;
      }
      expect(status).toBe("SUCCEEDED");

      const assets = await prisma.asset.findMany({ where: { scopeId: scope.id } });
      expect(assets.map((a) => `${a.kind} ${a.address}`).sort()).toEqual(
        [
          `DOMAIN ${apex}`,
          `SERVICE ${apex}:443`,
          `SERVICE api.${apex}:443`,
          `SUBDOMAIN api.${apex}`,
          `SUBDOMAIN internal.${apex}`, // recorded, never probed (private IP)
        ].sort(),
      );
      expect(assets.find((a) => a.address === `internal.${apex}`)!.metadata).toMatchObject({ private: true, probed: false });

      const actions = (await prisma.auditEvent.findMany({ where: { scanId }, orderBy: { createdAt: "asc" } })).map((e) => e.action);
      expect(actions).toEqual(expect.arrayContaining(["scan.authorized", "scan.requested", "scan.started", "scan.completed"]));
    } finally {
      await worker.close();
      await app.close();
      await queue.close();
      redis.disconnect();
    }
  });

  it("runs a WEB scan end-to-end and writes deduplicated findings to Postgres", async () => {
    const redis = connectRedis(redisUrl!);
    await redis.connect();
    const queue = createBullScanQueue(redis);
    let token = "";
    const verifier = createVerifier({ resolveTxt: async () => [[token]], fetchWellKnown: async () => "", assumeRoleAccount: async () => "" });
    const app = await buildApp({ config: testConfig, store: createPrismaStore(prisma), verifier, queue });

    const suffix = Date.now();
    const apex = `web-${suffix}.example.com`;
    const reg = await app.inject({ method: "POST", url: "/auth/register", payload: { email: `web-${suffix}@example.com`, password: PASSWORD, orgName: "Web Co" } });
    const { accessToken, org } = reg.json() as { accessToken: string; org: { id: string } };
    const post = (url: string, payload?: object) => app.inject({ method: "POST", url, headers: bearer(accessToken), payload });
    const scope = (await post(`/orgs/${org.id}/scopes`, { type: "DOMAIN", value: apex })).json().scope;
    token = scope.verification.DNS_TXT.value;
    await post(`/orgs/${org.id}/scopes/${scope.id}/verify`, { method: "DNS_TXT" });
    const asset = await prisma.asset.findFirstOrThrow({ where: { scopeId: scope.id } });

    // A web engine whose HTTP responses are canned: insecure site + exposed .git.
    const page = (path: string): { status: number; headers: Record<string, string>; setCookies: string[]; bodyPrefix: string } =>
      path === "/.git/HEAD"
        ? { status: 200, headers: {}, setCookies: [], bodyPrefix: "ref: refs/heads/main\n" }
        : path === "/"
          ? { status: 200, headers: { server: "nginx" }, setCookies: ["sid=abc; Path=/"], bodyPrefix: "<html>" }
          : { status: 404, headers: { "content-type": "text/html" }, setCookies: [], bodyPrefix: "<html>nope</html>" };
    const engine = createWebEngine({
      resolve: async () => ({ addresses: ["93.184.216.34"] }),
      request: async (url) => page(url.pathname),
    });
    const worker = startEngineWorker({ engine, redisUrl: redisUrl!, prisma, log: () => {} });

    try {
      const res = await post(`/orgs/${org.id}/scans`, { assetId: asset.id, engine: "WEB" });
      expect(res.statusCode).toBe(201);
      const scanId = res.json().scan.id as string;

      let status = "QUEUED";
      for (let i = 0; i < 100 && (status === "QUEUED" || status === "RUNNING"); i++) {
        await new Promise((r) => setTimeout(r, 200));
        status = (await prisma.scan.findUniqueOrThrow({ where: { id: scanId } })).status;
      }
      expect(status).toBe("SUCCEEDED");

      const findings = await app.inject({ method: "GET", url: `/orgs/${org.id}/findings`, headers: bearer(accessToken) });
      const types = findings.json().findings.map((f: { type: string }) => f.type);
      expect(types).toContain("web.exposed-git");
      expect(types).toContain("web.missing-hsts");
      expect(findings.json().summary.HIGH).toBeGreaterThanOrEqual(1);
      // No raw body or secret leaked into stored evidence.
      expect(JSON.stringify(findings.json().findings)).not.toContain("refs/heads");

      // Re-running updates in place: same fingerprints, no duplicate rows.
      const before = await prisma.finding.count({ where: { asset: { scopeId: scope.id } } });
      await prisma.scan.update({ where: { id: scanId }, data: {} });
      const res2 = await post(`/orgs/${org.id}/scans`, { assetId: asset.id, engine: "WEB" });
      const scan2 = res2.json().scan.id as string;
      let s2 = "QUEUED";
      for (let i = 0; i < 100 && (s2 === "QUEUED" || s2 === "RUNNING"); i++) {
        await new Promise((r) => setTimeout(r, 200));
        s2 = (await prisma.scan.findUniqueOrThrow({ where: { id: scan2 } })).status;
      }
      expect(await prisma.finding.count({ where: { asset: { scopeId: scope.id } } })).toBe(before);
    } finally {
      await worker.close();
      await app.close();
      await queue.close();
      redis.disconnect();
    }
  });

  it("admits at most the org's concurrency cap under parallel requests", async () => {
    let token = "";
    const verifier = createVerifier({ resolveTxt: async () => [[token]], fetchWellKnown: async () => "", assumeRoleAccount: async () => "" });
    const app = await buildApp({ config: testConfig, store: createPrismaStore(prisma), verifier });
    const suffix = Date.now();
    const reg = await app.inject({
      method: "POST",
      url: "/auth/register",
      payload: { email: `race-${suffix}@example.com`, password: PASSWORD, orgName: "Race Co" },
    });
    const { accessToken, org } = reg.json() as { accessToken: string; org: { id: string } };
    const post = (url: string, payload?: object) => app.inject({ method: "POST", url, headers: bearer(accessToken), payload });
    const scope = (await post(`/orgs/${org.id}/scopes`, { type: "DOMAIN", value: `race-${suffix}.example.com` })).json().scope;
    token = scope.verification.DNS_TXT.value;
    await post(`/orgs/${org.id}/scopes/${scope.id}/verify`, { method: "DNS_TXT" });
    const asset = await prisma.asset.findFirstOrThrow({ where: { scopeId: scope.id } });

    const codes = await Promise.all(
      Array.from({ length: 5 }, () => post(`/orgs/${org.id}/scans`, { assetId: asset.id, engine: "TLS" }).then((r) => r.statusCode)),
    );
    await app.close();
    expect(codes.filter((c) => c === 201)).toHaveLength(testConfig.gateLimits.maxConcurrentScansPerOrg);
    expect(codes.filter((c) => c === 429)).toHaveLength(5 - testConfig.gateLimits.maxConcurrentScansPerOrg);
    expect(await prisma.scan.count({ where: { orgId: org.id, status: "QUEUED" } })).toBe(3);
  });
});
