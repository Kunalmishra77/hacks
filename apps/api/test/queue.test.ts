import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createMemoryScanQueue, type ScanQueue } from "../src/queue.js";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, makeApp, register } from "./helpers.js";

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

async function setup(queue = createMemoryScanQueue()) {
  const published = new Map<string, string>();
  const verifier = createVerifier({
    resolveTxt: async (h) => (published.has(h) ? [[published.get(h)!]] : []),
    fetchWellKnown: async () => "",
    assumeRoleAccount: async () => "",
  });
  const ctx = await makeApp({}, { verifier, queue });
  app = ctx.app;
  const owner = await register(app, "owner@acme.io", "Acme");
  const orgId = owner.org!.id;
  const T = owner.accessToken;
  const post = (url: string, payload?: object) => app.inject({ method: "POST", url, headers: bearer(T), payload });
  const scope = (await post(`/orgs/${orgId}/scopes`, { type: "DOMAIN", value: "example.com" })).json().scope;
  published.set("example.com", scope.verification.DNS_TXT.value);
  await post(`/orgs/${orgId}/scopes/${scope.id}/verify`, { method: "DNS_TXT" });
  const assetId = ctx.store.raw.assets[0]!.id;
  return { ...ctx, queue, orgId, post, assetId, scopeId: scope.id as string };
}

describe("scan queue", () => {
  it("enqueues exactly the gate-resolved target once a scan is allowed", async () => {
    const s = await setup();
    const res = await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "DISCOVERY" });
    expect(res.statusCode).toBe(201);
    expect(s.queue.jobs).toEqual([
      { scanId: res.json().scan.id, orgId: s.orgId, assetId: s.assetId, engine: "DISCOVERY", targetAddress: "example.com" },
    ]);
  });

  it("does not enqueue rejected, throttled or pending-approval scans", async () => {
    const s = await setup();
    await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "NETWORK" }); // needs approval
    await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "CLOUD" }); // not allowed on a domain
    expect(s.queue.jobs).toEqual([]);
  });

  it("enqueues after approval", async () => {
    const s = await setup();
    const scan = (await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "NETWORK" })).json().scan;
    expect((await s.post(`/orgs/${s.orgId}/scans/${scan.id}/approve`)).statusCode).toBe(200);
    expect(s.queue.jobs.map((j) => [j.scanId, j.engine])).toEqual([[scan.id, "NETWORK"]]);
  });

  it("removes queued jobs on scan kill, kill-switch and scope revoke", async () => {
    const s = await setup();
    const a = (await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "TLS" })).json().scan;
    await s.post(`/orgs/${s.orgId}/scans/${a.id}/kill`);
    const b = (await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "TLS" })).json().scan;
    await s.post(`/orgs/${s.orgId}/kill-switch`, { engaged: true });
    await s.post(`/orgs/${s.orgId}/kill-switch`, { engaged: false });
    const c = (await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "TLS" })).json().scan;
    await s.post(`/orgs/${s.orgId}/scopes/${s.scopeId}/revoke`);
    expect(s.queue.removed).toEqual([a.id, b.id, c.id]);
  });

  it("fails the scan visibly (503) if the queue is unreachable", async () => {
    const broken: ScanQueue = {
      enqueue: async () => {
        throw new Error("ECONNREFUSED");
      },
      remove: async () => {},
      close: async () => {},
    };
    const s = await setup(broken as ReturnType<typeof createMemoryScanQueue>);
    const res = await s.post(`/orgs/${s.orgId}/scans`, { assetId: s.assetId, engine: "TLS" });
    expect(res.statusCode).toBe(503);
    expect(s.store.raw.scans[0]!.status).toBe("FAILED");
  });
});
