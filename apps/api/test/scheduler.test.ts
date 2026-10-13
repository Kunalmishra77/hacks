import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createScopeGate, createMemoryRateLimiter, createAuditLogger } from "@aegis/core";
import { createMemoryScanQueue } from "../src/queue.js";
import { runDueSchedules } from "../src/scheduler.js";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, makeApp, register, testConfig } from "./helpers.js";

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
  const post = (url: string, payload?: object) => app.inject({ method: "POST", url, headers: bearer(T), payload });
  const scope = (await post(`/orgs/${orgId}/scopes`, { type: "DOMAIN", value: "acme.example" })).json().scope;
  published.set("acme.example", scope.verification.DNS_TXT.value);
  await post(`/orgs/${orgId}/scopes/${scope.id}/verify`, { method: "DNS_TXT" });
  // Add a couple of discovered assets so TLS/WEB have targets.
  const now = new Date();
  await ctx.store.assets.upsert({ scopeId: scope.id, kind: "SERVICE", address: "acme.example:443", at: now });
  await ctx.store.assets.upsert({ scopeId: scope.id, kind: "SUBDOMAIN", address: "api.acme.example", at: now });

  const queue = ctx.queue;
  const gate = createScopeGate({ repo: ctx.store.gate, limiter: createMemoryRateLimiter(), audit: createAuditLogger(ctx.store.audit) });
  const deps = { store: ctx.store, gate, queue, config: testConfig, log: () => {} };
  return { ctx, orgId, T, post, scopeId: scope.id as string, ownerId: owner.user.id, deps };
}

describe("runDueSchedules", () => {
  it("runs a due schedule through the gate, queues scans, and advances nextRunAt", async () => {
    const s = await setup();
    const past = new Date(Date.now() - 60_000);
    const sched = await s.ctx.store.schedules.create({
      orgId: s.orgId, scopeId: s.scopeId, cron: "0 3 * * *", engines: ["TLS", "WEB"], createdById: s.ownerId, nextRunAt: past,
    });

    const summary = await runDueSchedules(s.deps, new Date());
    expect(summary.schedulesRun).toBe(1);
    expect(s.ctx.queue.jobs.length).toBeGreaterThan(0);
    // Every queued job is a TLS or WEB scan on an in-scope asset.
    expect(s.ctx.queue.jobs.every((j) => j.engine === "TLS" || j.engine === "WEB")).toBe(true);
    // nextRunAt advanced into the future.
    const after = await s.ctx.store.schedules.find(s.orgId, sched.id);
    expect(after!.nextRunAt!.getTime()).toBeGreaterThan(Date.now());
    expect(after!.lastRunAt).not.toBeNull();
  });

  it("holds approval-gated NETWORK scans instead of queuing them", async () => {
    const s = await setup();
    await s.ctx.store.schedules.create({
      orgId: s.orgId, scopeId: s.scopeId, cron: "0 3 * * *", engines: ["NETWORK"], createdById: s.ownerId, nextRunAt: new Date(Date.now() - 1000),
    });
    const summary = await runDueSchedules(s.deps, new Date());
    expect(summary.pendingApproval).toBeGreaterThan(0);
    expect(s.ctx.queue.jobs).toEqual([]); // nothing queued; all awaiting approval
    expect(s.ctx.store.raw.scans.every((sc) => sc.status === "PENDING_APPROVAL")).toBe(true);
  });

  it("does not run a schedule that isn't due yet", async () => {
    const s = await setup();
    await s.ctx.store.schedules.create({
      orgId: s.orgId, scopeId: s.scopeId, cron: "0 3 * * *", engines: ["TLS"], createdById: s.ownerId, nextRunAt: new Date(Date.now() + 3_600_000),
    });
    const summary = await runDueSchedules(s.deps, new Date());
    expect(summary.schedulesRun).toBe(0);
    expect(s.ctx.queue.jobs).toEqual([]);
  });

  it("skips scans when the org kill-switch is engaged, but still advances the schedule", async () => {
    const s = await setup();
    const sched = await s.ctx.store.schedules.create({
      orgId: s.orgId, scopeId: s.scopeId, cron: "0 3 * * *", engines: ["TLS"], createdById: s.ownerId, nextRunAt: new Date(Date.now() - 1000),
    });
    await s.ctx.store.orgs.setKillSwitch(s.orgId, true, s.ownerId, new Date());
    const summary = await runDueSchedules(s.deps, new Date());
    expect(s.ctx.queue.jobs).toEqual([]);
    expect(summary.denied).toBeGreaterThan(0);
    const after = await s.ctx.store.schedules.find(s.orgId, sched.id);
    expect(after!.nextRunAt!.getTime()).toBeGreaterThan(Date.now()); // still rescheduled
  });
});
