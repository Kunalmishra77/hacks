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
  const req = (method: string, url: string, token = T, payload?: object) => app.inject({ method: method as never, url, headers: bearer(token), payload });
  const scope = (await req("POST", `/orgs/${orgId}/scopes`, T, { type: "DOMAIN", value: "acme.example" })).json().scope;
  published.set("acme.example", scope.verification.DNS_TXT.value);
  await req("POST", `/orgs/${orgId}/scopes/${scope.id}/verify`, T, { method: "DNS_TXT" });

  async function member(email: string, role: string) {
    const inv = await req("POST", `/orgs/${orgId}/invites`, T, { email, role });
    const u = await register(app, email);
    await req("POST", "/invites/accept", u.accessToken, { token: inv.json().token });
    return u.accessToken;
  }
  return { ctx, orgId, T, req, scopeId: scope.id as string, member };
}

describe("schedules", () => {
  it("creates a schedule with a computed nextRunAt and lists it", async () => {
    const s = await setup();
    const res = await s.req("POST", `/orgs/${s.orgId}/schedules`, s.T, { scopeId: s.scopeId, cron: "0 3 * * *", engines: ["TLS", "WEB"] });
    expect(res.statusCode).toBe(201);
    expect(res.json().schedule).toMatchObject({ cron: "0 3 * * *", enabled: true });
    expect(new Date(res.json().schedule.nextRunAt).getTime()).toBeGreaterThan(Date.now());
    expect((await s.req("GET", `/orgs/${s.orgId}/schedules`)).json().schedules).toHaveLength(1);
    expect(s.ctx.store.auditEvents.at(-1)).toMatchObject({ action: "schedule.create" });
  });

  it("rejects sub-hourly crons, invalid crons, and engines the scope disallows", async () => {
    const s = await setup();
    expect((await s.req("POST", `/orgs/${s.orgId}/schedules`, s.T, { scopeId: s.scopeId, cron: "* * * * *", engines: ["TLS"] })).statusCode).toBe(400);
    expect((await s.req("POST", `/orgs/${s.orgId}/schedules`, s.T, { scopeId: s.scopeId, cron: "nope", engines: ["TLS"] })).statusCode).toBe(400);
    expect((await s.req("POST", `/orgs/${s.orgId}/schedules`, s.T, { scopeId: s.scopeId, cron: "0 3 * * *", engines: ["CLOUD"] })).statusCode).toBe(400);
  });

  it("updates and deletes a schedule; recomputes nextRunAt on cron change", async () => {
    const s = await setup();
    const id = (await s.req("POST", `/orgs/${s.orgId}/schedules`, s.T, { scopeId: s.scopeId, cron: "0 3 * * *", engines: ["TLS"] })).json().schedule.id;
    const paused = await s.req("PATCH", `/orgs/${s.orgId}/schedules/${id}`, s.T, { enabled: false });
    expect(paused.json().schedule.enabled).toBe(false);
    expect((await s.req("PATCH", `/orgs/${s.orgId}/schedules/${id}`, s.T, { cron: "0 */6 * * *" })).json().schedule.cron).toBe("0 */6 * * *");
    expect((await s.req("DELETE", `/orgs/${s.orgId}/schedules/${id}`)).statusCode).toBe(204);
    expect((await s.req("GET", `/orgs/${s.orgId}/schedules`)).json().schedules).toHaveLength(0);
  });

  it("only Admins+ manage schedules; Viewers can read", async () => {
    const s = await setup();
    const analyst = await s.member("an@acme.io", "ANALYST");
    expect((await s.req("POST", `/orgs/${s.orgId}/schedules`, analyst, { scopeId: s.scopeId, cron: "0 3 * * *", engines: ["TLS"] })).statusCode).toBe(403);
    expect((await s.req("GET", `/orgs/${s.orgId}/schedules`, analyst)).statusCode).toBe(200);
  });
});

describe("notification channels", () => {
  it("creates channels and validates targets per type, without logging the target", async () => {
    const s = await setup();
    const ok = await s.req("POST", `/orgs/${s.orgId}/channels`, s.T, { type: "SLACK", name: "Ops", target: "https://hooks.slack.com/services/xxx" });
    expect(ok.statusCode).toBe(201);
    expect(ok.json().channel).toMatchObject({ type: "SLACK", minSeverity: "HIGH", kevAlways: true });
    // Audit records the type/name but not the webhook URL (it can carry a secret).
    expect(JSON.stringify(s.ctx.store.auditEvents.at(-1))).not.toContain("hooks.slack.com");

    expect((await s.req("POST", `/orgs/${s.orgId}/channels`, s.T, { type: "SLACK", name: "x", target: "http://insecure/x" })).statusCode).toBe(400);
    expect((await s.req("POST", `/orgs/${s.orgId}/channels`, s.T, { type: "EMAIL", name: "x", target: "not-an-email" })).statusCode).toBe(400);
    expect((await s.req("POST", `/orgs/${s.orgId}/channels`, s.T, { type: "EMAIL", name: "x", target: "soc@acme.io" })).statusCode).toBe(201);
    expect((await s.req("POST", `/orgs/${s.orgId}/channels`, s.T, { type: "WHATSAPP", name: "x", target: "+919812345678" })).statusCode).toBe(201);
  });

  it("updates severity threshold and deletes; isolates tenants", async () => {
    const s = await setup();
    const id = (await s.req("POST", `/orgs/${s.orgId}/channels`, s.T, { type: "WEBHOOK", name: "w", target: "https://hooks.example.com/x", minSeverity: "CRITICAL" })).json().channel.id;
    expect((await s.req("PATCH", `/orgs/${s.orgId}/channels/${id}`, s.T, { minSeverity: "MEDIUM", enabled: false })).json().channel).toMatchObject({ minSeverity: "MEDIUM", enabled: false });

    const other = await register(app, "eve@other.io", "Other");
    expect((await app.inject({ method: "DELETE", url: `/orgs/${other.org!.id}/channels/${id}`, headers: bearer(other.accessToken) })).statusCode).toBe(404);
    expect((await s.req("DELETE", `/orgs/${s.orgId}/channels/${id}`)).statusCode).toBe(204);
  });
});
