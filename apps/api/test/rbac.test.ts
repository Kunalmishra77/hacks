import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { bearer, makeApp, register } from "./helpers.js";

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

async function invite(app: FastifyInstance, token: string, orgId: string, email: string, role: string) {
  return app.inject({ method: "POST", url: `/orgs/${orgId}/invites`, headers: bearer(token), payload: { email, role } });
}

/** Registers `email` and joins `orgId` as `role` via an invite from `inviterToken`. */
async function join(app: FastifyInstance, inviterToken: string, orgId: string, email: string, role: string) {
  const inv = await invite(app, inviterToken, orgId, email, role);
  expect(inv.statusCode).toBe(201);
  const user = await register(app, email);
  const acc = await app.inject({
    method: "POST",
    url: "/invites/accept",
    headers: bearer(user.accessToken),
    payload: { token: inv.json().token },
  });
  expect(acc.statusCode).toBe(201);
  return user;
}

describe("RBAC + invites", () => {
  it("enforces the role matrix on org member endpoints", async () => {
    const ctx = await makeApp();
    app = ctx.app;
    const owner = await register(app, "owner@acme.io", "Acme");
    const orgId = owner.org!.id;

    const admin = await join(app, owner.accessToken, orgId, "admin@acme.io", "ADMIN");
    const viewer = await join(app, admin.accessToken, orgId, "viewer@acme.io", "VIEWER");

    // Admin can invite up to Admin, never Owner.
    expect((await invite(app, admin.accessToken, orgId, "a2@acme.io", "ANALYST")).statusCode).toBe(201);
    expect((await invite(app, admin.accessToken, orgId, "o2@acme.io", "OWNER")).statusCode).toBe(403);
    // Owner can invite another Owner.
    expect((await invite(app, owner.accessToken, orgId, "o3@acme.io", "OWNER")).statusCode).toBe(201);
    // Viewer can read members but not invite.
    expect((await invite(app, viewer.accessToken, orgId, "v2@acme.io", "VIEWER")).statusCode).toBe(403);
    const members = await app.inject({ method: "GET", url: `/orgs/${orgId}/members`, headers: bearer(viewer.accessToken) });
    expect(members.statusCode).toBe(200);
    expect(members.json().members.map((m: { role: string }) => m.role).sort()).toEqual(["ADMIN", "OWNER", "VIEWER"]);

    // Every invite and join is audited against the org.
    const actions = ctx.store.auditEvents.filter((e) => e.orgId === orgId).map((e) => e.action);
    expect(actions.filter((a) => a === "member.invite")).toHaveLength(4);
    expect(actions.filter((a) => a === "member.join")).toHaveLength(2);
  });

  it("isolates tenants: non-members get 404, not 403", async () => {
    ({ app } = await makeApp());
    const a = await register(app, "a@one.io", "One");
    const b = await register(app, "b@two.io", "Two");

    for (const url of [`/orgs/${a.org!.id}`, `/orgs/${a.org!.id}/members`]) {
      const res = await app.inject({ method: "GET", url, headers: bearer(b.accessToken) });
      expect(res.statusCode).toBe(404);
    }
    expect((await invite(app, b.accessToken, a.org!.id, "x@x.io", "VIEWER")).statusCode).toBe(404);
    const bad = await app.inject({ method: "GET", url: "/orgs/not-a-uuid", headers: bearer(b.accessToken) });
    expect(bad.statusCode).toBe(404);
  });

  it("requires authentication on org routes", async () => {
    ({ app } = await makeApp());
    const owner = await register(app, "o@x.io", "Xco");
    const res = await app.inject({ method: "GET", url: `/orgs/${owner.org!.id}` });
    expect(res.statusCode).toBe(401);
  });

  it("binds invites to the invited email and makes them single-use", async () => {
    ({ app } = await makeApp());
    const owner = await register(app, "o@x.io", "Xco");
    const inv = await invite(app, owner.accessToken, owner.org!.id, "invited@x.io", "ANALYST");
    const token = inv.json().token as string;

    const stranger = await register(app, "stranger@x.io");
    const wrong = await app.inject({ method: "POST", url: "/invites/accept", headers: bearer(stranger.accessToken), payload: { token } });
    expect(wrong.statusCode).toBe(403);

    const invited = await register(app, "invited@x.io");
    const ok = await app.inject({ method: "POST", url: "/invites/accept", headers: bearer(invited.accessToken), payload: { token } });
    expect(ok.statusCode).toBe(201);
    expect(ok.json()).toEqual({ orgId: owner.org!.id, role: "ANALYST" });

    const again = await app.inject({ method: "POST", url: "/invites/accept", headers: bearer(invited.accessToken), payload: { token } });
    expect(again.statusCode).toBe(400);
  });

  it("audits org creation via POST /orgs", async () => {
    const ctx = await makeApp();
    app = ctx.app;
    const u = await register(app, "solo@x.io");
    const res = await app.inject({ method: "POST", url: "/orgs", headers: bearer(u.accessToken), payload: { name: "Solo Co" } });
    expect(res.statusCode).toBe(201);
    const orgId = res.json().org.id;
    expect(ctx.store.auditEvents).toContainEqual(
      expect.objectContaining({ action: "org.create", orgId, actor: { type: "user", id: u.user.id } }),
    );
  });
});
