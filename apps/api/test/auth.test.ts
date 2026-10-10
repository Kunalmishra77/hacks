import { SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { REFRESH_COOKIE } from "../src/routes/auth.js";
import { bearer, makeApp, PASSWORD, refreshCookie, register, testConfig } from "./helpers.js";

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

describe("auth", () => {
  it("registers a user + org, stores an argon2id hash, and audits both", async () => {
    const ctx = await makeApp();
    app = ctx.app;
    const reg = await register(app, "Alice@Example.com", "Acme");

    expect(reg.org).toMatchObject({ id: expect.any(String) });
    const stored = await ctx.store.users.findByEmail("alice@example.com");
    expect(stored?.passwordHash).toMatch(/^\$argon2id\$/);
    expect(stored?.passwordHash).not.toContain(PASSWORD);

    const me = await app.inject({ method: "GET", url: "/auth/me", headers: bearer(reg.accessToken) });
    expect(me.statusCode).toBe(200);
    expect(me.json()).toMatchObject({
      user: { email: "alice@example.com" },
      memberships: [{ orgId: reg.org!.id, role: "OWNER" }],
    });

    expect(ctx.store.auditEvents.map((e) => e.action)).toEqual(["auth.register", "org.create"]);
    expect(ctx.store.auditEvents[1]).toMatchObject({ orgId: reg.org!.id, actor: { type: "user", id: reg.user.id } });
  });

  it("rejects weak passwords and duplicate emails", async () => {
    ({ app } = await makeApp());
    const weak = await app.inject({ method: "POST", url: "/auth/register", payload: { email: "a@x.io", password: "short" } });
    expect(weak.statusCode).toBe(400);

    await register(app, "dup@x.io");
    const dup = await app.inject({ method: "POST", url: "/auth/register", payload: { email: "DUP@x.io", password: PASSWORD } });
    expect(dup.statusCode).toBe(409);
  });

  it("logs in, sets an httpOnly refresh cookie scoped to /auth, and audits the login", async () => {
    const ctx = await makeApp();
    app = ctx.app;
    await register(app, "bob@x.io");

    const res = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "bob@x.io", password: PASSWORD } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ accessToken: expect.any(String), user: { email: "bob@x.io" } });
    const cookie = res.cookies.find((c) => c.name === REFRESH_COOKIE);
    expect(cookie).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/auth" });
    expect(res.body).not.toContain(cookie!.value); // refresh token never in the body
    expect(ctx.store.auditEvents.at(-1)).toMatchObject({ action: "auth.login", actor: { type: "user" } });
  });

  it("gives the same 401 for bad password and unknown user, and audits both without the password", async () => {
    const ctx = await makeApp();
    app = ctx.app;
    await register(app, "carol@x.io");

    const bad = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "carol@x.io", password: "wrong-password-123" } });
    const unknown = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "nobody@x.io", password: "wrong-password-123" } });
    expect(bad.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(bad.json()).toEqual(unknown.json());

    const failed = ctx.store.auditEvents.filter((e) => e.action === "auth.login_failed");
    expect(failed).toHaveLength(2);
    expect(failed[1]!.actor).toEqual({ type: "anonymous" });
    expect(JSON.stringify(failed)).not.toContain("wrong-password-123");
  });

  it("rejects missing, malformed, and foreign-signed access tokens", async () => {
    ({ app } = await makeApp());
    const { user } = await register(app, "dan@x.io");

    const forged = await new SignJWT({ typ: "access" })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(user.id)
      .setIssuer(testConfig.jwtIssuer)
      .setAudience("aegis")
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode("some-other-secret-that-is-long-enough-xxxxx"));

    for (const headers of [{}, bearer("not-a-jwt"), bearer(forged)]) {
      const res = await app.inject({ method: "GET", url: "/auth/me", headers });
      expect(res.statusCode).toBe(401);
    }
  });

  it("rotates refresh tokens and revokes the family when an old one is replayed", async () => {
    const ctx = await makeApp();
    app = ctx.app;
    const { refresh: first } = await register(app, "erin@x.io");
    expect(first).toBeDefined();

    const r1 = await app.inject({ method: "POST", url: "/auth/refresh", cookies: { [REFRESH_COOKIE]: first! } });
    expect(r1.statusCode).toBe(200);
    const second = refreshCookie(r1);
    expect(second).toBeDefined();
    expect(second).not.toBe(first);

    // Replaying the first token is treated as theft…
    const replay = await app.inject({ method: "POST", url: "/auth/refresh", cookies: { [REFRESH_COOKIE]: first! } });
    expect(replay.statusCode).toBe(401);
    expect(ctx.store.auditEvents.some((e) => e.action === "auth.refresh_reuse_detected")).toBe(true);

    // …so the legitimate successor is revoked too.
    const r2 = await app.inject({ method: "POST", url: "/auth/refresh", cookies: { [REFRESH_COOKIE]: second! } });
    expect(r2.statusCode).toBe(401);
  });

  it("logout revokes the refresh token", async () => {
    ({ app } = await makeApp());
    const { refresh } = await register(app, "fay@x.io");
    const out = await app.inject({ method: "POST", url: "/auth/logout", cookies: { [REFRESH_COOKIE]: refresh! } });
    expect(out.statusCode).toBe(204);
    const after = await app.inject({ method: "POST", url: "/auth/refresh", cookies: { [REFRESH_COOKIE]: refresh! } });
    expect(after.statusCode).toBe(401);
  });

  it("rate-limits credential endpoints", async () => {
    ({ app } = await makeApp({ authRateLimit: { max: 3, timeWindowMs: 60_000 } }));
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await app.inject({ method: "POST", url: "/auth/login", payload: { email: "x@x.io", password: "whatever-123456" } });
      codes.push(res.statusCode);
    }
    expect(codes).toEqual([401, 401, 401, 429]);
  });
});
