import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { createAuditLogger } from "@aegis/core";
import type { AppConfig } from "../config.js";
import {
  burnPasswordCheck,
  hashOpaqueToken,
  hashPassword,
  newOpaqueToken,
  signAccessToken,
  verifyPassword,
} from "../security.js";
import type { Store, UserRecord } from "../store/types.js";
import { createOrgWithOwner } from "./orgs.js";
import { requestContext } from "./context.js";

export const REFRESH_COOKIE = "aegis_rt";

const Email = z.string().trim().toLowerCase().email().max(254);
// Length-based policy (NIST 800-63B); no composition rules.
const Password = z.string().min(12, "at least 12 characters").max(128);

const RegisterBody = z.object({
  email: Email,
  password: Password,
  name: z.string().trim().min(1).max(100).optional(),
  // Omit when joining an existing org through an invite.
  orgName: z.string().trim().min(2).max(100).optional(),
});

const LoginBody = z.object({
  email: Email,
  password: z.string().min(1).max(128),
});

export function publicUser(u: UserRecord) {
  return { id: u.id, email: u.email, name: u.name };
}

export async function authRoutes(app: FastifyInstance, opts: { config: AppConfig; store: Store }) {
  const { config, store } = opts;
  const credentialLimit = {
    rateLimit: { max: config.authRateLimit.max, timeWindow: config.authRateLimit.timeWindowMs },
  };

  /** Creates a refresh token in `familyId`, sets the cookie, returns an access token. */
  async function issueSession(tx: Store, reply: FastifyReply, userId: string, familyId: string = randomUUID()) {
    const refresh = newOpaqueToken();
    const expiresAt = new Date(Date.now() + config.refreshTokenTtlDays * 86_400_000);
    const record = await tx.refreshTokens.create({
      userId,
      familyId,
      tokenHash: hashOpaqueToken(refresh, config.refreshSecret),
      expiresAt,
    });
    reply.setCookie(REFRESH_COOKIE, refresh, {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: "strict",
      path: "/auth",
      expires: expiresAt,
    });
    const accessToken = await signAccessToken(userId, {
      secret: config.jwtSecret,
      issuer: config.jwtIssuer,
      ttlSeconds: config.accessTokenTtlSeconds,
    });
    return { record, accessToken };
  }

  function clearRefreshCookie(reply: FastifyReply) {
    reply.clearCookie(REFRESH_COOKIE, { path: "/auth" });
  }

  app.post("/auth/register", { config: credentialLimit }, async (req, reply) => {
    const body = RegisterBody.parse(req.body);
    const passwordHash = await hashPassword(body.password);
    const ctx = requestContext(req);

    const result = await store.transaction(async (tx) => {
      const audit = createAuditLogger(tx.audit);
      const user = await tx.users.create({ email: body.email, name: body.name ?? null, passwordHash });
      await audit.record({ action: "auth.register", actor: { type: "user", id: user.id }, targetId: user.id, ...ctx });
      const org = body.orgName ? await createOrgWithOwner(tx, user.id, body.orgName, ctx) : null;
      const session = await issueSession(tx, reply, user.id);
      return { user, org, accessToken: session.accessToken };
    });

    return reply.code(201).send({
      user: publicUser(result.user),
      org: result.org,
      accessToken: result.accessToken,
      expiresIn: config.accessTokenTtlSeconds,
    });
  });

  app.post("/auth/login", { config: credentialLimit }, async (req, reply) => {
    const body = LoginBody.parse(req.body);
    const ctx = requestContext(req);
    const audit = createAuditLogger(store.audit);

    const user = await store.users.findByEmail(body.email);
    const ok = user ? await verifyPassword(user.passwordHash, body.password) : (await burnPasswordCheck(body.password), false);

    if (!user || !ok || user.disabledAt) {
      await audit.record({
        action: "auth.login_failed",
        actor: user ? { type: "user", id: user.id } : { type: "anonymous" },
        payload: { email: body.email, reason: !user ? "unknown_user" : user.disabledAt ? "disabled" : "bad_password" },
        ...ctx,
      });
      // Same response for every failure so accounts can't be enumerated.
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    const now = new Date();
    const session = await store.transaction(async (tx) => {
      await tx.users.touchLogin(user.id, now);
      await createAuditLogger(tx.audit).record({ action: "auth.login", actor: { type: "user", id: user.id }, ...ctx });
      return issueSession(tx, reply, user.id);
    });

    return { user: publicUser(user), accessToken: session.accessToken, expiresIn: config.accessTokenTtlSeconds };
  });

  app.post("/auth/refresh", { config: credentialLimit }, async (req, reply) => {
    const presented = req.cookies[REFRESH_COOKIE];
    if (!presented) return reply.code(401).send({ error: "unauthorized" });
    const ctx = requestContext(req);
    const now = new Date();

    const existing = await store.refreshTokens.findByHash(hashOpaqueToken(presented, config.refreshSecret));
    if (!existing || existing.expiresAt <= now) {
      clearRefreshCookie(reply);
      return reply.code(401).send({ error: "unauthorized" });
    }

    const outcome = await store.transaction(async (tx) => {
      const audit = createAuditLogger(tx.audit);
      const user = await tx.users.findById(existing.userId);
      if (!user || user.disabledAt) return null;

      // Claim the presented token first; only the caller that revokes it may
      // receive a successor.
      const won = await tx.refreshTokens.revoke(existing.id, now);
      if (!won) {
        // The token was already used: either a replay of a stolen token or a
        // lost race. Kill the whole family either way (OWASP rotation guidance).
        await tx.refreshTokens.revokeFamily(existing.familyId, now);
        await audit.record({
          action: "auth.refresh_reuse_detected",
          actor: { type: "user", id: existing.userId },
          payload: { familyId: existing.familyId },
          ...ctx,
        });
        return "reuse" as const;
      }
      const next = await issueSession(tx, reply, existing.userId, existing.familyId);
      await audit.record({ action: "auth.refresh", actor: { type: "user", id: existing.userId }, ...ctx });
      return { user, accessToken: next.accessToken };
    });

    if (outcome === null || outcome === "reuse") {
      clearRefreshCookie(reply);
      return reply.code(401).send({ error: "unauthorized" });
    }
    return { user: publicUser(outcome.user), accessToken: outcome.accessToken, expiresIn: config.accessTokenTtlSeconds };
  });

  app.post("/auth/logout", async (req: FastifyRequest, reply) => {
    const presented = req.cookies[REFRESH_COOKIE];
    if (presented) {
      const existing = await store.refreshTokens.findByHash(hashOpaqueToken(presented, config.refreshSecret));
      if (existing) {
        const now = new Date();
        await store.transaction(async (tx) => {
          await tx.refreshTokens.revokeFamily(existing.familyId, now);
          await createAuditLogger(tx.audit).record({
            action: "auth.logout",
            actor: { type: "user", id: existing.userId },
            ...requestContext(req),
          });
        });
      }
    }
    clearRefreshCookie(reply);
    return reply.code(204).send();
  });

  app.get("/auth/me", { preHandler: app.authenticate }, async (req) => {
    const user = req.user!;
    const memberships = await store.memberships.listByUser(user.id);
    return {
      user: publicUser(user),
      memberships: memberships.map((m) => ({ orgId: m.orgId, role: m.role, org: { name: m.org.name, slug: m.org.slug } })),
    };
  });
}
