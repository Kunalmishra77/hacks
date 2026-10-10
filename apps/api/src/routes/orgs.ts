import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { canGrantRole, createAuditLogger, ROLES } from "@aegis/core";
import type { AppConfig } from "../config.js";
import { hashOpaqueToken, newOpaqueToken } from "../security.js";
import type { Store } from "../store/types.js";
import { requestContext } from "./context.js";

const CreateOrgBody = z.object({ name: z.string().trim().min(2).max(100) });
const InviteBody = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  role: z.enum(ROLES),
});
const AcceptInviteBody = z.object({ token: z.string().min(16).max(256) });

function slugify(name: string): string {
  const base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return `${base || "org"}-${randomBytes(3).toString("hex")}`;
}

/** Creates an org with `userId` as Owner and audits it. Call inside a transaction. */
export async function createOrgWithOwner(
  tx: Store,
  userId: string,
  name: string,
  ctx: { ip: string; userAgent: string | null },
) {
  const org = await tx.orgs.create({ name, slug: slugify(name) });
  await tx.memberships.create({ orgId: org.id, userId, role: "OWNER" });
  await createAuditLogger(tx.audit).record({
    action: "org.create",
    actor: { type: "user", id: userId },
    orgId: org.id,
    targetId: org.id,
    payload: { name: org.name, slug: org.slug },
    ...ctx,
  });
  return { id: org.id, name: org.name, slug: org.slug };
}

export async function orgRoutes(app: FastifyInstance, opts: { config: AppConfig; store: Store }) {
  const { config, store } = opts;

  app.post("/orgs", { preHandler: app.authenticate }, async (req, reply) => {
    const body = CreateOrgBody.parse(req.body);
    const org = await store.transaction((tx) => createOrgWithOwner(tx, req.user!.id, body.name, requestContext(req)));
    return reply.code(201).send({ org, role: "OWNER" });
  });

  app.get("/orgs", { preHandler: app.authenticate }, async (req) => {
    const memberships = await store.memberships.listByUser(req.user!.id);
    return {
      orgs: memberships.map((m) => ({ id: m.org.id, name: m.org.name, slug: m.org.slug, role: m.role })),
    };
  });

  app.get(
    "/orgs/:orgId",
    { preHandler: [app.authenticate, app.requirePermission("org.read")] },
    async (req) => {
      const org = (await store.orgs.findById(req.membership!.orgId))!;
      return {
        org: { id: org.id, name: org.name, slug: org.slug, killSwitchEngaged: org.killSwitchEngaged },
        role: req.membership!.role,
      };
    },
  );

  app.get(
    "/orgs/:orgId/members",
    { preHandler: [app.authenticate, app.requirePermission("member.read")] },
    async (req) => {
      const members = await store.memberships.listByOrg(req.membership!.orgId);
      return {
        members: members.map((m) => ({ userId: m.userId, email: m.email, name: m.name, role: m.role, joinedAt: m.createdAt })),
      };
    },
  );

  app.post(
    "/orgs/:orgId/invites",
    { preHandler: [app.authenticate, app.requirePermission("member.invite")] },
    async (req, reply) => {
      const body = InviteBody.parse(req.body);
      const actor = req.membership!;
      if (!canGrantRole(actor.role, body.role)) {
        return reply.code(403).send({ error: "forbidden", message: `cannot grant role ${body.role}` });
      }
      const existingUser = await store.users.findByEmail(body.email);
      if (existingUser && (await store.memberships.find(actor.orgId, existingUser.id))) {
        return reply.code(409).send({ error: "already_member" });
      }

      const token = newOpaqueToken();
      const expiresAt = new Date(Date.now() + config.inviteTtlHours * 3_600_000);
      const invite = await store.transaction(async (tx) => {
        const created = await tx.invites.create({
          orgId: actor.orgId,
          email: body.email,
          role: body.role,
          tokenHash: hashOpaqueToken(token, config.refreshSecret),
          invitedById: actor.userId,
          expiresAt,
        });
        await createAuditLogger(tx.audit).record({
          action: "member.invite",
          actor: { type: "user", id: actor.userId },
          orgId: actor.orgId,
          targetId: created.id,
          payload: { email: body.email, role: body.role },
          ...requestContext(req),
        });
        return created;
      });

      // Phase 0 has no mail delivery: the token is returned once so an admin
      // can share the invite link. Phase 6 (notifications) emails it instead.
      return reply.code(201).send({
        invite: { id: invite.id, email: invite.email, role: invite.role, expiresAt: invite.expiresAt },
        token,
      });
    },
  );

  app.post("/invites/accept", { preHandler: app.authenticate }, async (req, reply) => {
    const body = AcceptInviteBody.parse(req.body);
    const user = req.user!;
    const now = new Date();
    const invite = await store.invites.findByTokenHash(hashOpaqueToken(body.token, config.refreshSecret));

    if (!invite || invite.acceptedAt || invite.expiresAt <= now) {
      return reply.code(400).send({ error: "invalid_or_expired_invite" });
    }
    if (invite.email !== user.email) {
      return reply.code(403).send({ error: "invite_email_mismatch" });
    }

    const result = await store.transaction(async (tx) => {
      if (!(await tx.invites.markAccepted(invite.id, now))) return null;
      if (await tx.memberships.find(invite.orgId, user.id)) return "already_member" as const;
      const membership = await tx.memberships.create({ orgId: invite.orgId, userId: user.id, role: invite.role });
      await createAuditLogger(tx.audit).record({
        action: "member.join",
        actor: { type: "user", id: user.id },
        orgId: invite.orgId,
        targetId: invite.id,
        payload: { role: invite.role, invitedBy: invite.invitedById },
        ...requestContext(req),
      });
      return membership;
    });

    if (result === null) return reply.code(400).send({ error: "invalid_or_expired_invite" });
    if (result === "already_member") return reply.code(409).send({ error: "already_member" });
    return reply.code(201).send({ orgId: result.orgId, role: result.role });
  });
}
