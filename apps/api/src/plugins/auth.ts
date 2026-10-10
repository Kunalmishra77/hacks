import fp from "fastify-plugin";
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";
import { can, type Permission } from "@aegis/core";
import { z } from "zod";
import { verifyAccessToken } from "../security.js";
import type { AppConfig } from "../config.js";
import type { MembershipRecord, Store, UserRecord } from "../store/types.js";

declare module "fastify" {
  interface FastifyRequest {
    user: UserRecord | null;
    membership: MembershipRecord | null;
  }
  interface FastifyInstance {
    /** preHandler: requires a valid access token for an active user. */
    authenticate: preHandlerAsyncHookHandler;
    /**
     * preHandler: requires `authenticate` first, then a membership in
     * `params.orgId` whose role grants `permission`. Non-members get 404 so
     * org ids can't be probed.
     */
    requirePermission(permission: Permission): preHandlerAsyncHookHandler;
  }
}

const OrgParams = z.object({ orgId: z.string().uuid() });

export const authPlugin = fp<{ config: AppConfig; store: Store }>(async (app, { config, store }) => {
  app.decorateRequest("user", null);
  app.decorateRequest("membership", null);

  app.decorate("authenticate", async function (req: FastifyRequest, reply: FastifyReply) {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    const claims = token
      ? await verifyAccessToken(token, { secret: config.jwtSecret, issuer: config.jwtIssuer })
      : null;
    const user = claims ? await store.users.findById(claims.sub) : null;
    if (!user || user.disabledAt) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    req.user = user;
  });

  app.decorate("requirePermission", (permission: Permission) => {
    return async function (req: FastifyRequest, reply: FastifyReply) {
      if (!req.user) return reply.code(401).send({ error: "unauthorized" });
      const params = OrgParams.safeParse(req.params);
      if (!params.success) return reply.code(404).send({ error: "not_found" });
      const membership = await store.memberships.find(params.data.orgId, req.user.id);
      if (!membership) return reply.code(404).send({ error: "not_found" });
      if (!can(membership.role, permission)) return reply.code(403).send({ error: "forbidden" });
      req.membership = membership;
    };
  });
});
