import { Prisma, type PrismaClient } from "@aegis/db";
import type { AuditEvent } from "@aegis/core";
import { UniqueViolationError, type Store } from "./types.js";

type Db = PrismaClient | Prisma.TransactionClient;

function rethrowUnique(err: unknown): never {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
    const target = (err.meta?.target as string[] | string | undefined) ?? "unknown";
    throw new UniqueViolationError(Array.isArray(target) ? target.join(",") : target);
  }
  throw err;
}

function auditRow(e: AuditEvent): Prisma.AuditEventCreateInput {
  return {
    id: e.id,
    orgId: e.orgId,
    actorId: e.actor.id ?? null,
    actorType: e.actor.type,
    action: e.action,
    scopeId: e.scopeId,
    scanId: e.scanId,
    targetId: e.targetId,
    ip: e.ip,
    userAgent: e.userAgent,
    payload: e.payload === null ? Prisma.JsonNull : (e.payload as Prisma.InputJsonObject),
    createdAt: e.createdAt,
  };
}

const orgSelect = { id: true, name: true, slug: true, killSwitchEngaged: true, createdAt: true } as const;
const userSelect = { id: true, email: true, name: true, passwordHash: true, disabledAt: true } as const;
const refreshSelect = { id: true, userId: true, familyId: true, expiresAt: true, revokedAt: true } as const;
const inviteSelect = {
  id: true,
  orgId: true,
  email: true,
  role: true,
  invitedById: true,
  expiresAt: true,
  acceptedAt: true,
} as const;

export function createPrismaStore(client: PrismaClient): Store {
  return build(client, client);
}

function build(db: Db, root: PrismaClient): Store {
  return {
    users: {
      findByEmail: (email) => db.user.findUnique({ where: { email }, select: userSelect }),
      findById: (id) => db.user.findUnique({ where: { id }, select: userSelect }),
      create: (input) => db.user.create({ data: input, select: userSelect }).catch(rethrowUnique),
      async touchLogin(id, at) {
        await db.user.update({ where: { id }, data: { lastLoginAt: at } });
      },
    },
    orgs: {
      create: (input) => db.org.create({ data: input, select: orgSelect }).catch(rethrowUnique),
      findById: (id) => db.org.findUnique({ where: { id }, select: orgSelect }),
    },
    memberships: {
      find: (orgId, userId) => db.membership.findUnique({ where: { orgId_userId: { orgId, userId } } }),
      create: (input) => db.membership.create({ data: input }).catch(rethrowUnique),
      async listByOrg(orgId) {
        const rows = await db.membership.findMany({
          where: { orgId },
          include: { user: { select: { email: true, name: true } } },
          orderBy: { createdAt: "asc" },
        });
        return rows.map(({ user, ...m }) => ({ ...m, email: user.email, name: user.name }));
      },
      listByUser: (userId) =>
        db.membership.findMany({
          where: { userId },
          include: { org: { select: orgSelect } },
          orderBy: { createdAt: "asc" },
        }),
    },
    invites: {
      create: (input) => db.invite.create({ data: input, select: inviteSelect }),
      findByTokenHash: (tokenHash) => db.invite.findUnique({ where: { tokenHash }, select: inviteSelect }),
      async markAccepted(id, at) {
        const r = await db.invite.updateMany({ where: { id, acceptedAt: null }, data: { acceptedAt: at } });
        return r.count === 1;
      },
    },
    refreshTokens: {
      create: (input) => db.refreshToken.create({ data: input, select: refreshSelect }),
      findByHash: (tokenHash) => db.refreshToken.findUnique({ where: { tokenHash }, select: refreshSelect }),
      async revoke(id, at, replacedBy) {
        // Conditional update makes concurrent refreshes race-safe: only one wins.
        const r = await db.refreshToken.updateMany({
          where: { id, revokedAt: null },
          data: { revokedAt: at, replacedBy: replacedBy ?? null },
        });
        return r.count === 1;
      },
      async revokeFamily(familyId, at) {
        await db.refreshToken.updateMany({ where: { familyId, revokedAt: null }, data: { revokedAt: at } });
      },
    },
    audit: {
      async append(event) {
        await db.auditEvent.create({ data: auditRow(event) });
      },
    },
    transaction(fn) {
      if (db !== root) return fn(build(db, root)); // already inside a transaction
      return root.$transaction((tx) => fn(build(tx, root)));
    },
  };
}
