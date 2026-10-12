import { createPrismaGateRepository, Prisma, type PrismaClient } from "@aegis/db";
import type { AuditEvent } from "@aegis/core";
import { ACTIVE_SCAN_STATUSES, UniqueViolationError, type Store } from "./types.js";

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

const scopeSelect = {
  id: true,
  orgId: true,
  type: true,
  value: true,
  status: true,
  verificationMethod: true,
  verificationToken: true,
  verifiedAt: true,
  expiresAt: true,
  revokedAt: true,
  allowedEngines: true,
  maxRequestsPerSec: true,
  criticality: true,
  cloudRoleArn: true,
  externalId: true,
  lastVerificationAt: true,
  lastVerificationError: true,
  createdById: true,
  createdAt: true,
} as const;
const reportSelect = {
  id: true,
  orgId: true,
  scopeId: true,
  title: true,
  format: true,
  summary: true,
  byteSize: true,
  createdById: true,
  createdAt: true,
} as const;
const scanSelect = {
  id: true,
  orgId: true,
  scopeId: true,
  assetId: true,
  engine: true,
  status: true,
  requestedById: true,
  approvedById: true,
  approvedAt: true,
  killedAt: true,
  killedById: true,
  createdAt: true,
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
      async setKillSwitch(id, engaged, byId, at) {
        await db.org.update({
          where: { id },
          data: { killSwitchEngaged: engaged, killSwitchAt: at, killSwitchById: byId },
        });
      },
    },
    scopes: {
      create: (input) => db.scope.create({ data: input, select: scopeSelect }).catch(rethrowUnique),
      find: (orgId, id) => db.scope.findFirst({ where: { id, orgId }, select: scopeSelect }),
      listByOrg: (orgId) => db.scope.findMany({ where: { orgId }, select: scopeSelect, orderBy: { createdAt: "asc" } }),
      markVerified: (id, { method, at, expiresAt }) =>
        db.scope.update({
          where: { id },
          data: {
            status: "VERIFIED",
            verificationMethod: method,
            verifiedAt: at,
            expiresAt,
            lastVerificationAt: at,
            lastVerificationError: null,
          },
          select: scopeSelect,
        }),
      async recordVerificationFailure(id, at, error) {
        await db.scope.update({ where: { id }, data: { lastVerificationAt: at, lastVerificationError: error } });
      },
      async setCriticality(orgId, id, criticality) {
        const r = await db.scope.updateMany({ where: { id, orgId }, data: { criticality } });
        return r.count === 1 ? db.scope.findUnique({ where: { id }, select: scopeSelect }) : null;
      },
      async revoke(id, at) {
        await db.scope.update({ where: { id }, data: { status: "REVOKED", revokedAt: at } });
      },
    },
    assets: {
      upsert: ({ scopeId, kind, address, at }) =>
        db.asset.upsert({
          where: { scopeId_kind_address: { scopeId, kind, address } },
          create: { scopeId, kind, address, firstSeen: at, lastSeen: at },
          update: { lastSeen: at },
        }),
      listByOrg: (orgId, scopeId) =>
        db.asset.findMany({
          where: { scope: { orgId }, ...(scopeId ? { scopeId } : {}) },
          orderBy: { firstSeen: "asc" },
        }),
    },
    scans: {
      create: (input) => db.scan.create({ data: input, select: scanSelect }),
      find: (orgId, id) => db.scan.findFirst({ where: { id, orgId }, select: scanSelect }),
      listByOrg: (orgId) =>
        db.scan.findMany({ where: { orgId }, select: scanSelect, orderBy: { createdAt: "desc" }, take: 200 }),
      async approve(id, approvedById, at) {
        const r = await db.scan.updateMany({
          where: { id, status: "PENDING_APPROVAL" },
          data: { approvedById, approvedAt: at },
        });
        return r.count === 1;
      },
      async resolvePending(id, status) {
        const r = await db.scan.updateMany({ where: { id, status: "PENDING_APPROVAL" }, data: { status } });
        return r.count === 1;
      },
      async kill(id, byId, at) {
        const r = await db.scan.updateMany({
          where: { id, status: { in: [...ACTIVE_SCAN_STATUSES] } },
          data: { status: "KILLED", killedAt: at, killedById: byId },
        });
        return r.count === 1;
      },
      async killActive({ orgId, scopeId }, byId, at) {
        const where = { orgId, ...(scopeId ? { scopeId } : {}), status: { in: [...ACTIVE_SCAN_STATUSES] } };
        const victims = await db.scan.findMany({ where, select: { id: true, engine: true } });
        if (victims.length === 0) return [];
        await db.scan.updateMany({
          where: { ...where, id: { in: victims.map((v) => v.id) } },
          data: { status: "KILLED", killedAt: at, killedById: byId },
        });
        return victims;
      },
      async markFailed(id, error, at) {
        await db.scan.updateMany({ where: { id, status: "QUEUED" }, data: { status: "FAILED", error, finishedAt: at } });
      },
      async lockOrg(orgId) {
        // Transaction-scoped advisory lock; released on commit/rollback.
        await db.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${orgId}))`;
      },
    },
    findings: {
      async listByOrg(orgId, filter = {}) {
        const rows = await db.finding.findMany({
          where: {
            asset: { scope: { orgId, ...(filter.scopeId ? { id: filter.scopeId } : {}) } },
            ...(filter.status ? { status: filter.status } : {}),
            ...(filter.severity ? { severity: filter.severity } : {}),
            ...(filter.assetId ? { assetId: filter.assetId } : {}),
          },
          include: { asset: { select: { address: true, kind: true, scopeId: true } } },
          orderBy: [{ riskScore: { sort: "desc", nulls: "last" } }, { severity: "desc" }, { lastSeenAt: "desc" }],
          take: 1000,
        });
        return rows.map(({ asset, ...f }) => ({
          ...f,
          assetAddress: asset.address,
          assetKind: asset.kind,
          scopeId: asset.scopeId,
        }));
      },
      find: (orgId, id) => db.finding.findFirst({ where: { id, asset: { scope: { orgId } } } }),
      async setStatus(orgId, id, status) {
        const r = await db.finding.updateMany({ where: { id, asset: { scope: { orgId } } }, data: { status } });
        return r.count === 1;
      },
      async summary(orgId) {
        const rows = await db.finding.groupBy({
          by: ["severity"],
          where: { asset: { scope: { orgId } }, status: { in: ["OPEN", "TRIAGED"] } },
          _count: true,
        });
        const out = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
        for (const r of rows) out[r.severity] = r._count;
        return out;
      },
    },
    reports: {
      create: (input) =>
        db.report.create({
          data: {
            orgId: input.orgId,
            scopeId: input.scopeId,
            title: input.title,
            format: "HTML",
            summary: input.summary as Prisma.InputJsonObject,
            content: input.content,
            byteSize: input.byteSize,
            createdById: input.createdById,
          },
          select: reportSelect,
        }),
      listByOrg: (orgId) => db.report.findMany({ where: { orgId }, select: reportSelect, orderBy: { createdAt: "desc" }, take: 200 }),
      find: (orgId, id) => db.report.findFirst({ where: { id, orgId }, select: reportSelect }),
      loadContent: (id) => db.report.findUnique({ where: { id }, select: { orgId: true, title: true, content: true } }),
    },
    gate: createPrismaGateRepository(db),
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
