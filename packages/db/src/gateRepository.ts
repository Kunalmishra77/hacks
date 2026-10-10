import type { GateRepository } from "@aegis/core";
import type { Prisma, PrismaClient } from "@prisma/client";

/**
 * Postgres-backed read model for the Scope Authorization Gate. Shared by the
 * API (enqueue) and every worker (job_start / heartbeat) so both evaluate the
 * same data the same way.
 */
export function createPrismaGateRepository(db: PrismaClient | Prisma.TransactionClient): GateRepository {
  return {
    async findAssetWithScope(assetId) {
      const a = await db.asset.findUnique({
        where: { id: assetId },
        select: {
          id: true,
          scopeId: true,
          kind: true,
          address: true,
          scope: {
            select: {
              id: true,
              orgId: true,
              type: true,
              value: true,
              status: true,
              expiresAt: true,
              allowedEngines: true,
              maxRequestsPerSec: true,
            },
          },
        },
      });
      if (!a) return null;
      const { scope, ...asset } = a;
      return { asset, scope };
    },
    findOrg: (orgId) => db.org.findUnique({ where: { id: orgId }, select: { id: true, killSwitchEngaged: true } }),
    findScan: (scanId) =>
      db.scan.findUnique({
        where: { id: scanId },
        select: {
          id: true,
          orgId: true,
          scopeId: true,
          assetId: true,
          engine: true,
          status: true,
          approvedById: true,
          killedAt: true,
        },
      }),
    countActiveScans: (orgId) => db.scan.count({ where: { orgId, status: { in: ["QUEUED", "RUNNING"] } } }),
  };
}
