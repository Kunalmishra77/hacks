import { createPrismaGateRepository, Prisma, type PrismaClient } from "@aegis/db";
import type { AssetKind, AuditEvent, AuditSink, GateRepository } from "@aegis/core";

/** What a worker may read and write. Deliberately small. */
export interface WorkerStore {
  gate: GateRepository;
  audit: AuditSink;
  /** QUEUED → RUNNING. "already_running" lets a job resume after a worker crash. */
  markRunning(scanId: string, at: Date): Promise<"started" | "already_running" | "not_runnable">;
  /**
   * Ends a scan. Only moves QUEUED/RUNNING scans, so a scan the API already
   * KILLED stays KILLED. Returns false when the scan was no longer active.
   */
  finish(scanId: string, status: "SUCCEEDED" | "FAILED" | "KILLED", at: Date, error?: string | null): Promise<boolean>;
  upsertAsset(input: {
    scopeId: string;
    kind: AssetKind;
    address: string;
    metadata: Record<string, unknown> | null;
    scanId: string;
    at: Date;
  }): Promise<{ id: string; created: boolean }>;
}

export function createPrismaWorkerStore(prisma: PrismaClient): WorkerStore {
  return {
    gate: createPrismaGateRepository(prisma),
    audit: {
      async append(e: AuditEvent) {
        await prisma.auditEvent.create({
          data: {
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
          },
        });
      },
    },
    async markRunning(scanId, at) {
      const r = await prisma.scan.updateMany({
        where: { id: scanId, status: "QUEUED" },
        data: { status: "RUNNING", startedAt: at },
      });
      if (r.count === 1) return "started";
      const s = await prisma.scan.findUnique({ where: { id: scanId }, select: { status: true } });
      return s?.status === "RUNNING" ? "already_running" : "not_runnable";
    },
    async finish(scanId, status, at, error) {
      const r = await prisma.scan.updateMany({
        where: { id: scanId, status: { in: ["QUEUED", "RUNNING"] } },
        data: {
          status,
          finishedAt: at,
          error: error ?? null,
          ...(status === "KILLED" ? { killedAt: at } : {}),
        },
      });
      return r.count === 1;
    },
    async upsertAsset({ scopeId, kind, address, metadata, scanId, at }) {
      const meta = metadata === null ? Prisma.JsonNull : (metadata as Prisma.InputJsonObject);
      try {
        const a = await prisma.asset.create({
          data: { scopeId, kind, address, metadata: meta, discoveredByScanId: scanId, firstSeen: at, lastSeen: at },
          select: { id: true },
        });
        return { id: a.id, created: true };
      } catch (e) {
        if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002")) throw e;
        const a = await prisma.asset.update({
          where: { scopeId_kind_address: { scopeId, kind, address } },
          data: { lastSeen: at, metadata: meta },
          select: { id: true },
        });
        return { id: a.id, created: false };
      }
    },
  };
}
