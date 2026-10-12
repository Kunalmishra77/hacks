import { createPrismaGateRepository, Prisma, type PrismaClient } from "@aegis/db";
import type { AssetKind, AuditEvent, AuditSink, GateRepository, Severity } from "@aegis/core";

export interface FindingUpsert {
  assetId: string;
  scanId: string;
  fingerprint: string;
  type: string;
  severity: Severity;
  title: string;
  remediation: string;
  evidence: Record<string, unknown> | null;
  cveRefs: string[];
  cvss: number | null;
  at: Date;
}

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
  /**
   * Creates a finding or refreshes an existing one (same asset + fingerprint).
   * A finding someone marked FIXED that shows up again is reopened; one marked
   * FALSE_POSITIVE keeps that status.
   */
  upsertFinding(f: FindingUpsert): Promise<"created" | "updated" | "reopened">;
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
    async upsertFinding(f) {
      const evidence = f.evidence === null ? Prisma.JsonNull : (f.evidence as Prisma.InputJsonObject);
      const existing = await prisma.finding.findUnique({
        where: { assetId_fingerprint: { assetId: f.assetId, fingerprint: f.fingerprint } },
        select: { id: true, status: true },
      });
      const fields = {
        type: f.type,
        severity: f.severity,
        title: f.title,
        remediation: f.remediation,
        evidence,
        cveRefs: f.cveRefs,
        cvss: f.cvss,
        lastSeenAt: f.at,
        lastScanId: f.scanId,
      };
      if (!existing) {
        try {
          await prisma.finding.create({
            data: { ...fields, assetId: f.assetId, scanId: f.scanId, fingerprint: f.fingerprint, firstSeenAt: f.at },
          });
          return "created";
        } catch (e) {
          if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002")) throw e;
        }
      }
      const reopened = existing?.status === "FIXED";
      await prisma.finding.update({
        where: { assetId_fingerprint: { assetId: f.assetId, fingerprint: f.fingerprint } },
        data: { ...fields, ...(reopened ? { status: "OPEN" as const } : {}) },
      });
      return reopened ? "reopened" : "updated";
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
