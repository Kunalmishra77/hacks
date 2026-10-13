import { createAuditLogger, type Actor, type Engine, type ScanAuthorizationDecision, type ScopeGate } from "@aegis/core";
import type { ScanQueue } from "../queue.js";
import type { ScanRecord, Store } from "../store/types.js";

// The single path that turns a scan request into a queued (or pending) scan.
// Both the HTTP route and the scheduler call this, so an automated schedule
// goes through the exact same Scope Authorization Gate, concurrency admission
// and audit as a human request — no bypass.

export class AdmissionThrottled extends Error {}

export interface ScanRequestInput {
  orgId: string;
  assetId: string;
  engine: Engine;
  actor: Actor;
  requestedById: string;
  scheduleId?: string;
  ctx?: { ip?: string | null; userAgent?: string | null };
}

export type ScanRequestResult =
  | { ok: true; scan: ScanRecord; status: "QUEUED" | "PENDING_APPROVAL" }
  | { ok: false; kind: "denied"; decision: Exclude<ScanAuthorizationDecision, { decision: "ALLOW" | "NEEDS_APPROVAL" }> }
  | { ok: false; kind: "throttled_concurrency" }
  | { ok: false; kind: "queue_unavailable"; scan: ScanRecord };

export interface ScanRequestDeps {
  store: Store;
  gate: ScopeGate;
  queue: ScanQueue;
  maxConcurrentScansPerOrg: number;
}

export async function requestScan(deps: ScanRequestDeps, input: ScanRequestInput): Promise<ScanRequestResult> {
  const { store, gate, queue } = deps;
  const d = await gate.authorize({ mode: "enqueue", orgId: input.orgId, assetId: input.assetId, engine: input.engine, actor: input.actor });
  if (d.decision !== "ALLOW" && d.decision !== "NEEDS_APPROVAL") return { ok: false, kind: "denied", decision: d };

  const scopeId = d.decision === "ALLOW" ? d.target.scopeId : d.scopeId;
  const status = d.decision === "ALLOW" ? "QUEUED" : "PENDING_APPROVAL";

  let scan: ScanRecord;
  try {
    scan = await store.transaction(async (tx) => {
      if (status === "QUEUED") {
        await tx.scans.lockOrg(input.orgId);
        if ((await tx.gate.countActiveScans(input.orgId)) >= deps.maxConcurrentScansPerOrg) throw new AdmissionThrottled();
      }
      const created = await tx.scans.create({
        orgId: input.orgId,
        scopeId,
        assetId: input.assetId,
        engine: input.engine,
        status,
        requestedById: input.requestedById,
        scheduleId: input.scheduleId,
      });
      await createAuditLogger(tx.audit).record({
        action: "scan.requested",
        actor: input.actor,
        orgId: input.orgId,
        scopeId,
        scanId: created.id,
        targetId: input.assetId,
        payload: { engine: input.engine, status, ...(input.scheduleId ? { scheduleId: input.scheduleId } : {}) },
        ip: input.ctx?.ip ?? null,
        userAgent: input.ctx?.userAgent ?? null,
      });
      return created;
    });
  } catch (e) {
    if (e instanceof AdmissionThrottled) return { ok: false, kind: "throttled_concurrency" };
    throw e;
  }

  if (status === "QUEUED") {
    try {
      await queue.enqueue({ scanId: scan.id, orgId: scan.orgId, assetId: d.decision === "ALLOW" ? d.target.assetId : input.assetId, engine: input.engine, targetAddress: d.decision === "ALLOW" ? d.target.address : "" });
    } catch (e) {
      await store.scans.markFailed(scan.id, `queue unavailable: ${(e as Error).message}`.slice(0, 300), new Date());
      return { ok: false, kind: "queue_unavailable", scan };
    }
  }
  return { ok: true, scan, status };
}
