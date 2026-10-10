import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import {
  createAuditLogger,
  ENGINES,
  can,
  type AuthorizedTarget,
  type ScanAuthorizationDecision,
  type ScopeGate,
} from "@aegis/core";
import type { AppConfig } from "../config.js";
import type { ScanQueue } from "../queue.js";
import type { ScanRecord, Store } from "../store/types.js";
import { requestContext } from "./context.js";

// Every scan path goes through `gate.authorize`. A job reaches the queue only
// after an ALLOW, and workers call the gate again in job_start mode.

const CreateScanBody = z.object({
  assetId: z.string().uuid(),
  engine: z.enum(ENGINES),
});
const ScanParams = z.object({ orgId: z.string().uuid(), scanId: z.string().uuid() });
const KillSwitchBody = z.object({ engaged: z.boolean() });

const CONCURRENCY_RETRY_MS = 30_000;

class AdmissionThrottled extends Error {}

function scanDto(s: ScanRecord) {
  return {
    id: s.id,
    scopeId: s.scopeId,
    assetId: s.assetId,
    engine: s.engine,
    status: s.status,
    requestedById: s.requestedById,
    approvedById: s.approvedById,
    approvedAt: s.approvedAt,
    killedAt: s.killedAt,
    createdAt: s.createdAt,
  };
}

/** Maps a non-ALLOW gate decision to an HTTP response. */
function sendDenied(reply: FastifyReply, d: Exclude<ScanAuthorizationDecision, { decision: "ALLOW" | "NEEDS_APPROVAL" }>) {
  if (d.decision === "THROTTLED") {
    // Throttled is explicit, never a silent drop: 429 with when to retry.
    reply.header("retry-after", Math.ceil(d.retryAfterMs / 1000));
    return reply.code(429).send({ error: "throttled", reason: d.reason, retryAfterMs: d.retryAfterMs });
  }
  // Don't reveal whether an asset id exists in another org.
  if (d.reason === "NO_SCOPE" || d.reason === "TENANT_MISMATCH") return reply.code(404).send({ error: "not_found" });
  return reply.code(403).send({ error: "scan_rejected", reason: d.reason });
}

function sendConcurrencyThrottled(reply: FastifyReply) {
  reply.header("retry-after", Math.ceil(CONCURRENCY_RETRY_MS / 1000));
  return reply.code(429).send({ error: "throttled", reason: "ORG_CONCURRENCY_LIMIT", retryAfterMs: CONCURRENCY_RETRY_MS });
}

export async function scanRoutes(
  app: FastifyInstance,
  opts: { config: AppConfig; store: Store; gate: ScopeGate; queue: ScanQueue },
) {
  const { config, store, gate, queue } = opts;

  /**
   * The gate's concurrency check runs before the scan exists, so two requests
   * could both pass it. This re-checks under a per-org lock in the same
   * transaction that makes the scan active.
   */
  async function admit(tx: Store, orgId: string) {
    await tx.scans.lockOrg(orgId);
    if ((await tx.gate.countActiveScans(orgId)) >= config.gateLimits.maxConcurrentScansPerOrg) {
      throw new AdmissionThrottled();
    }
  }

  /** Puts an admitted scan on its engine queue; if Redis is down, fails the scan visibly. */
  async function enqueue(scan: ScanRecord, target: AuthorizedTarget, reply: FastifyReply): Promise<boolean> {
    try {
      await queue.enqueue({
        scanId: scan.id,
        orgId: scan.orgId,
        assetId: target.assetId,
        engine: target.engine,
        targetAddress: target.address,
      });
      return true;
    } catch (e) {
      await store.scans.markFailed(scan.id, `queue unavailable: ${(e as Error).message}`.slice(0, 300), new Date());
      reply.code(503).send({ error: "queue_unavailable", scanId: scan.id });
      return false;
    }
  }

  app.post(
    "/orgs/:orgId/scans",
    { preHandler: [app.authenticate, app.requirePermission("scan.run")] },
    async (req, reply) => {
      const body = CreateScanBody.parse(req.body);
      const member = req.membership!;
      const actor = { type: "user" as const, id: member.userId };

      const d = await gate.authorize({ mode: "enqueue", orgId: member.orgId, assetId: body.assetId, engine: body.engine, actor });
      if (d.decision !== "ALLOW" && d.decision !== "NEEDS_APPROVAL") return sendDenied(reply, d);

      const scopeId = d.decision === "ALLOW" ? d.target.scopeId : d.scopeId;
      const status = d.decision === "ALLOW" ? "QUEUED" : "PENDING_APPROVAL";
      let scan: ScanRecord;
      try {
        scan = await store.transaction(async (tx) => {
          if (status === "QUEUED") await admit(tx, member.orgId);
          const created = await tx.scans.create({
            orgId: member.orgId,
            scopeId,
            assetId: body.assetId,
            engine: body.engine,
            status,
            requestedById: member.userId,
          });
          await createAuditLogger(tx.audit).record({
            action: "scan.requested",
            actor,
            orgId: member.orgId,
            scopeId,
            scanId: created.id,
            targetId: body.assetId,
            payload: { engine: body.engine, status },
            ...requestContext(req),
          });
          return created;
        });
      } catch (e) {
        if (e instanceof AdmissionThrottled) return sendConcurrencyThrottled(reply);
        throw e;
      }

      if (d.decision === "ALLOW" && !(await enqueue(scan, d.target, reply))) return reply;
      return reply.code(status === "QUEUED" ? 201 : 202).send({ scan: scanDto(scan) });
    },
  );

  app.get(
    "/orgs/:orgId/scans",
    { preHandler: [app.authenticate, app.requirePermission("finding.read")] },
    async (req) => ({ scans: (await store.scans.listByOrg(req.membership!.orgId)).map(scanDto) }),
  );

  app.post(
    "/orgs/:orgId/scans/:scanId/approve",
    { preHandler: [app.authenticate, app.requirePermission("scan.approve")] },
    async (req, reply) => {
      const { scanId } = ScanParams.parse(req.params);
      const member = req.membership!;
      const actor = { type: "user" as const, id: member.userId };
      const scan = await store.scans.find(member.orgId, scanId);
      if (!scan) return reply.code(404).send({ error: "not_found" });
      if (scan.status !== "PENDING_APPROVAL") return reply.code(409).send({ error: "not_pending", status: scan.status });

      if (!scan.approvedById) {
        const ok = await store.transaction(async (tx) => {
          if (!(await tx.scans.approve(scan.id, member.userId, new Date()))) return false;
          await createAuditLogger(tx.audit).record({
            action: "scan.approved",
            actor,
            orgId: member.orgId,
            scopeId: scan.scopeId,
            scanId: scan.id,
            payload: { engine: scan.engine, requestedById: scan.requestedById },
            ...requestContext(req),
          });
          return true;
        });
        if (!ok) return reply.code(409).send({ error: "not_pending" });
      }

      // Approval is necessary, not sufficient: the gate re-checks everything.
      const d = await gate.authorize({
        mode: "enqueue",
        orgId: member.orgId,
        assetId: scan.assetId!,
        engine: scan.engine,
        scanId: scan.id,
        actor,
      });
      if (d.decision === "ALLOW") {
        let queued: boolean;
        try {
          // Conditional on still being pending: a kill in between wins.
          queued = await store.transaction(async (tx) => {
            await admit(tx, member.orgId);
            return tx.scans.resolvePending(scan.id, "QUEUED");
          });
        } catch (e) {
          if (e instanceof AdmissionThrottled) return sendConcurrencyThrottled(reply);
          throw e;
        }
        if (!queued) return reply.code(409).send({ error: "not_pending" });
        const approved = { ...scan, status: "QUEUED" as const, approvedById: scan.approvedById ?? member.userId };
        if (!(await enqueue(approved, d.target, reply))) return reply;
        return { scan: scanDto(approved) };
      }
      if (d.decision === "REJECT") await store.scans.resolvePending(scan.id, "REJECTED");
      // THROTTLED leaves it approved and pending; calling approve again retries.
      if (d.decision === "NEEDS_APPROVAL") return reply.code(409).send({ error: "not_approved" });
      return sendDenied(reply, d);
    },
  );

  app.post(
    "/orgs/:orgId/scans/:scanId/kill",
    { preHandler: [app.authenticate, app.requirePermission("scan.kill")] },
    async (req, reply) => {
      const { scanId } = ScanParams.parse(req.params);
      const member = req.membership!;
      const scan = await store.scans.find(member.orgId, scanId);
      if (!scan) return reply.code(404).send({ error: "not_found" });
      const killed = await store.transaction(async (tx) => {
        if (!(await tx.scans.kill(scan.id, member.userId, new Date()))) return false;
        await createAuditLogger(tx.audit).record({
          action: "scan.killed",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          scopeId: scan.scopeId,
          scanId: scan.id,
          payload: { previousStatus: scan.status },
          ...requestContext(req),
        });
        return true;
      });
      if (!killed) return reply.code(409).send({ error: "not_active", status: scan.status });
      // Best effort: a queued job is dropped now; if it slips through, the
      // worker's job_start gate check refuses it because the scan is KILLED.
      await queue.remove(scan.id, scan.engine).catch(() => {});
      return { scanId: scan.id, status: "KILLED" };
    },
  );

  // Org-level kill-switch: one API call. Engaging stops every active scan and
  // blocks new ones at the gate; running workers stop at their next heartbeat.
  app.post(
    "/orgs/:orgId/kill-switch",
    { preHandler: [app.authenticate, app.requirePermission("killswitch.engage")] },
    async (req, reply) => {
      const { engaged } = KillSwitchBody.parse(req.body);
      const member = req.membership!;
      if (!engaged && !can(member.role, "killswitch.release")) {
        return reply.code(403).send({ error: "forbidden", message: "only Admins can release the kill-switch" });
      }
      const now = new Date();
      const killed = await store.transaction(async (tx) => {
        await tx.orgs.setKillSwitch(member.orgId, engaged, member.userId, now);
        const list = engaged ? await tx.scans.killActive({ orgId: member.orgId }, member.userId, now) : [];
        await createAuditLogger(tx.audit).record({
          action: engaged ? "killswitch.engaged" : "killswitch.released",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          payload: engaged ? { killedScans: list.length } : null,
          ...requestContext(req),
        });
        return list;
      });
      await Promise.all(killed.map((s) => queue.remove(s.id, s.engine).catch(() => {})));
      return { killSwitchEngaged: engaged, killedScans: killed.length };
    },
  );
}
