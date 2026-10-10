import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { createAuditLogger, ENGINES, can, type ScanAuthorizationDecision, type ScopeGate } from "@aegis/core";
import type { ScanRecord, Store } from "../store/types.js";
import { requestContext } from "./context.js";

// Every scan path goes through `gate.authorize`. No route creates a QUEUED
// scan any other way. (Phase 2 adds the BullMQ producer right after ALLOW,
// and workers call the gate again in job_start mode.)

const CreateScanBody = z.object({
  assetId: z.string().uuid(),
  engine: z.enum(ENGINES),
});
const ScanParams = z.object({ orgId: z.string().uuid(), scanId: z.string().uuid() });
const KillSwitchBody = z.object({ engaged: z.boolean() });

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

export async function scanRoutes(app: FastifyInstance, opts: { store: Store; gate: ScopeGate }) {
  const { store, gate } = opts;

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
      const scan = await store.transaction(async (tx) => {
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
        // Conditional on still being pending: a kill in between wins.
        if (!(await store.scans.resolvePending(scan.id, "QUEUED"))) return reply.code(409).send({ error: "not_pending" });
        return { scan: scanDto({ ...scan, status: "QUEUED", approvedById: scan.approvedById ?? member.userId }) };
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
      return { scanId: scan.id, status: "KILLED" };
    },
  );

  // Org-level kill-switch: one API call. Engaging stops every active scan and
  // blocks new ones at the gate; workers refuse killed jobs at start.
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
      const killedScans = await store.transaction(async (tx) => {
        await tx.orgs.setKillSwitch(member.orgId, engaged, member.userId, now);
        const n = engaged ? await tx.scans.killActive({ orgId: member.orgId }, member.userId, now) : 0;
        await createAuditLogger(tx.audit).record({
          action: engaged ? "killswitch.engaged" : "killswitch.released",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          payload: engaged ? { killedScans: n } : null,
          ...requestContext(req),
        });
        return n;
      });
      return { killSwitchEngaged: engaged, killedScans };
    },
  );
}
