import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createAuditLogger, SEVERITIES } from "@aegis/core";
import type { FindingRecord, Store } from "../store/types.js";
import { requestContext } from "./context.js";

const ListQuery = z.object({
  status: z.enum(["OPEN", "TRIAGED", "FIXED", "FALSE_POSITIVE"]).optional(),
  severity: z.enum(SEVERITIES).optional(),
  scopeId: z.string().uuid().optional(),
  assetId: z.string().uuid().optional(),
});
const FindingParams = z.object({ orgId: z.string().uuid(), findingId: z.string().uuid() });
// A user can triage; "FIXED" is also allowed so they can mark remediation done.
const StatusBody = z.object({ status: z.enum(["OPEN", "TRIAGED", "FIXED", "FALSE_POSITIVE"]) });

function dto(f: FindingRecord & { assetAddress?: string; assetKind?: string; scopeId?: string }) {
  return {
    id: f.id,
    assetId: f.assetId,
    assetAddress: f.assetAddress,
    assetKind: f.assetKind,
    scopeId: f.scopeId,
    type: f.type,
    severity: f.severity,
    cvss: f.cvss,
    cveRefs: f.cveRefs,
    title: f.title,
    evidence: f.evidence,
    remediation: f.remediation,
    status: f.status,
    epss: f.epss,
    kevListed: f.kevListed,
    riskScore: f.riskScore,
    enrichedAt: f.enrichedAt,
    firstSeenAt: f.firstSeenAt,
    lastSeenAt: f.lastSeenAt,
    aiAdvice: f.aiAdvice ?? null,
    aiModel: f.aiModel ?? null,
    aiAdviceAt: f.aiAdviceAt ?? null,
  };
}

export async function findingRoutes(app: FastifyInstance, opts: { store: Store }) {
  const { store } = opts;

  app.get(
    "/orgs/:orgId/findings",
    { preHandler: [app.authenticate, app.requirePermission("finding.read")] },
    async (req) => {
      const filter = ListQuery.parse(req.query);
      const [findings, summary] = await Promise.all([
        store.findings.listByOrg(req.membership!.orgId, filter),
        store.findings.summary(req.membership!.orgId),
      ]);
      return { findings: findings.map(dto), summary };
    },
  );

  app.get(
    "/orgs/:orgId/findings/:findingId",
    { preHandler: [app.authenticate, app.requirePermission("finding.read")] },
    async (req, reply) => {
      const { findingId } = FindingParams.parse(req.params);
      const f = await store.findings.find(req.membership!.orgId, findingId);
      if (!f) return reply.code(404).send({ error: "not_found" });
      return { finding: dto(f) };
    },
  );

  app.post(
    "/orgs/:orgId/findings/:findingId/status",
    { preHandler: [app.authenticate, app.requirePermission("finding.triage")] },
    async (req, reply) => {
      const { findingId } = FindingParams.parse(req.params);
      const { status } = StatusBody.parse(req.body);
      const member = req.membership!;
      const existing = await store.findings.find(member.orgId, findingId);
      if (!existing) return reply.code(404).send({ error: "not_found" });
      await store.transaction(async (tx) => {
        await tx.findings.setStatus(member.orgId, findingId, status);
        await createAuditLogger(tx.audit).record({
          action: "finding.triaged",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          targetId: findingId,
          payload: { from: existing.status, to: status, type: existing.type },
          ...requestContext(req),
        });
      });
      return { findingId, status };
    },
  );
}
