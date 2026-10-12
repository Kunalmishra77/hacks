import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { createAuditLogger } from "@aegis/core";
import { buildReport, renderReportHtml, type ReportFinding, type ReportInput } from "@aegis/report";
import type { AppConfig } from "../config.js";
import { signDownloadToken, verifyDownloadToken } from "../security.js";
import type { ReportRecord, Store } from "../store/types.js";
import { requestContext } from "./context.js";

const CreateReportBody = z.object({ scopeId: z.string().uuid().optional() });
const ReportParams = z.object({ orgId: z.string().uuid(), reportId: z.string().uuid() });
const DownloadQuery = z.object({ token: z.string().min(10).max(400) });

const MAX_REPORT_BYTES = 8 * 1024 * 1024; // guard against a runaway report

function reportDto(r: ReportRecord) {
  return {
    id: r.id,
    scopeId: r.scopeId,
    title: r.title,
    format: r.format,
    summary: r.summary,
    byteSize: r.byteSize,
    createdById: r.createdById,
    createdAt: r.createdAt,
  };
}

function sendHtml(reply: FastifyReply, title: string, html: string) {
  return reply
    .header("content-type", "text/html; charset=utf-8")
    // Reports can contain sensitive findings: never cache in shared proxies.
    .header("cache-control", "no-store")
    .header("content-disposition", `inline; filename="${title.replace(/[^\w.-]+/g, "_").slice(0, 80)}.html"`)
    // The report is self-contained; forbid any resource loading as defense in depth.
    .header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'")
    .send(html);
}

export async function reportRoutes(app: FastifyInstance, opts: { config: AppConfig; store: Store }) {
  const { config, store } = opts;

  function publicBase(req: FastifyRequest): string {
    if (config.apiPublicUrl) return config.apiPublicUrl.replace(/\/$/, "");
    const proto = (req.headers["x-forwarded-proto"] as string)?.split(",")[0] ?? req.protocol;
    return `${proto}://${req.headers.host}`;
  }

  app.post(
    "/orgs/:orgId/reports",
    { preHandler: [app.authenticate, app.requirePermission("report.create")] },
    async (req, reply) => {
      const body = CreateReportBody.parse(req.body ?? {});
      const member = req.membership!;

      // A scoped report covers one boundary; otherwise the whole org.
      let scope = null;
      if (body.scopeId) {
        scope = await store.scopes.find(member.orgId, body.scopeId);
        if (!scope) return reply.code(404).send({ error: "not_found" });
      }

      const [findings, assets] = await Promise.all([
        store.findings.listByOrg(member.orgId, body.scopeId ? { scopeId: body.scopeId } : {}),
        store.assets.listByOrg(member.orgId, body.scopeId),
      ]);

      const byKind: Record<string, number> = {};
      for (const a of assets) byKind[a.kind] = (byKind[a.kind] ?? 0) + 1;

      const input: ReportInput = {
        org: { name: (await store.orgs.findById(member.orgId))!.name },
        scope: scope ? { value: scope.value, type: scope.type } : null,
        generatedAt: new Date(),
        generatedBy: req.user!.email,
        assets: { total: assets.length, byKind },
        findings: findings.map(
          (f): ReportFinding => ({
            type: f.type,
            severity: f.severity,
            riskScore: f.riskScore,
            kevListed: f.kevListed,
            epss: f.epss,
            cvss: f.cvss,
            cveRefs: f.cveRefs,
            title: f.title,
            assetAddress: f.assetAddress,
            assetKind: f.assetKind,
            remediation: f.remediation,
            evidence: (f.evidence as Record<string, unknown> | null) ?? null,
            status: f.status,
            firstSeenAt: f.firstSeenAt,
            lastSeenAt: f.lastSeenAt,
          }),
        ),
      };

      const model = buildReport(input);
      const html = renderReportHtml(model);
      if (Buffer.byteLength(html) > MAX_REPORT_BYTES) return reply.code(413).send({ error: "report_too_large" });

      const report = await store.transaction(async (tx) => {
        const created = await tx.reports.create({
          orgId: member.orgId,
          scopeId: body.scopeId ?? null,
          title: model.title,
          summary: { ...model.summary, generatedAt: model.generatedAt.toISOString(), scopeLabel: model.scopeLabel },
          content: html,
          byteSize: Buffer.byteLength(html),
          createdById: member.userId,
        });
        await createAuditLogger(tx.audit).record({
          action: "report.create",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          scopeId: body.scopeId ?? null,
          targetId: created.id,
          payload: { scopeLabel: model.scopeLabel, findings: model.summary.total, kev: model.summary.kev },
          ...requestContext(req),
        });
        return created;
      });
      return reply.code(201).send({ report: reportDto(report) });
    },
  );

  app.get(
    "/orgs/:orgId/reports",
    { preHandler: [app.authenticate, app.requirePermission("report.read")] },
    async (req) => ({ reports: (await store.reports.listByOrg(req.membership!.orgId)).map(reportDto) }),
  );

  // Authenticated, in-app view/download.
  app.get(
    "/orgs/:orgId/reports/:reportId/download",
    { preHandler: [app.authenticate, app.requirePermission("report.read")] },
    async (req, reply) => {
      const { reportId } = ReportParams.parse(req.params);
      const meta = await store.reports.find(req.membership!.orgId, reportId);
      if (!meta) return reply.code(404).send({ error: "not_found" });
      const blob = await store.reports.loadContent(reportId);
      if (!blob?.content) return reply.code(404).send({ error: "not_found" });
      return sendHtml(reply, meta.title, blob.content);
    },
  );

  // Mint a short-lived shareable link (no login needed to open it).
  app.post(
    "/orgs/:orgId/reports/:reportId/share",
    { preHandler: [app.authenticate, app.requirePermission("report.create")] },
    async (req, reply) => {
      const { reportId } = ReportParams.parse(req.params);
      const meta = await store.reports.find(req.membership!.orgId, reportId);
      if (!meta) return reply.code(404).send({ error: "not_found" });
      const expiresAtSec = Math.floor(Date.now() / 1000) + config.reportShareTtlHours * 3600;
      const token = signDownloadToken(reportId, expiresAtSec, config.refreshSecret);
      await createAuditLogger(store.audit).record({
        action: "report.shared",
        actor: { type: "user", id: req.membership!.userId },
        orgId: req.membership!.orgId,
        targetId: reportId,
        payload: { expiresAt: new Date(expiresAtSec * 1000).toISOString() },
        ...requestContext(req),
      });
      return { url: `${publicBase(req)}/reports/download?token=${token}`, expiresAt: new Date(expiresAtSec * 1000) };
    },
  );

  // Public, signed, expiring download. No auth: the token is the capability.
  app.get("/reports/download", async (req, reply) => {
    const { token } = DownloadQuery.parse(req.query);
    const reportId = verifyDownloadToken(token, config.refreshSecret);
    if (!reportId) return reply.code(403).send({ error: "invalid_or_expired_link" });
    const blob = await store.reports.loadContent(reportId);
    if (!blob?.content) return reply.code(404).send({ error: "not_found" });
    return sendHtml(reply, blob.title, blob.content);
  });
}
