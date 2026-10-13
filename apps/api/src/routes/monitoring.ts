import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createAuditLogger, ENGINES, isValidCron, nextCronRun, SEVERITIES } from "@aegis/core";
import type { AppConfig } from "../config.js";
import type { ChannelRecord, ScheduleRecord, Store } from "../store/types.js";
import { requestContext } from "./context.js";

// Monitoring config (Phase 6): recurring scan schedules and notification
// channels. Managing both is Admin-level, like scope management.

const MIN_INTERVAL_MINUTES = 60; // schedules run hourly at most

const ScheduleBody = z.object({
  scopeId: z.string().uuid(),
  cron: z.string().min(1).max(120),
  engines: z.array(z.enum(ENGINES)).min(1),
});
const SchedulePatch = z.object({
  cron: z.string().min(1).max(120).optional(),
  engines: z.array(z.enum(ENGINES)).min(1).optional(),
  enabled: z.boolean().optional(),
});
const ScheduleParams = z.object({ orgId: z.string().uuid(), scheduleId: z.string().uuid() });

const ChannelBody = z.object({
  type: z.enum(["SLACK", "WEBHOOK", "EMAIL", "WHATSAPP"]),
  name: z.string().trim().min(1).max(100),
  target: z.string().trim().min(1).max(500),
  minSeverity: z.enum(SEVERITIES).default("HIGH"),
  kevAlways: z.boolean().default(true),
});
const ChannelPatch = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  target: z.string().trim().min(1).max(500).optional(),
  minSeverity: z.enum(SEVERITIES).optional(),
  kevAlways: z.boolean().optional(),
  enabled: z.boolean().optional(),
});
const ChannelParams = z.object({ orgId: z.string().uuid(), channelId: z.string().uuid() });

function scheduleDto(s: ScheduleRecord) {
  return { id: s.id, scopeId: s.scopeId, cron: s.cron, engines: s.engines, enabled: s.enabled, lastRunAt: s.lastRunAt, nextRunAt: s.nextRunAt, createdAt: s.createdAt };
}
function channelDto(c: ChannelRecord) {
  return { id: c.id, type: c.type, name: c.name, target: c.target, minSeverity: c.minSeverity, kevAlways: c.kevAlways, enabled: c.enabled, lastNotifiedAt: c.lastNotifiedAt, lastError: c.lastError, createdAt: c.createdAt };
}

/** Lightweight shape check so an obviously wrong target is rejected at create. */
function validTarget(type: string, target: string): boolean {
  if (type === "EMAIL") return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(target);
  if (type === "WHATSAPP") return /^\+?[0-9]{8,15}$/.test(target);
  try {
    return new URL(target).protocol === "https:";
  } catch {
    return false;
  }
}

export async function monitoringRoutes(app: FastifyInstance, opts: { config: AppConfig; store: Store }) {
  const { store } = opts;

  // ── Schedules ─────────────────────────────────────────────────────
  app.post(
    "/orgs/:orgId/schedules",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const body = ScheduleBody.parse(req.body);
      const member = req.membership!;
      if (!isValidCron(body.cron, { minIntervalMinutes: MIN_INTERVAL_MINUTES })) {
        return reply.code(400).send({ error: "invalid_cron", message: "Use standard 5-field cron, running at most hourly." });
      }
      const scope = await store.scopes.find(member.orgId, body.scopeId);
      if (!scope) return reply.code(404).send({ error: "not_found" });
      const bad = body.engines.filter((e) => !scope.allowedEngines.includes(e));
      if (bad.length) return reply.code(400).send({ error: "engine_not_allowed", message: `not allowed for this scope: ${bad.join(", ")}` });

      const schedule = await store.transaction(async (tx) => {
        const created = await tx.schedules.create({
          orgId: member.orgId, scopeId: body.scopeId, cron: body.cron, engines: [...new Set(body.engines)],
          createdById: member.userId, nextRunAt: nextCronRun(body.cron, new Date())!,
        });
        await createAuditLogger(tx.audit).record({
          action: "schedule.create", actor: { type: "user", id: member.userId }, orgId: member.orgId, scopeId: body.scopeId, targetId: created.id,
          payload: { cron: body.cron, engines: created.engines }, ...requestContext(req),
        });
        return created;
      });
      return reply.code(201).send({ schedule: scheduleDto(schedule) });
    },
  );

  app.get(
    "/orgs/:orgId/schedules",
    { preHandler: [app.authenticate, app.requirePermission("scope.read")] },
    async (req) => ({ schedules: (await store.schedules.listByOrg(req.membership!.orgId)).map(scheduleDto) }),
  );

  app.patch(
    "/orgs/:orgId/schedules/:scheduleId",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const { scheduleId } = ScheduleParams.parse(req.params);
      const patch = SchedulePatch.parse(req.body);
      const member = req.membership!;
      if (patch.cron && !isValidCron(patch.cron, { minIntervalMinutes: MIN_INTERVAL_MINUTES })) {
        return reply.code(400).send({ error: "invalid_cron" });
      }
      const next = patch.cron ? nextCronRun(patch.cron, new Date()) : undefined;
      const updated = await store.schedules.update(member.orgId, scheduleId, { ...patch, ...(next !== undefined ? { nextRunAt: next } : {}) });
      if (!updated) return reply.code(404).send({ error: "not_found" });
      return { schedule: scheduleDto(updated) };
    },
  );

  app.delete(
    "/orgs/:orgId/schedules/:scheduleId",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const { scheduleId } = ScheduleParams.parse(req.params);
      const ok = await store.schedules.remove(req.membership!.orgId, scheduleId);
      if (!ok) return reply.code(404).send({ error: "not_found" });
      return reply.code(204).send();
    },
  );

  // ── Notification channels ─────────────────────────────────────────
  app.post(
    "/orgs/:orgId/channels",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const body = ChannelBody.parse(req.body);
      const member = req.membership!;
      if (!validTarget(body.type, body.target)) {
        return reply.code(400).send({ error: "invalid_target", message: `not a valid ${body.type.toLowerCase()} target` });
      }
      const channel = await store.transaction(async (tx) => {
        const created = await tx.channels.create({
          orgId: member.orgId, type: body.type, name: body.name, target: body.target, minSeverity: body.minSeverity, kevAlways: body.kevAlways, createdById: member.userId,
        });
        await createAuditLogger(tx.audit).record({
          action: "channel.create", actor: { type: "user", id: member.userId }, orgId: member.orgId, targetId: created.id,
          // Target may be a webhook URL with a secret path; don't log it.
          payload: { type: body.type, name: body.name, minSeverity: body.minSeverity }, ...requestContext(req),
        });
        return created;
      });
      return reply.code(201).send({ channel: channelDto(channel) });
    },
  );

  app.get(
    "/orgs/:orgId/channels",
    { preHandler: [app.authenticate, app.requirePermission("scope.read")] },
    async (req) => ({ channels: (await store.channels.listByOrg(req.membership!.orgId)).map(channelDto) }),
  );

  app.patch(
    "/orgs/:orgId/channels/:channelId",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const { channelId } = ChannelParams.parse(req.params);
      const patch = ChannelPatch.parse(req.body);
      const member = req.membership!;
      const existing = await store.channels.find(member.orgId, channelId);
      if (!existing) return reply.code(404).send({ error: "not_found" });
      if (patch.target && !validTarget(existing.type, patch.target)) return reply.code(400).send({ error: "invalid_target" });
      const updated = await store.channels.update(member.orgId, channelId, patch);
      return { channel: channelDto(updated!) };
    },
  );

  app.delete(
    "/orgs/:orgId/channels/:channelId",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const { channelId } = ChannelParams.parse(req.params);
      const ok = await store.channels.remove(req.membership!.orgId, channelId);
      if (!ok) return reply.code(404).send({ error: "not_found" });
      return reply.code(204).send();
    },
  );
}
