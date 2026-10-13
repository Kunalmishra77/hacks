import { nextCronRun, type AssetKind, type Engine, type ScopeGate } from "@aegis/core";
import type { AppConfig } from "./config.js";
import type { ScanQueue } from "./queue.js";
import { requestScan } from "./scans/request.js";
import type { ScheduleRecord, Store } from "./store/types.js";

// The monitoring loop (Phase 6): find due schedules and fire their scans
// through the Scope Authorization Gate, exactly like a human request. A
// schedule can't scan anything a user couldn't — the gate still enforces
// verification, allowed engines, kill-switch, approval and rate limits.

export interface SchedulerDeps {
  store: Store;
  gate: ScopeGate;
  queue: ScanQueue;
  config: AppConfig;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

/** Asset kinds each engine targets. Discovery seeds from the apex/IP. */
const ENGINE_TARGETS: Record<Engine, AssetKind[]> = {
  DISCOVERY: ["DOMAIN", "IP"],
  NETWORK: ["DOMAIN", "SUBDOMAIN", "IP"],
  TLS: ["SERVICE", "DOMAIN", "SUBDOMAIN", "IP"],
  WEB: ["SERVICE", "DOMAIN", "SUBDOMAIN", "IP"],
  CLOUD: ["CLOUD_RESOURCE"],
  DEPS: [],
};

const MAX_SCHEDULES_PER_TICK = 20;
const MAX_SCANS_PER_SCHEDULE = 50;

export interface ScheduleRunSummary {
  schedulesRun: number;
  queued: number;
  pendingApproval: number;
  denied: number;
  throttled: number;
}

async function runOneSchedule(deps: SchedulerDeps, schedule: ScheduleRecord, summary: ScheduleRunSummary): Promise<void> {
  const log = deps.log ?? (() => {});
  const assets = await deps.store.assets.listByOrg(schedule.orgId, schedule.scopeId);
  const actor = { type: "system" as const };
  let requested = 0;

  for (const engine of schedule.engines) {
    const kinds = ENGINE_TARGETS[engine];
    const targets = assets.filter((a) => kinds.includes(a.kind));
    for (const asset of targets) {
      if (requested >= MAX_SCANS_PER_SCHEDULE) break;
      requested++;
      const result = await requestScan(
        { store: deps.store, gate: deps.gate, queue: deps.queue, maxConcurrentScansPerOrg: deps.config.gateLimits.maxConcurrentScansPerOrg },
        { orgId: schedule.orgId, assetId: asset.id, engine, actor, requestedById: schedule.createdById, scheduleId: schedule.id },
      );
      if (result.ok) {
        if (result.status === "QUEUED") summary.queued++;
        else summary.pendingApproval++;
      } else if (result.kind === "denied") {
        summary.denied++;
      } else if (result.kind === "throttled_concurrency") {
        summary.throttled++;
      } else {
        log("schedule scan could not be queued", { scheduleId: schedule.id, scanId: result.scan.id });
      }
    }
  }
  log("schedule run", { scheduleId: schedule.id, requested });
}

/** Runs every due schedule once, then advances each to its next cron time. */
export async function runDueSchedules(deps: SchedulerDeps, now: Date = new Date()): Promise<ScheduleRunSummary> {
  const summary: ScheduleRunSummary = { schedulesRun: 0, queued: 0, pendingApproval: 0, denied: 0, throttled: 0 };
  const due = await deps.store.schedules.dueForRun(now, MAX_SCHEDULES_PER_TICK);
  for (const schedule of due) {
    try {
      await runOneSchedule(deps, schedule, summary);
    } catch (e) {
      (deps.log ?? (() => {}))("schedule run failed", { scheduleId: schedule.id, error: (e as Error).message });
    } finally {
      // Always advance, even on error, so one bad schedule can't jam the loop.
      await deps.store.schedules.markRun(schedule.id, now, nextCronRun(schedule.cron, now));
      summary.schedulesRun++;
    }
  }
  return summary;
}
