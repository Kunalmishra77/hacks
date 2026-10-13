import { Cron } from "croner";

// Cron helpers for recurring scans (Phase 6). Standard 5-field cron, evaluated
// in UTC so schedules are predictable regardless of server timezone. A minimum
// interval keeps a schedule from hammering a target (which can look like an
// attack even when authorized).

export interface CronPolicy {
  minIntervalMinutes?: number;
}

function parse(expr: string): Cron | null {
  if (typeof expr !== "string" || !expr.trim()) return null;
  try {
    const c = new Cron(expr.trim(), { timezone: "UTC" });
    // croner accepts 6-field (with seconds); require the standard 5 fields.
    if (expr.trim().split(/\s+/).length !== 5) return null;
    return c.nextRun() ? c : null;
  } catch {
    return null;
  }
}

export function nextCronRun(expr: string, from: Date = new Date()): Date | null {
  const c = parse(expr);
  return c ? (c.nextRun(from) ?? null) : null;
}

export function isValidCron(expr: string, policy: CronPolicy = {}): boolean {
  const c = parse(expr);
  if (!c) return false;
  const min = policy.minIntervalMinutes ?? 0;
  if (min > 0) {
    // Check the gap between the next few runs is never shorter than the minimum.
    const runs = c.nextRuns(5);
    for (let i = 1; i < runs.length; i++) {
      if (runs[i]!.getTime() - runs[i - 1]!.getTime() < min * 60_000) return false;
    }
  }
  return true;
}
