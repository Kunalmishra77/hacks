import { describe, expect, it } from "vitest";
import { isValidCron, nextCronRun } from "../src/index.js";

describe("cron scheduling", () => {
  it("validates cron expressions", () => {
    expect(isValidCron("0 3 * * *")).toBe(true); // 03:00 daily
    expect(isValidCron("*/15 * * * *")).toBe(true);
    expect(isValidCron("0 0 * * 1")).toBe(true); // Mondays
    expect(isValidCron("")).toBe(false);
    expect(isValidCron("not a cron")).toBe(false);
    expect(isValidCron("60 0 * * *")).toBe(false); // minute out of range
  });

  it("computes the next run strictly after a given time, in UTC", () => {
    const from = new Date("2026-10-13T02:30:00Z");
    const next = nextCronRun("0 3 * * *", from);
    expect(next?.toISOString()).toBe("2026-10-13T03:00:00.000Z");
    // If we're past today's 03:00, it rolls to tomorrow.
    expect(nextCronRun("0 3 * * *", new Date("2026-10-13T03:00:00Z"))?.toISOString()).toBe("2026-10-14T03:00:00.000Z");
  });

  it("returns null for an invalid expression", () => {
    expect(nextCronRun("nonsense", new Date())).toBeNull();
  });

  it("enforces a minimum interval so schedules can't hammer targets", () => {
    // A once-a-minute cron is rejected: monitoring runs hourly at most.
    expect(isValidCron("* * * * *", { minIntervalMinutes: 60 })).toBe(false);
    expect(isValidCron("*/30 * * * *", { minIntervalMinutes: 60 })).toBe(false);
    expect(isValidCron("0 * * * *", { minIntervalMinutes: 60 })).toBe(true);
  });
});
