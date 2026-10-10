import { describe, expect, it } from "vitest";
import { createAuditLogger, createMemoryAuditSink } from "../src/index.js";

describe("audit", () => {
  it("appends events with actor, action and timestamp", async () => {
    const sink = createMemoryAuditSink();
    const at = new Date("2026-01-01T00:00:00Z");
    const audit = createAuditLogger(sink, { now: () => at });

    await audit.record({ action: "auth.login", actor: { type: "user", id: "u1" }, orgId: null });
    await audit.record({ action: "org.create", actor: { type: "user", id: "u1" }, orgId: "o1" });

    expect(sink.events.map((e) => e.action)).toEqual(["auth.login", "org.create"]);
    expect(sink.events[1]).toMatchObject({ actor: { type: "user", id: "u1" }, orgId: "o1", createdAt: at });
  });

  it("returns frozen events that cannot be mutated after the fact", async () => {
    const sink = createMemoryAuditSink();
    const audit = createAuditLogger(sink);
    const ev = await audit.record({
      action: "member.invite",
      actor: { type: "user", id: "u1" },
      payload: { email: "a@example.com", nested: { role: "VIEWER" } },
    });

    expect(Object.isFrozen(ev)).toBe(true);
    expect(() => {
      (ev as { action: string }).action = "tampered";
    }).toThrow(TypeError);
    expect(() => {
      (ev.payload!.nested as { role: string }).role = "OWNER";
    }).toThrow(TypeError);
  });

  it("exposes no update or delete on the sink, and its view is a copy", async () => {
    const sink = createMemoryAuditSink();
    const audit = createAuditLogger(sink);
    await audit.record({ action: "auth.login", actor: { type: "user", id: "u1" } });

    expect(Object.keys(sink)).not.toEqual(expect.arrayContaining(["update", "delete", "remove"]));
    (sink.events as unknown as unknown[]).length = 0;
    expect(sink.events).toHaveLength(1);
  });

  it("redacts secrets from payloads", async () => {
    const sink = createMemoryAuditSink();
    const audit = createAuditLogger(sink);
    await audit.record({
      action: "auth.login_failed",
      actor: { type: "anonymous" },
      payload: { email: "a@example.com", password: "hunter2", inner: { refreshToken: "x" } },
    });
    expect(sink.events[0]!.payload).toEqual({
      email: "a@example.com",
      password: "[REDACTED]",
      inner: { refreshToken: "[REDACTED]" },
    });
  });

  it("propagates sink failures instead of swallowing them", async () => {
    const audit = createAuditLogger({
      append: async () => {
        throw new Error("db down");
      },
    });
    await expect(audit.record({ action: "auth.login", actor: { type: "system" } })).rejects.toThrow("db down");
  });
});

