import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { createMemoryStore } from "../src/store/memory.js";
import { createMemoryScanQueue } from "../src/queue.js";
import { testConfig } from "./helpers.js";

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

describe("health & readiness", () => {
  it("/health is always ok", async () => {
    app = await buildApp({ config: testConfig, store: createMemoryStore(), queue: createMemoryScanQueue() });
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
  });

  it("/ready is 200 when dependencies are reachable, 503 when not", async () => {
    app = await buildApp({ config: testConfig, store: createMemoryStore(), queue: createMemoryScanQueue(), readiness: async () => ({ db: true, redis: true }) });
    expect((await app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(200);
    await app.close();

    app = await buildApp({ config: testConfig, store: createMemoryStore(), queue: createMemoryScanQueue(), readiness: async () => ({ db: false }) });
    const bad = await app.inject({ method: "GET", url: "/ready" });
    expect(bad.statusCode).toBe(503);
    expect(bad.json().status).toBe("degraded");
  });
});
