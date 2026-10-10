// Runs against a real Redis. Skipped unless TEST_REDIS_URL is set.
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Redis } from "ioredis";
import { connectRedis, createRedisRateLimiter } from "../src/redis.js";

const url = process.env.TEST_REDIS_URL;

describe.skipIf(!url)("redis rate limiter (integration)", { timeout: 30_000 }, () => {
  let redis: Redis;
  // Unique namespace per run; keys expire on their own.
  const prefix = `aegis:test:${randomUUID()}:`;

  beforeAll(async () => {
    redis = connectRedis(url!);
    await redis.connect();
  });
  afterAll(() => redis?.disconnect());

  it("enforces a shared fixed window and reports when to retry", async () => {
    const limiter = createRedisRateLimiter(redis, prefix);
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await limiter.hit("scope:s1", 3, 5_000));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results[3]!.retryAfterMs).toBeGreaterThan(0);
    expect(results[3]!.retryAfterMs).toBeLessThanOrEqual(5_000);

    // A second limiter (another API process) shares the same window.
    const other = createRedisRateLimiter(redis, prefix);
    expect((await other.hit("scope:s1", 3, 5_000)).allowed).toBe(false);
    expect((await other.hit("scope:s2", 3, 5_000)).allowed).toBe(true);

    const ttl = await redis.pttl(`${prefix}scope:s1`);
    expect(ttl).toBeGreaterThan(0);
  });
});
