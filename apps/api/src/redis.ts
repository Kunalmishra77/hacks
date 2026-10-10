import { Redis } from "ioredis";
import type { RateLimiter } from "@aegis/core";

const KEY_PREFIX = "aegis:rl:";

// INCR + PEXPIRE-on-first-hit in one atomic step, so concurrent API processes
// share one fixed window per key.
const HIT_SCRIPT = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
return {c, ttl}
`;

export function createRedisRateLimiter(redis: Redis, prefix = KEY_PREFIX): RateLimiter {
  return {
    async hit(key, limit, windowMs) {
      const [count, ttl] = (await redis.eval(HIT_SCRIPT, 1, prefix + key, String(windowMs))) as [number, number];
      if (count <= limit) return { allowed: true, retryAfterMs: 0 };
      return { allowed: false, retryAfterMs: ttl > 0 ? ttl : windowMs };
    },
  };
}

export function connectRedis(url: string): Redis {
  return new Redis(url, {
    maxRetriesPerRequest: 2,
    connectTimeout: 10_000,
    enableOfflineQueue: false,
    lazyConnect: true,
  });
}

/**
 * BullMQ (Phase 2) needs maxmemory-policy=noeviction, or Redis may silently
 * drop queued scan jobs under memory pressure. Managed Redis often blocks
 * CONFIG, in which case we can't check and say so.
 */
export async function checkEvictionPolicy(redis: Redis): Promise<"ok" | "unknown" | string> {
  try {
    const res = (await redis.config("GET", "maxmemory-policy")) as string[];
    const policy = res?.[1];
    if (!policy) return "unknown";
    return policy === "noeviction" ? "ok" : policy;
  } catch {
    return "unknown";
  }
}
