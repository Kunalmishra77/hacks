import { prisma } from "@aegis/db";
import { createMemoryRateLimiter } from "@aegis/core";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { checkEvictionPolicy, connectRedis, createRedisRateLimiter } from "./redis.js";
import { createPrismaStore } from "./store/prisma.js";

const config = loadConfig();

const redis = config.redisUrl ? connectRedis(config.redisUrl) : undefined;
if (redis) await redis.connect();

const app = await buildApp({
  config,
  store: createPrismaStore(prisma),
  logger: true,
  redis,
  limiter: redis ? createRedisRateLimiter(redis) : createMemoryRateLimiter(),
});

if (redis) {
  const policy = await checkEvictionPolicy(redis);
  if (policy === "unknown") app.log.warn("could not read Redis maxmemory-policy; make sure it is noeviction");
  else if (policy !== "ok") app.log.warn({ policy }, "Redis maxmemory-policy should be noeviction (queued jobs may be evicted)");
} else {
  app.log.warn("REDIS_URL not set: using in-process rate limits (single process only, dev only)");
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  await app.close();
  redis?.disconnect();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.host, port: config.port });
