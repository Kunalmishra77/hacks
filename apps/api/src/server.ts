import { prisma } from "@aegis/db";
import { createMemoryRateLimiter } from "@aegis/core";
import { createCveIntel } from "@aegis/cve";
import { startEnrichmentWorker } from "@aegis/worker-kit";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { checkEvictionPolicy, connectRedis, createRedisRateLimiter } from "./redis.js";
import { createPrismaStore } from "./store/prisma.js";
import { createBullScanQueue } from "./queue.js";

const config = loadConfig();

const redis = config.redisUrl ? connectRedis(config.redisUrl) : undefined;
if (redis) await redis.connect();

const app = await buildApp({
  config,
  store: createPrismaStore(prisma),
  logger: true,
  redis,
  limiter: redis ? createRedisRateLimiter(redis) : createMemoryRateLimiter(),
  queue: redis ? createBullScanQueue(redis) : undefined,
});

if (redis) {
  const policy = await checkEvictionPolicy(redis);
  if (policy === "unknown") app.log.warn("could not read Redis maxmemory-policy; make sure it is noeviction");
  else if (policy !== "ok") app.log.warn({ policy }, "Redis maxmemory-policy should be noeviction (queued jobs may be evicted)");
} else {
  app.log.warn("REDIS_URL not set: in-process rate limits and NO scan queue (scans are recorded but never run)");
}

// CVE enrichment (Phase 3.5) runs here, where the NVD key lives, not on the
// scan workers. Without a key NVD still works at a lower rate limit; EPSS and
// KEV need no key.
let enrichment: { close(): Promise<void> } | undefined;
if (config.redisUrl && config.cveEnrichment) {
  if (!config.nvdApiKey) app.log.warn("NVD_API_KEY not set: CVE enrichment runs with NVD's lower anonymous rate limit");
  enrichment = startEnrichmentWorker({
    redisUrl: config.redisUrl,
    prisma,
    intel: createCveIntel({ apiKey: config.nvdApiKey, log: (msg, data) => app.log.warn({ ...data }, msg) }),
    log: (msg, data) => app.log.info({ ...data }, msg),
  });
  app.log.info("CVE enrichment worker started");
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  await app.close();
  await enrichment?.close();
  redis?.disconnect();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.host, port: config.port });
