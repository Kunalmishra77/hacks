import { prisma } from "@aegis/db";
import { createMemoryRateLimiter, createScopeGate, createAuditLogger } from "@aegis/core";
import { createCveIntel } from "@aegis/cve";
import { startEnrichmentWorker } from "@aegis/worker-kit";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createEmailSender } from "./notify/email.js";
import { dispatchScanAlerts } from "./notify/dispatch.js";
import { createSenders } from "./notify/senders.js";
import { checkEvictionPolicy, connectRedis, createRedisRateLimiter } from "./redis.js";
import { runDueSchedules } from "./scheduler.js";
import { createPrismaStore } from "./store/prisma.js";
import { createBullScanQueue } from "./queue.js";

const config = loadConfig();

const redis = config.redisUrl ? connectRedis(config.redisUrl) : undefined;
if (redis) await redis.connect();

const store = createPrismaStore(prisma);
const app = await buildApp({
  config,
  store,
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
// New-exposure alerts (Phase 6): built here where SMTP / WhatsApp config live.
const senders = createSenders({
  sendEmail: await createEmailSender(config.smtpUrl, config.smtpFrom),
  whatsapp: config.whatsapp,
});
const dashboardUrl = config.webPublicUrl ? `${config.webPublicUrl.replace(/\/$/, "")}/dashboard` : undefined;

async function dispatchAlertsForScan(scanId: string, orgId: string): Promise<void> {
  const scan = await store.scans.find(orgId, scanId);
  if (!scan) return;
  const scope = await store.scopes.find(orgId, scan.scopeId);
  // Only findings first-seen since this scan started count as "new".
  await dispatchScanAlerts(
    { store, senders, dashboardUrl, log: (m, d) => app.log.info({ ...d }, m) },
    { orgId, scanId, scopeLabel: scope?.value ?? "a boundary", since: scan.createdAt },
  );
}

let enrichment: { close(): Promise<void> } | undefined;
if (config.redisUrl && config.cveEnrichment) {
  if (!config.nvdApiKey) app.log.warn("NVD_API_KEY not set: CVE enrichment runs with NVD's lower anonymous rate limit");
  enrichment = startEnrichmentWorker({
    redisUrl: config.redisUrl,
    prisma,
    intel: createCveIntel({ apiKey: config.nvdApiKey, log: (msg, data) => app.log.warn({ ...data }, msg) }),
    log: (msg, data) => app.log.info({ ...data }, msg),
    afterEnrich: dispatchAlertsForScan,
  });
  app.log.info("CVE enrichment worker started");
}

// Schedule tick: fire due recurring scans every minute (needs the queue).
let schedulerTimer: NodeJS.Timeout | undefined;
if (config.redisUrl && config.scheduler) {
  const gate = createScopeGate({ repo: store.gate, limiter: createMemoryRateLimiter(), audit: createAuditLogger(store.audit) });
  const queue = createBullScanQueue(redis!);
  let ticking = false;
  schedulerTimer = setInterval(async () => {
    if (ticking) return;
    ticking = true;
    try {
      const s = await runDueSchedules({ store, gate, queue, config, log: (m, d) => app.log.info({ ...d }, m) });
      if (s.schedulesRun > 0) app.log.info({ ...s }, "scheduler tick");
    } catch (e) {
      app.log.error({ error: (e as Error).message }, "scheduler tick failed");
    } finally {
      ticking = false;
    }
  }, 60_000);
  app.log.info("scheduler started");
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  if (schedulerTimer) clearInterval(schedulerTimer);
  await app.close();
  await enrichment?.close();
  redis?.disconnect();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.host, port: config.port });
