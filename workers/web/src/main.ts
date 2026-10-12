import { prisma } from "@aegis/db";
import { createPublicResolver, startEngineWorker } from "@aegis/worker-kit";
import { createWebEngine } from "./engine.js";
import { pinnedGet } from "./http.js";

const log = (msg: string, data?: Record<string, unknown>) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), worker: "web", msg, ...data }));

const redisUrl = process.env.REDIS_URL;
if (!redisUrl) throw new Error("REDIS_URL is required");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");

const engine = createWebEngine({
  resolve: createPublicResolver(),
  request: (url, ip, signal) => pinnedGet(url, ip, { timeoutMs: 10_000, maxBody: 16 * 1024, signal }),
});

const { close } = startEngineWorker({
  engine,
  redisUrl,
  prisma,
  concurrency: Number(process.env.WEB_CONCURRENCY ?? 2),
  jobTimeoutMs: Number(process.env.WEB_JOB_TIMEOUT_MS ?? 10 * 60_000),
  log,
});
log("listening", { queue: "aegis-scan-web" });

const shutdown = async (signal: string) => {
  log("shutting down", { signal });
  await close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
