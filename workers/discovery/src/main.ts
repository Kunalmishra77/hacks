import { prisma } from "@aegis/db";
import { createPublicResolver, runTool, startEngineWorker } from "@aegis/worker-kit";
import { fetchCrtSh } from "./crtsh.js";
import { createDiscoveryEngine } from "./engine.js";
import { runHttpx } from "./httpx.js";
import { runSubfinder } from "./subfinder.js";

const log = (msg: string, data?: Record<string, unknown>) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), worker: "discovery", msg, ...data }));

const redisUrl = process.env.REDIS_URL;
if (!redisUrl) throw new Error("REDIS_URL is required");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const SUBFINDER = process.env.SUBFINDER_BIN ?? "subfinder";
const HTTPX = process.env.HTTPX_BIN ?? "httpx";

// Refuse to start without the tools: a worker that silently skips its probe
// would report "no services" when it simply couldn't look.
for (const bin of [SUBFINDER, HTTPX]) {
  await runTool({ bin, args: ["-version"], timeoutMs: 20_000 }).catch((e: Error) => {
    log("required tool missing", { bin, error: e.message });
    process.exit(1);
  });
}

const resolve = createPublicResolver();
const engine = createDiscoveryEngine({
  crtsh: fetchCrtSh,
  subfinder: (apex, signal) => runSubfinder(apex, signal, SUBFINDER),
  resolve,
  httpx: (hosts, rate, signal) => runHttpx(hosts, rate, signal, HTTPX),
});

const { close } = startEngineWorker({
  engine,
  redisUrl,
  prisma,
  concurrency: Number(process.env.DISCOVERY_CONCURRENCY ?? 1),
  jobTimeoutMs: Number(process.env.DISCOVERY_JOB_TIMEOUT_MS ?? 30 * 60_000),
  log,
});
log("listening", { queue: "aegis-scan-discovery" });

const shutdown = async (signal: string) => {
  log("shutting down", { signal });
  await close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
