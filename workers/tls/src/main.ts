import { prisma } from "@aegis/db";
import { createPublicResolver, runTool, startEngineWorker } from "@aegis/worker-kit";
import { createTlsEngine } from "./engine.js";
import { runTestssl } from "./testssl.js";

const log = (msg: string, data?: Record<string, unknown>) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), worker: "tls", msg, ...data }));

const redisUrl = process.env.REDIS_URL;
if (!redisUrl) throw new Error("REDIS_URL is required");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const TESTSSL = process.env.TESTSSL_BIN ?? "/opt/testssl/testssl.sh";

await runTool({ bin: TESTSSL, args: ["--version"], timeoutMs: 30_000 }).catch((e: Error) => {
  log("required tool missing", { bin: TESTSSL, error: e.message });
  process.exit(1);
});

const engine = createTlsEngine({
  resolve: createPublicResolver(),
  testssl: (t, signal) => runTestssl(t, signal, TESTSSL),
});

const { close } = startEngineWorker({
  engine,
  redisUrl,
  prisma,
  concurrency: Number(process.env.TLS_CONCURRENCY ?? 1),
  jobTimeoutMs: Number(process.env.TLS_JOB_TIMEOUT_MS ?? 20 * 60_000),
  log,
});
log("listening", { queue: "aegis-scan-tls" });

const shutdown = async (signal: string) => {
  log("shutting down", { signal });
  await close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
