import { prisma } from "@aegis/db";
import { createPublicResolver, runTool, startEngineWorker } from "@aegis/worker-kit";
import { createNetworkEngine } from "./engine.js";
import { runFingerprintx } from "./fingerprintx.js";
import { runNaabu } from "./naabu.js";

const log = (msg: string, data?: Record<string, unknown>) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), worker: "network", msg, ...data }));

const redisUrl = process.env.REDIS_URL;
if (!redisUrl) throw new Error("REDIS_URL is required");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const NAABU = process.env.NAABU_BIN ?? "naabu";
const FINGERPRINTX = process.env.FINGERPRINTX_BIN ?? "fingerprintx";

for (const [bin, arg] of [[NAABU, "-version"], [FINGERPRINTX, "--help"]] as const) {
  await runTool({ bin, args: [arg], timeoutMs: 20_000 }).catch((e: Error) => {
    log("required tool missing", { bin, error: e.message });
    process.exit(1);
  });
}

const engine = createNetworkEngine({
  resolve: createPublicResolver(),
  naabu: (ip, rate, signal) => runNaabu(ip, rate, signal, NAABU),
  fingerprintx: (ip, ports, signal) => runFingerprintx(ip, ports, signal, FINGERPRINTX),
});

const { close } = startEngineWorker({
  engine,
  redisUrl,
  prisma,
  concurrency: Number(process.env.NETWORK_CONCURRENCY ?? 1),
  jobTimeoutMs: Number(process.env.NETWORK_JOB_TIMEOUT_MS ?? 20 * 60_000),
  log,
});
log("listening", { queue: "aegis-scan-network" });

const shutdown = async (signal: string) => {
  log("shutting down", { signal });
  await close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
