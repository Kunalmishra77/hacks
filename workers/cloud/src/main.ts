import { prisma } from "@aegis/db";
import { createPrismaWorkerStore, runTool, startEngineWorker } from "@aegis/worker-kit";
import { assumeReadOnlyRole } from "./aws.js";
import { createCloudEngine } from "./engine.js";
import { runProwler } from "./prowler.js";

const log = (msg: string, data?: Record<string, unknown>) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), worker: "cloud", msg, ...data }));

const redisUrl = process.env.REDIS_URL;
if (!redisUrl) throw new Error("REDIS_URL is required");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const PROWLER = process.env.PROWLER_BIN ?? "prowler";

await runTool({ bin: PROWLER, args: ["--version"], timeoutMs: 60_000 }).catch((e: Error) => {
  log("required tool missing", { bin: PROWLER, error: e.message });
  process.exit(1);
});

// The role lookup reads the scope's stored ARN + external ID. We assume that
// role (capped read-only), run prowler, and hand the engine only the findings.
const store = createPrismaWorkerStore(prisma);
const engine = createCloudEngine({
  async scanAccount({ scopeId, accountId, signal }) {
    const role = await store.cloudRole(scopeId);
    if (!role) throw new Error("scope has no cloud role configured");
    const creds = await assumeReadOnlyRole(role.roleArn, role.externalId, signal);
    return runProwler(creds, accountId, signal, PROWLER);
  },
});

const { close } = startEngineWorker({
  engine,
  redisUrl,
  prisma,
  concurrency: Number(process.env.CLOUD_CONCURRENCY ?? 1),
  jobTimeoutMs: Number(process.env.CLOUD_JOB_TIMEOUT_MS ?? 20 * 60_000),
  log,
});
log("listening", { queue: "aegis-scan-cloud" });

const shutdown = async (signal: string) => {
  log("shutting down", { signal });
  await close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
