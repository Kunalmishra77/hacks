import { Worker, type Job } from "bullmq";
import { Redis } from "ioredis";
import {
  createAuditLogger,
  createMemoryRateLimiter,
  createScopeGate,
  scanQueueName,
  type ScanJobPayload,
} from "@aegis/core";
import type { PrismaClient } from "@aegis/db";
import { runScanJob, type EngineImpl, type JobOutcome } from "./runner.js";
import { createPrismaWorkerStore } from "./store.js";

export interface EngineWorkerOptions {
  engine: EngineImpl;
  redisUrl: string;
  prisma: PrismaClient;
  /** Jobs this process runs at once. Keep low: each job drives external tools. */
  concurrency?: number;
  jobTimeoutMs?: number;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

/**
 * Consumes the engine's queue. The queue only carries untrusted hints; each
 * job goes through runScanJob, which re-checks the Scope Authorization Gate
 * before and during the run.
 */
export function startEngineWorker(opts: EngineWorkerOptions): { worker: Worker; close(): Promise<void> } {
  const log = opts.log ?? ((msg, data) => console.log(JSON.stringify({ msg, ...data })));
  const connection = new Redis(opts.redisUrl, { maxRetriesPerRequest: null });
  const store = createPrismaWorkerStore(opts.prisma);
  // Workers never consume the enqueue rate limit (job_start/heartbeat skip it),
  // so an in-process limiter is fine here.
  const gate = createScopeGate({ repo: store.gate, limiter: createMemoryRateLimiter(), audit: createAuditLogger(store.audit) });

  const worker = new Worker<ScanJobPayload, JobOutcome>(
    scanQueueName(opts.engine.engine),
    async (job: Job<ScanJobPayload>) => {
      const outcome = await runScanJob(job.data, {
        gate,
        store,
        engine: opts.engine,
        jobTimeoutMs: opts.jobTimeoutMs,
        log: (msg, data) => log(msg, { jobId: job.id, ...data }),
      });
      log("job finished", { jobId: job.id, scanId: job.data?.scanId, ...outcome });
      return outcome;
    },
    {
      connection,
      concurrency: opts.concurrency ?? 1,
      // Long tool runs: keep the lock while the job is alive.
      lockDuration: 60_000,
      // A crashed job is retried at most once; the gate re-checks it anyway.
      maxStalledCount: 1,
    },
  );
  worker.on("failed", (job, err) => log("job errored", { jobId: job?.id, error: err.message }));

  return {
    worker,
    async close() {
      await worker.close();
      connection.disconnect();
    },
  };
}
