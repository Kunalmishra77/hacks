import { Queue, Worker, type Job } from "bullmq";
import { Redis } from "ioredis";
import {
  createAuditLogger,
  createMemoryRateLimiter,
  createScopeGate,
  ENRICH_QUEUE,
  scanQueueName,
  type EnrichJobPayload,
  type ScanJobPayload,
} from "@aegis/core";
import type { CveIntel } from "@aegis/cve";
import type { PrismaClient } from "@aegis/db";
import { enrichScanFindings, type EnrichOutcome } from "./enrich.js";
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
  // Produces enrichment jobs (no API keys here). An enrichment worker that has
  // the NVD key consumes them. Enrichment is advisory, so failures to enqueue
  // never fail the scan.
  const enrichQueue = new Queue<EnrichJobPayload>(ENRICH_QUEUE, { connection });

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
      if (outcome.status === "SUCCEEDED" && outcome.findingsCreated + outcome.findingsUpdated > 0) {
        // jobId may not contain ':' (BullMQ reserves it), so one enrich job per scan id.
        await enrichQueue
          .add("enrich", { scanId: job.data.scanId, orgId: job.data.orgId }, { jobId: `enrich-${job.data.scanId}`, removeOnComplete: { count: 1000 }, removeOnFail: { count: 1000 } })
          .catch((e: Error) => log("could not enqueue enrichment", { error: e.message }));
      }
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
      await enrichQueue.close();
      connection.disconnect();
    },
  };
}

export interface EnrichmentWorkerOptions {
  redisUrl: string;
  prisma: PrismaClient;
  intel: CveIntel;
  concurrency?: number;
  log?: (msg: string, data?: Record<string, unknown>) => void;
  /** Called after a scan's findings are enriched — the API dispatches alerts here. */
  afterEnrich?: (scanId: string, orgId: string) => Promise<void>;
}

/**
 * Consumes the enrichment queue. Runs where the NVD key lives (next to the
 * API), not on the scan workers. One retry on failure; enrichment is advisory.
 */
export function startEnrichmentWorker(opts: EnrichmentWorkerOptions): { worker: Worker; close(): Promise<void> } {
  const log = opts.log ?? ((msg, data) => console.log(JSON.stringify({ msg, ...data })));
  const connection = new Redis(opts.redisUrl, { maxRetriesPerRequest: null });
  const store = createPrismaWorkerStore(opts.prisma);

  const worker = new Worker<EnrichJobPayload, EnrichOutcome>(
    ENRICH_QUEUE,
    async (job: Job<EnrichJobPayload>) => {
      const outcome = await enrichScanFindings(job.data.scanId, { store, intel: opts.intel, log: (m, d) => log(m, { jobId: job.id, ...d }) });
      log("enrichment finished", { jobId: job.id, scanId: job.data?.scanId, ...outcome });
      // Alerts run after enrichment so risk/KEV are known. Never fail the job on it.
      if (opts.afterEnrich) {
        await opts.afterEnrich(job.data.scanId, job.data.orgId).catch((e: Error) => log("afterEnrich failed", { error: e.message }));
      }
      return outcome;
    },
    { connection, concurrency: opts.concurrency ?? 2, lockDuration: 120_000, maxStalledCount: 1 },
  );
  worker.on("failed", (job, err) => log("enrichment errored", { jobId: job?.id, error: err.message }));

  return {
    worker,
    async close() {
      await worker.close();
      connection.disconnect();
    },
  };
}
