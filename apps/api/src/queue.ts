import { Queue } from "bullmq";
import type { Redis } from "ioredis";
import { ENGINES, scanQueueName, type Engine, type ScanJobPayload } from "@aegis/core";

/** Producer side of the scan queues. Only called after the gate said ALLOW. */
export interface ScanQueue {
  enqueue(job: ScanJobPayload): Promise<void>;
  /** Drops a not-yet-started job (kill / kill-switch / revoke). Running jobs stop via the worker heartbeat. */
  remove(scanId: string, engine: Engine): Promise<void>;
  close(): Promise<void>;
}

export function createBullScanQueue(connection: Redis): ScanQueue {
  const queues = new Map<Engine, Queue<ScanJobPayload>>();
  const q = (engine: Engine) => {
    let queue = queues.get(engine);
    if (!queue) {
      queue = new Queue<ScanJobPayload>(scanQueueName(engine), { connection });
      queues.set(engine, queue);
    }
    return queue;
  };
  return {
    async enqueue(job) {
      if (!ENGINES.includes(job.engine)) throw new Error(`unknown engine ${job.engine}`);
      // jobId = scanId makes enqueue idempotent: one scan, at most one job.
      await q(job.engine).add("scan", job, {
        jobId: job.scanId,
        attempts: 1,
        removeOnComplete: { count: 1000 },
        removeOnFail: { count: 1000 },
      });
    },
    async remove(scanId, engine) {
      const job = await q(engine).getJob(scanId);
      if (job && (await job.isWaiting() || await job.isDelayed())) await job.remove();
    },
    async close() {
      await Promise.all([...queues.values()].map((x) => x.close()));
    },
  };
}

/** For tests and Redis-less local dev: records jobs, runs nothing. */
export function createMemoryScanQueue(): ScanQueue & { jobs: ScanJobPayload[]; removed: string[] } {
  const jobs: ScanJobPayload[] = [];
  const removed: string[] = [];
  return {
    jobs,
    removed,
    async enqueue(job) {
      if (!jobs.some((j) => j.scanId === job.scanId)) jobs.push(job);
    },
    async remove(scanId) {
      removed.push(scanId);
    },
    async close() {},
  };
}
