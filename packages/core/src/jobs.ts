import type { Engine } from "./types.js";

/**
 * What the API puts on the queue after the gate ALLOWs a scan. Workers treat
 * every field as untrusted: they pass it to the gate in job_start mode, and
 * only the AuthorizedTarget the gate returns is used to touch anything.
 */
export interface ScanJobPayload {
  scanId: string;
  orgId: string;
  assetId: string;
  engine: Engine;
  targetAddress: string;
}

/** One BullMQ queue per engine, so each engine's workers scale and fail independently. */
export function scanQueueName(engine: Engine): string {
  return `aegis-scan-${engine.toLowerCase()}`;
}
