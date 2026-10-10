import { z } from "zod";
import {
  createAuditLogger,
  ENGINES,
  isWithinDomain,
  normalizeDomain,
  targetInScope,
  type AssetKind,
  type AuthorizedTarget,
  type Engine,
  type ScanRejectReason,
  type ScopeGate,
} from "@aegis/core";
import type { WorkerStore } from "./store.js";

// The lifecycle every engine worker shares (docs/SCOPE_AUTHORIZATION.md:
// "Every worker re-checks the gate at job start"):
//   1. gate.authorize(job_start) on the raw payload; refuse unless ALLOW
//   2. QUEUED → RUNNING
//   3. run the engine against the gate's AuthorizedTarget only
//   4. heartbeat: re-check the gate every few seconds; abort on any refusal
//   5. record assets only if they're inside the scope
//   6. SUCCEEDED / FAILED / KILLED + audit

export interface EmittedAsset {
  kind: AssetKind;
  address: string;
  metadata?: Record<string, unknown>;
}

export interface EngineContext {
  /** Resolved from the database by the gate. Never from the job payload. */
  target: AuthorizedTarget;
  /** Aborted on kill-switch, scan kill, scope revocation/expiry, or timeout. */
  signal: AbortSignal;
  /** Records an asset if it is inside the scope. Returns false if dropped. */
  emitAsset(asset: EmittedAsset): Promise<boolean>;
  log(msg: string, data?: Record<string, unknown>): void;
}

export interface EngineImpl {
  engine: Engine;
  run(ctx: EngineContext): Promise<void>;
}

export type JobOutcome =
  | { status: "REFUSED"; reason: ScanRejectReason | "INVALID_PAYLOAD" | "WRONG_ENGINE" | "NOT_RUNNABLE" }
  | { status: "SUCCEEDED"; assetsCreated: number; assetsUpdated: number; dropped: number }
  | { status: "FAILED"; error: string }
  | { status: "KILLED"; reason: ScanRejectReason };

export interface RunJobDeps {
  gate: ScopeGate;
  store: WorkerStore;
  engine: EngineImpl;
  now?: () => Date;
  heartbeatMs?: number;
  jobTimeoutMs?: number;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

const Payload = z.object({
  scanId: z.string().min(1).max(64),
  orgId: z.string().min(1).max(64),
  assetId: z.string().min(1).max(64),
  engine: z.enum(ENGINES),
  targetAddress: z.string().min(1).max(300),
});

/** Gate refusals that mean "stop because someone stopped it", vs. the scope going bad. */
const KILL_REASONS: ReadonlySet<ScanRejectReason> = new Set(["SCAN_KILLED", "KILL_SWITCH_ENGAGED", "SCOPE_REVOKED"]);

class StopError extends Error {
  constructor(public readonly reason: ScanRejectReason | "TIMEOUT") {
    super(reason === "TIMEOUT" ? "job timed out" : `stopped by scope gate: ${reason}`);
  }
}

function normalizeAddress(kind: AssetKind, address: string): string | null {
  const a = address.trim();
  if (kind === "DOMAIN" || kind === "SUBDOMAIN") return normalizeDomain(a);
  if (kind === "SERVICE") {
    const m = /^(.+):(\d{1,5})$/.exec(a);
    if (!m) return null;
    const port = Number(m[2]);
    if (port < 1 || port > 65535) return null;
    const host = m[1]!.startsWith("[") ? m[1]! : normalizeDomain(m[1]!) ?? m[1]!;
    return `${host}:${port}`;
  }
  return a;
}

export async function runScanJob(rawPayload: unknown, deps: RunJobDeps): Promise<JobOutcome> {
  const now = deps.now ?? (() => new Date());
  const log = deps.log ?? (() => {});
  const heartbeatMs = deps.heartbeatMs ?? 15_000;
  const jobTimeoutMs = deps.jobTimeoutMs ?? 30 * 60_000;
  const audit = createAuditLogger(deps.store.audit, { now });
  const actor = { type: "system" as const };

  const parsed = Payload.safeParse(rawPayload);
  if (!parsed.success) return { status: "REFUSED", reason: "INVALID_PAYLOAD" };
  const job = parsed.data;
  if (job.engine !== deps.engine.engine) return { status: "REFUSED", reason: "WRONG_ENGINE" };

  // 1. Re-check the gate with the payload exactly as received.
  const d = await deps.gate.authorize({ mode: "job_start", ...job, actor });
  if (d.decision !== "ALLOW") {
    const reason = d.decision === "REJECT" ? d.reason : "NOT_APPROVED";
    // A tampered payload must not be able to change any real scan's state.
    if (reason !== "TAMPERED_JOB") {
      await deps.store.finish(job.scanId, "FAILED", now(), `refused by scope gate: ${reason}`);
    }
    return { status: "REFUSED", reason };
  }
  const target = d.target;

  // 2. Claim the scan.
  const claimed = await deps.store.markRunning(job.scanId, now());
  if (claimed === "not_runnable") return { status: "REFUSED", reason: "NOT_RUNNABLE" };
  await audit.record({
    action: "scan.started",
    actor,
    orgId: target.orgId,
    scopeId: target.scopeId,
    scanId: job.scanId,
    targetId: target.assetId,
    payload: { engine: target.engine, address: target.address, resumed: claimed === "already_running" },
  });

  // 3–5. Run with heartbeat + timeout.
  const controller = new AbortController();
  const stop = (reason: ScanRejectReason | "TIMEOUT") => {
    if (!controller.signal.aborted) controller.abort(new StopError(reason));
  };
  const timeout = setTimeout(() => stop("TIMEOUT"), jobTimeoutMs);
  let beating = false;
  const heartbeat = setInterval(async () => {
    if (beating || controller.signal.aborted) return;
    beating = true;
    try {
      const hb = await deps.gate.authorize({ mode: "heartbeat", ...job, actor });
      if (hb.decision === "REJECT") stop(hb.reason);
      else if (hb.decision !== "ALLOW") stop("NOT_APPROVED");
    } catch (e) {
      log("heartbeat check failed; stopping (fail closed)", { error: (e as Error).message });
      stop("SCAN_NOT_RUNNABLE");
    } finally {
      beating = false;
    }
  }, heartbeatMs);

  let created = 0;
  let updated = 0;
  let dropped = 0;
  const scope = { type: target.scopeType, value: target.scopeValue };
  const ctx: EngineContext = {
    target,
    signal: controller.signal,
    log,
    async emitAsset(asset) {
      if (controller.signal.aborted) return false;
      const address = normalizeAddress(asset.kind, asset.address);
      const inScope = !!address && targetInScope(scope, { kind: asset.kind, address });
      // Domain scopes: discovery may only add names under the apex.
      if (!address || !inScope || (scope.type === "DOMAIN" && asset.kind === "SUBDOMAIN" && !isWithinDomain(address, target.scopeValue))) {
        dropped++;
        return false;
      }
      const r = await deps.store.upsertAsset({
        scopeId: target.scopeId,
        kind: asset.kind,
        address,
        metadata: asset.metadata ?? null,
        scanId: job.scanId,
        at: now(),
      });
      if (r.created) created++;
      else updated++;
      return true;
    },
  };

  let outcome: JobOutcome;
  try {
    await deps.engine.run(ctx);
    if (controller.signal.aborted) throw controller.signal.reason;
    outcome = { status: "SUCCEEDED", assetsCreated: created, assetsUpdated: updated, dropped };
  } catch (e) {
    const stopErr = controller.signal.aborted && controller.signal.reason instanceof StopError ? controller.signal.reason : null;
    if (stopErr && stopErr.reason !== "TIMEOUT" && KILL_REASONS.has(stopErr.reason)) {
      outcome = { status: "KILLED", reason: stopErr.reason };
    } else {
      outcome = { status: "FAILED", error: (stopErr ?? (e as Error)).message.slice(0, 500) };
    }
  } finally {
    clearTimeout(timeout);
    clearInterval(heartbeat);
  }

  // 6. Finish + audit.
  const at = now();
  const status = outcome.status === "SUCCEEDED" ? "SUCCEEDED" : outcome.status === "KILLED" ? "KILLED" : "FAILED";
  await deps.store.finish(job.scanId, status, at, outcome.status === "FAILED" ? outcome.error : null);
  await audit.record({
    action: outcome.status === "SUCCEEDED" ? "scan.completed" : outcome.status === "KILLED" ? "scan.killed" : "scan.failed",
    actor,
    orgId: target.orgId,
    scopeId: target.scopeId,
    scanId: job.scanId,
    payload: { engine: target.engine, assetsCreated: created, assetsUpdated: updated, dropped, ...outcome },
  });
  return outcome;
}
