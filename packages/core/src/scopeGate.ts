import type { AuditLogger } from "./audit.js";
import type { RateLimiter } from "./rateLimit.js";
import { targetInScope } from "./targets.js";
import type { Actor, AssetKind, Engine, ScanStatus, ScopeStatus, ScopeType } from "./types.js";

/**
 * Scope Authorization Gate: the single choke point every scan path calls
 * (docs/SCOPE_AUTHORIZATION.md). There is no other way to authorize a scan.
 *
 * - The API calls it in "enqueue" mode before creating or queueing a scan.
 * - Every worker calls it again in "job_start" mode before touching a target
 *   (defense in depth: never trust that the API already checked).
 *
 * It fails closed: any missing data is a rejection, and any dependency error
 * propagates so the caller cannot treat it as an approval.
 */

/** Engines that need an Admin's approval before they may run. */
export const ENGINES_REQUIRING_APPROVAL: ReadonlySet<Engine> = new Set<Engine>(["NETWORK", "CLOUD"]);

export interface GateScope {
  id: string;
  orgId: string;
  type: ScopeType;
  value: string;
  status: ScopeStatus;
  expiresAt: Date | null;
  allowedEngines: Engine[];
  maxRequestsPerSec: number;
}

export interface GateAsset {
  id: string;
  scopeId: string;
  kind: AssetKind;
  address: string;
}

export interface GateOrg {
  id: string;
  killSwitchEngaged: boolean;
}

export interface GateScan {
  id: string;
  orgId: string;
  scopeId: string;
  assetId: string | null;
  engine: Engine;
  status: ScanStatus;
  approvedById: string | null;
  killedAt: Date | null;
}

/** Read-only data access the gate needs. */
export interface GateRepository {
  findAssetWithScope(assetId: string): Promise<{ asset: GateAsset; scope: GateScope } | null>;
  findOrg(orgId: string): Promise<GateOrg | null>;
  findScan(scanId: string): Promise<GateScan | null>;
  /** Scans in QUEUED or RUNNING state for the org. */
  countActiveScans(orgId: string): Promise<number>;
}

export interface GateLimits {
  maxConcurrentScansPerOrg: number;
  scanStartsPerScopePerMinute: number;
}

export const DEFAULT_GATE_LIMITS: GateLimits = {
  maxConcurrentScansPerOrg: 3,
  scanStartsPerScopePerMinute: 5,
};

interface BaseRequest {
  orgId: string;
  /** Scans target stored Assets only; raw hostnames/IPs are never accepted. */
  assetId: string;
  engine: Engine;
  actor: Actor;
}

/** API path: before a scan is created or moved to QUEUED. */
export interface EnqueueRequest extends BaseRequest {
  mode: "enqueue";
  /** Set when re-authorizing an existing scan (e.g. after approval). */
  scanId?: string;
}

/** Worker path: at job start, with the payload exactly as the worker received it. */
export interface JobStartRequest extends BaseRequest {
  mode: "job_start";
  scanId: string;
  /** The address the worker is about to contact. Must equal the asset's address. */
  targetAddress: string;
}

export type ScanAuthorizationRequest = EnqueueRequest | JobStartRequest;

export type ScanRejectReason =
  | "NO_SCOPE"
  | "TENANT_MISMATCH"
  | "SCOPE_NOT_VERIFIED"
  | "SCOPE_EXPIRED"
  | "SCOPE_REVOKED"
  | "TARGET_OUTSIDE_SCOPE"
  | "ENGINE_NOT_ALLOWED"
  | "KILL_SWITCH_ENGAGED"
  | "SCAN_KILLED"
  | "SCAN_NOT_RUNNABLE"
  | "NOT_APPROVED"
  | "TAMPERED_JOB";

export type ThrottleReason = "SCOPE_RATE_LIMIT" | "ORG_CONCURRENCY_LIMIT";

/** What a worker may touch, resolved from the database, never from the job payload. */
export interface AuthorizedTarget {
  orgId: string;
  scopeId: string;
  assetId: string;
  kind: AssetKind;
  address: string;
  engine: Engine;
  /** Per-scope cap on requests/sec the engine must respect against this target. */
  maxRequestsPerSec: number;
}

export type ScanAuthorizationDecision =
  | { decision: "ALLOW"; target: AuthorizedTarget }
  | { decision: "NEEDS_APPROVAL"; scopeId: string }
  | { decision: "THROTTLED"; reason: ThrottleReason; scopeId: string; retryAfterMs: number }
  | { decision: "REJECT"; reason: ScanRejectReason };

export interface ScopeGate {
  authorize(request: ScanAuthorizationRequest): Promise<ScanAuthorizationDecision>;
}

const CONCURRENCY_RETRY_MS = 30_000;

export function createScopeGate(deps: {
  repo: GateRepository;
  limiter: RateLimiter;
  audit: AuditLogger;
  now?: () => Date;
  limits?: Partial<GateLimits>;
}): ScopeGate {
  const { repo, limiter, audit } = deps;
  const now = deps.now ?? (() => new Date());
  const limits = { ...DEFAULT_GATE_LIMITS, ...deps.limits };

  async function decide(req: ScanAuthorizationRequest): Promise<{ d: ScanAuthorizationDecision; scopeId: string | null }> {
    const reject = (reason: ScanRejectReason, scopeId: string | null = null) => ({
      d: { decision: "REJECT", reason } as const,
      scopeId,
    });

    const found = await repo.findAssetWithScope(req.assetId);
    if (!found) return reject(req.mode === "job_start" ? "TAMPERED_JOB" : "NO_SCOPE");
    const { asset, scope } = found;

    // Tenant isolation: the asset's scope must belong to the requesting org.
    // The scope id is not recorded on the rejection so the other org's ids don't leak.
    if (scope.orgId !== req.orgId) return reject(req.mode === "job_start" ? "TAMPERED_JOB" : "TENANT_MISMATCH");

    // In job_start mode the scan record is the source of truth; the payload must match it.
    let scan: GateScan | null = null;
    if (req.scanId !== undefined) {
      scan = await repo.findScan(req.scanId);
      if (
        !scan ||
        scan.orgId !== req.orgId ||
        scan.assetId !== asset.id ||
        scan.scopeId !== scope.id ||
        scan.engine !== req.engine
      ) {
        return reject("TAMPERED_JOB", scope.id);
      }
    }
    if (req.mode === "job_start" && req.targetAddress !== asset.address) return reject("TAMPERED_JOB", scope.id);

    if (scope.status === "REVOKED") return reject("SCOPE_REVOKED", scope.id);
    if (scope.status === "EXPIRED") return reject("SCOPE_EXPIRED", scope.id);
    if (scope.status !== "VERIFIED") return reject("SCOPE_NOT_VERIFIED", scope.id);
    if (!scope.expiresAt || scope.expiresAt.getTime() <= now().getTime()) return reject("SCOPE_EXPIRED", scope.id);

    if (!targetInScope(scope, asset)) return reject("TARGET_OUTSIDE_SCOPE", scope.id);
    if (!scope.allowedEngines.includes(req.engine)) return reject("ENGINE_NOT_ALLOWED", scope.id);

    const org = await repo.findOrg(req.orgId);
    if (!org) return reject("NO_SCOPE", scope.id);
    if (org.killSwitchEngaged) return reject("KILL_SWITCH_ENGAGED", scope.id);
    if (scan?.killedAt || scan?.status === "KILLED") return reject("SCAN_KILLED", scope.id);

    const needsApproval = ENGINES_REQUIRING_APPROVAL.has(req.engine) && !scan?.approvedById;

    if (req.mode === "job_start") {
      if (scan!.status !== "QUEUED" && scan!.status !== "RUNNING") return reject("SCAN_NOT_RUNNABLE", scope.id);
      if (needsApproval) return reject("NOT_APPROVED", scope.id);
    } else {
      if (scan && scan.status !== "PENDING_APPROVAL") return reject("SCAN_NOT_RUNNABLE", scope.id);
      if (needsApproval) return { d: { decision: "NEEDS_APPROVAL", scopeId: scope.id }, scopeId: scope.id };

      if ((await repo.countActiveScans(req.orgId)) >= limits.maxConcurrentScansPerOrg) {
        return {
          d: { decision: "THROTTLED", reason: "ORG_CONCURRENCY_LIMIT", scopeId: scope.id, retryAfterMs: CONCURRENCY_RETRY_MS },
          scopeId: scope.id,
        };
      }
      const rl = await limiter.hit(`gate:scope:${scope.id}:scan-start`, limits.scanStartsPerScopePerMinute, 60_000);
      if (!rl.allowed) {
        return {
          d: { decision: "THROTTLED", reason: "SCOPE_RATE_LIMIT", scopeId: scope.id, retryAfterMs: Math.max(1, rl.retryAfterMs) },
          scopeId: scope.id,
        };
      }
    }

    return {
      d: {
        decision: "ALLOW",
        target: {
          orgId: req.orgId,
          scopeId: scope.id,
          assetId: asset.id,
          kind: asset.kind,
          address: asset.address,
          engine: req.engine,
          maxRequestsPerSec: scope.maxRequestsPerSec,
        },
      },
      scopeId: scope.id,
    };
  }

  return {
    async authorize(req) {
      const { d, scopeId } = await decide(req);
      const action =
        d.decision === "ALLOW"
          ? "scan.authorized"
          : d.decision === "NEEDS_APPROVAL"
            ? "scan.needs_approval"
            : d.decision === "THROTTLED"
              ? "scan.throttled"
              : "scan.rejected";
      // Every decision is audited. If the audit write fails, the error
      // propagates and the caller gets no decision (fail closed).
      await audit.record({
        action,
        actor: req.actor,
        orgId: req.orgId,
        scopeId,
        scanId: req.scanId ?? null,
        targetId: req.assetId,
        payload: {
          mode: req.mode,
          engine: req.engine,
          assetId: req.assetId,
          ...(d.decision === "REJECT" || d.decision === "THROTTLED" ? { reason: d.reason } : {}),
          ...(req.mode === "job_start" ? { targetAddress: req.targetAddress } : {}),
        },
      });
      return d;
    },
  };
}
