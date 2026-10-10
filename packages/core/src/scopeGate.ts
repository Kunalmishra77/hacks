import type { Actor, Engine } from "./types.js";

/**
 * Scope Authorization Gate: the single choke point every scan path calls.
 *
 * TODO(Phase 1): implement per docs/SCOPE_AUTHORIZATION.md:
 *   - resolve assetId to an Asset under a Scope in the same org (tenant isolation)
 *   - scope.status === VERIFIED and now < scope.expiresAt
 *   - engine is in scope.allowedEngines
 *   - org-level and scan-level kill-switch not engaged
 *   - per-scope rate limit and per-org concurrency cap (throttle, never drop silently)
 *   - approval workflow for heavier engines -> NEEDS_APPROVAL
 *   - audit every decision ('scan.authorized' / 'scan.rejected')
 *   - workers call this again at job start (defense in depth)
 * Write the "Tests to write first" from that doc before the implementation.
 *
 * Until then this stub FAILS CLOSED and refuses every request. Do not make it
 * allow anything without the Phase 1 implementation and tests.
 */

export interface ScanAuthorizationRequest {
  orgId: string;
  /** Asset the scan targets. Raw hostnames/IPs are never accepted. */
  assetId: string;
  engine: Engine;
  actor: Actor;
  scanId?: string;
}

export type ScanRejectReason =
  | "GATE_NOT_IMPLEMENTED"
  | "NO_SCOPE"
  | "TENANT_MISMATCH"
  | "SCOPE_NOT_VERIFIED"
  | "SCOPE_EXPIRED"
  | "ENGINE_NOT_ALLOWED"
  | "KILL_SWITCH_ENGAGED";

export type ScanAuthorizationDecision =
  | { decision: "ALLOW"; scopeId: string }
  | { decision: "NEEDS_APPROVAL"; scopeId: string }
  | { decision: "THROTTLED"; scopeId: string; retryAfterMs: number }
  | { decision: "REJECT"; reason: ScanRejectReason };

export async function authorizeScan(
  _request: ScanAuthorizationRequest,
): Promise<ScanAuthorizationDecision> {
  return { decision: "REJECT", reason: "GATE_NOT_IMPLEMENTED" };
}
