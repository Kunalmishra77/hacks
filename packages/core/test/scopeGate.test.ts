// Phase 1 "tests to write first" (docs/SCOPE_AUTHORIZATION.md) plus the
// other gate invariants. The gate is the safety-critical choke point: every
// rule here must hold for every scan path.
import { beforeEach, describe, expect, it } from "vitest";
import {
  createAuditLogger,
  createMemoryAuditSink,
  createMemoryRateLimiter,
  createScopeGate,
  type GateAsset,
  type GateOrg,
  type GateRepository,
  type GateScan,
  type GateScope,
} from "../src/index.js";

const NOW = new Date("2026-10-10T12:00:00Z");
const DAY = 86_400_000;
const actor = { type: "user" as const, id: "user-1" };

function fixture() {
  const orgs = new Map<string, GateOrg>([
    ["org-a", { id: "org-a", killSwitchEngaged: false }],
    ["org-b", { id: "org-b", killSwitchEngaged: false }],
  ]);
  const scopes = new Map<string, GateScope>();
  const assets = new Map<string, GateAsset>();
  const scans = new Map<string, GateScan>();
  let activeScans = 0;

  const repo: GateRepository = {
    async findAssetWithScope(assetId) {
      const asset = assets.get(assetId);
      const scope = asset && scopes.get(asset.scopeId);
      return asset && scope ? { asset: { ...asset }, scope: { ...scope } } : null;
    },
    async findOrg(orgId) {
      return orgs.get(orgId) ?? null;
    },
    async findScan(scanId) {
      return scans.get(scanId) ?? null;
    },
    async countActiveScans() {
      return activeScans;
    },
  };

  function addScope(s: Partial<GateScope> & Pick<GateScope, "id" | "orgId">): GateScope {
    const scope: GateScope = {
      type: "DOMAIN",
      value: "example.com",
      status: "VERIFIED",
      expiresAt: new Date(NOW.getTime() + 30 * DAY),
      allowedEngines: ["DISCOVERY", "TLS", "WEB", "NETWORK"],
      maxRequestsPerSec: 5,
      ...s,
    };
    scopes.set(scope.id, scope);
    return scope;
  }
  function addAsset(a: Partial<GateAsset> & Pick<GateAsset, "id" | "scopeId">): GateAsset {
    const asset: GateAsset = { kind: "DOMAIN", address: "example.com", ...a };
    assets.set(asset.id, asset);
    return asset;
  }
  function addScan(s: Partial<GateScan> & Pick<GateScan, "id" | "orgId" | "assetId" | "scopeId">): GateScan {
    const scan: GateScan = { engine: "TLS", status: "QUEUED", approvedById: null, killedAt: null, ...s };
    scans.set(scan.id, scan);
    return scan;
  }

  const sink = createMemoryAuditSink();
  const limiter = createMemoryRateLimiter({ now: () => NOW.getTime() });
  const gate = createScopeGate({
    repo,
    limiter,
    audit: createAuditLogger(sink),
    now: () => NOW,
    limits: { maxConcurrentScansPerOrg: 3, scanStartsPerScopePerMinute: 2 },
  });

  return {
    gate,
    sink,
    orgs,
    scopes,
    scans,
    addScope,
    addAsset,
    addScan,
    setActiveScans: (n: number) => (activeScans = n),
  };
}

let f: ReturnType<typeof fixture>;
beforeEach(() => {
  f = fixture();
});

describe("scope gate: tests to write first", () => {
  it("rejects a scan against an unverified scope, and audits the rejection", async () => {
    f.addScope({ id: "s1", orgId: "org-a", status: "PENDING", expiresAt: null });
    f.addAsset({ id: "a1", scopeId: "s1" });

    const d = await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "TLS", actor });

    expect(d).toEqual({ decision: "REJECT", reason: "SCOPE_NOT_VERIFIED" });
    expect(f.sink.events).toHaveLength(1);
    expect(f.sink.events[0]).toMatchObject({
      action: "scan.rejected",
      orgId: "org-a",
      scopeId: "s1",
      actor,
      payload: { reason: "SCOPE_NOT_VERIFIED", engine: "TLS", assetId: "a1", mode: "enqueue" },
    });
  });

  it("rejects a scan against another org's verified scope (tenant isolation)", async () => {
    f.addScope({ id: "s-b", orgId: "org-b" });
    f.addAsset({ id: "a-b", scopeId: "s-b" });

    const d = await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a-b", engine: "TLS", actor });

    expect(d).toEqual({ decision: "REJECT", reason: "TENANT_MISMATCH" });
    // The rejection is recorded against the requesting org, never leaking into org-b's log.
    expect(f.sink.events[0]).toMatchObject({ action: "scan.rejected", orgId: "org-a" });
  });

  it("rejects an expired scope until it is re-verified", async () => {
    const scope = f.addScope({ id: "s1", orgId: "org-a", expiresAt: new Date(NOW.getTime() - 1) });
    f.addAsset({ id: "a1", scopeId: "s1" });
    const req = { mode: "enqueue" as const, orgId: "org-a", assetId: "a1", engine: "TLS" as const, actor };

    expect(await f.gate.authorize(req)).toEqual({ decision: "REJECT", reason: "SCOPE_EXPIRED" });

    f.scopes.set("s1", { ...scope, status: "EXPIRED" });
    expect(await f.gate.authorize(req)).toEqual({ decision: "REJECT", reason: "SCOPE_EXPIRED" });

    // Re-verification sets status VERIFIED and a fresh expiry.
    f.scopes.set("s1", { ...scope, status: "VERIFIED", expiresAt: new Date(NOW.getTime() + 90 * DAY) });
    expect(await f.gate.authorize(req)).toMatchObject({ decision: "ALLOW" });
  });

  it("blocks new scans while the org kill-switch is engaged, and stops killed jobs at start", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1" });

    f.orgs.set("org-a", { id: "org-a", killSwitchEngaged: true });
    expect(await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "TLS", actor })).toEqual({
      decision: "REJECT",
      reason: "KILL_SWITCH_ENGAGED",
    });

    // A queued job whose org kill-switch is engaged refuses to start.
    f.addScan({ id: "scan-1", orgId: "org-a", assetId: "a1", scopeId: "s1", status: "QUEUED" });
    expect(
      await f.gate.authorize({
        mode: "job_start",
        orgId: "org-a",
        scanId: "scan-1",
        assetId: "a1",
        engine: "TLS",
        targetAddress: "example.com",
        actor: { type: "system" },
      }),
    ).toEqual({ decision: "REJECT", reason: "KILL_SWITCH_ENGAGED" });

    // A scan-level kill also stops it, even with the org switch released.
    f.orgs.set("org-a", { id: "org-a", killSwitchEngaged: false });
    f.addScan({ id: "scan-2", orgId: "org-a", assetId: "a1", scopeId: "s1", status: "KILLED", killedAt: NOW });
    expect(
      await f.gate.authorize({
        mode: "job_start",
        orgId: "org-a",
        scanId: "scan-2",
        assetId: "a1",
        engine: "TLS",
        targetAddress: "example.com",
        actor: { type: "system" },
      }),
    ).toEqual({ decision: "REJECT", reason: "SCAN_KILLED" });
  });

  it("throttles (never silently drops) when the per-scope rate limit is exceeded", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1" });
    const req = { mode: "enqueue" as const, orgId: "org-a", assetId: "a1", engine: "TLS" as const, actor };

    expect(await f.gate.authorize(req)).toMatchObject({ decision: "ALLOW" });
    expect(await f.gate.authorize(req)).toMatchObject({ decision: "ALLOW" });
    const third = await f.gate.authorize(req);

    expect(third).toMatchObject({ decision: "THROTTLED", reason: "SCOPE_RATE_LIMIT", scopeId: "s1" });
    expect(third.decision === "THROTTLED" && third.retryAfterMs).toBeGreaterThan(0);
    expect(f.sink.events.at(-1)).toMatchObject({ action: "scan.throttled", payload: { reason: "SCOPE_RATE_LIMIT" } });
  });

  it("refuses at job start when the worker payload was tampered with", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1", address: "example.com" });
    f.addScope({ id: "s2", orgId: "org-a", value: "other.org" });
    f.addAsset({ id: "a2", scopeId: "s2", kind: "DOMAIN", address: "other.org" });
    f.addScan({ id: "scan-1", orgId: "org-a", assetId: "a1", scopeId: "s1", engine: "TLS" });
    const base = {
      mode: "job_start" as const,
      orgId: "org-a",
      scanId: "scan-1",
      assetId: "a1",
      engine: "TLS" as const,
      targetAddress: "example.com",
      actor: { type: "system" as const },
    };

    expect(await f.gate.authorize(base)).toMatchObject({ decision: "ALLOW" });
    // Target rewritten to something outside the scope.
    expect(await f.gate.authorize({ ...base, targetAddress: "victim.example.net" })).toEqual({
      decision: "REJECT",
      reason: "TAMPERED_JOB",
    });
    // Asset swapped for a different (even authorized) asset than the scan record says.
    expect(await f.gate.authorize({ ...base, assetId: "a2", targetAddress: "other.org" })).toEqual({
      decision: "REJECT",
      reason: "TAMPERED_JOB",
    });
    // Engine swapped.
    expect(await f.gate.authorize({ ...base, engine: "NETWORK" })).toEqual({ decision: "REJECT", reason: "TAMPERED_JOB" });
    // Scan id from another org.
    f.addScope({ id: "s-b", orgId: "org-b" });
    f.addAsset({ id: "a-b", scopeId: "s-b" });
    f.addScan({ id: "scan-b", orgId: "org-b", assetId: "a-b", scopeId: "s-b" });
    expect(await f.gate.authorize({ ...base, scanId: "scan-b" })).toEqual({ decision: "REJECT", reason: "TAMPERED_JOB" });
    // Unknown scan id.
    expect(await f.gate.authorize({ ...base, scanId: "nope" })).toEqual({ decision: "REJECT", reason: "TAMPERED_JOB" });
  });
});

describe("scope gate: other invariants", () => {
  it("allows a verified, in-date, in-scope request and returns the resolved target", async () => {
    f.addScope({ id: "s1", orgId: "org-a", maxRequestsPerSec: 7 });
    f.addAsset({ id: "a1", scopeId: "s1", kind: "SUBDOMAIN", address: "api.example.com" });

    const d = await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "WEB", actor });

    expect(d).toEqual({
      decision: "ALLOW",
      target: {
        orgId: "org-a",
        scopeId: "s1",
        assetId: "a1",
        kind: "SUBDOMAIN",
        address: "api.example.com",
        engine: "WEB",
        maxRequestsPerSec: 7,
      },
    });
    expect(f.sink.events[0]).toMatchObject({ action: "scan.authorized", scopeId: "s1" });
  });

  it("rejects unknown assets and revoked scopes", async () => {
    expect(await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "ghost", engine: "TLS", actor })).toEqual({
      decision: "REJECT",
      reason: "NO_SCOPE",
    });
    f.addScope({ id: "s1", orgId: "org-a", status: "REVOKED" });
    f.addAsset({ id: "a1", scopeId: "s1" });
    expect(await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "TLS", actor })).toEqual({
      decision: "REJECT",
      reason: "SCOPE_REVOKED",
    });
  });

  it("rejects engines the scope does not allow", async () => {
    f.addScope({ id: "s1", orgId: "org-a", allowedEngines: ["TLS"] });
    f.addAsset({ id: "a1", scopeId: "s1" });
    expect(await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "WEB", actor })).toEqual({
      decision: "REJECT",
      reason: "ENGINE_NOT_ALLOWED",
    });
  });

  it("rejects assets whose address falls outside the scope value (defense in depth)", async () => {
    f.addScope({ id: "s1", orgId: "org-a", value: "example.com" });
    f.addAsset({ id: "evil", scopeId: "s1", kind: "SUBDOMAIN", address: "example.com.attacker.net" });
    f.addAsset({ id: "evil2", scopeId: "s1", kind: "SUBDOMAIN", address: "notexample.com" });
    f.addScope({ id: "s-ip", orgId: "org-a", type: "IP_RANGE", value: "203.0.113.0/30", allowedEngines: ["TLS"] });
    f.addAsset({ id: "ip-in", scopeId: "s-ip", kind: "IP", address: "203.0.113.2" });
    f.addAsset({ id: "ip-out", scopeId: "s-ip", kind: "IP", address: "203.0.113.9" });
    f.addAsset({ id: "svc-in", scopeId: "s-ip", kind: "SERVICE", address: "203.0.113.1:443" });

    const ask = (assetId: string) =>
      f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId, engine: "TLS", actor });

    expect(await ask("evil")).toEqual({ decision: "REJECT", reason: "TARGET_OUTSIDE_SCOPE" });
    expect(await ask("evil2")).toEqual({ decision: "REJECT", reason: "TARGET_OUTSIDE_SCOPE" });
    expect(await ask("ip-out")).toEqual({ decision: "REJECT", reason: "TARGET_OUTSIDE_SCOPE" });
    expect(await ask("ip-in")).toMatchObject({ decision: "ALLOW" });
    expect(await ask("svc-in")).toMatchObject({ decision: "ALLOW" });
  });

  it("requires Admin approval for heavier engines, then allows once approved", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1" });

    const pending = await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "NETWORK", actor });
    expect(pending).toEqual({ decision: "NEEDS_APPROVAL", scopeId: "s1" });
    expect(f.sink.events.at(-1)).toMatchObject({ action: "scan.needs_approval" });

    f.addScan({
      id: "scan-1",
      orgId: "org-a",
      assetId: "a1",
      scopeId: "s1",
      engine: "NETWORK",
      status: "PENDING_APPROVAL",
      approvedById: "admin-1",
    });
    const approved = await f.gate.authorize({
      mode: "enqueue",
      orgId: "org-a",
      assetId: "a1",
      engine: "NETWORK",
      scanId: "scan-1",
      actor: { type: "user", id: "admin-1" },
    });
    expect(approved).toMatchObject({ decision: "ALLOW" });

    // A worker refuses an unapproved heavy job even if someone queued it directly.
    f.addScan({ id: "scan-2", orgId: "org-a", assetId: "a1", scopeId: "s1", engine: "NETWORK", status: "QUEUED" });
    expect(
      await f.gate.authorize({
        mode: "job_start",
        orgId: "org-a",
        scanId: "scan-2",
        assetId: "a1",
        engine: "NETWORK",
        targetAddress: "example.com",
        actor: { type: "system" },
      }),
    ).toEqual({ decision: "REJECT", reason: "NOT_APPROVED" });
  });

  it("throttles when the org's concurrent-scan cap is reached", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1" });
    f.setActiveScans(3);
    const d = await f.gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "TLS", actor });
    expect(d).toMatchObject({ decision: "THROTTLED", reason: "ORG_CONCURRENCY_LIMIT" });
  });

  it("does not consume rate-limit budget or count concurrency at job start", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1" });
    f.addScan({ id: "scan-1", orgId: "org-a", assetId: "a1", scopeId: "s1", status: "RUNNING" });
    f.setActiveScans(99);
    const job = {
      mode: "job_start" as const,
      orgId: "org-a",
      scanId: "scan-1",
      assetId: "a1",
      engine: "TLS" as const,
      targetAddress: "example.com",
      actor: { type: "system" as const },
    };
    for (let i = 0; i < 5; i++) expect(await f.gate.authorize(job)).toMatchObject({ decision: "ALLOW" });
  });

  it("refuses jobs whose scan is not queued or running", async () => {
    f.addScope({ id: "s1", orgId: "org-a" });
    f.addAsset({ id: "a1", scopeId: "s1" });
    f.addScan({ id: "scan-1", orgId: "org-a", assetId: "a1", scopeId: "s1", status: "SUCCEEDED" });
    expect(
      await f.gate.authorize({
        mode: "job_start",
        orgId: "org-a",
        scanId: "scan-1",
        assetId: "a1",
        engine: "TLS",
        targetAddress: "example.com",
        actor: { type: "system" },
      }),
    ).toEqual({ decision: "REJECT", reason: "SCAN_NOT_RUNNABLE" });
  });

  it("fails closed when a dependency throws", async () => {
    const sink = createMemoryAuditSink();
    const gate = createScopeGate({
      repo: {
        findAssetWithScope: async () => {
          throw new Error("db down");
        },
        findOrg: async () => null,
        findScan: async () => null,
        countActiveScans: async () => 0,
      },
      limiter: createMemoryRateLimiter(),
      audit: createAuditLogger(sink),
    });
    await expect(
      gate.authorize({ mode: "enqueue", orgId: "org-a", assetId: "a1", engine: "TLS", actor }),
    ).rejects.toThrow("db down");
  });
});
