import { describe, expect, it } from "vitest";
import {
  createAuditLogger,
  createMemoryAuditSink,
  createMemoryRateLimiter,
  createScopeGate,
  type AssetKind,
  type GateScan,
  type GateScope,
} from "@aegis/core";
import { runScanJob, type EngineImpl } from "../src/runner.js";
import type { WorkerStore } from "../src/store.js";

const NOW = new Date("2026-10-10T12:00:00Z");

function world() {
  const scope: GateScope = {
    id: "scope-1",
    orgId: "org-1",
    type: "DOMAIN",
    value: "example.com",
    status: "VERIFIED",
    expiresAt: new Date(NOW.getTime() + 86_400_000),
    allowedEngines: ["DISCOVERY", "TLS"],
    maxRequestsPerSec: 4,
  };
  const org = { id: "org-1", killSwitchEngaged: false };
  const scans = new Map<string, GateScan & { error?: string | null }>();
  scans.set("scan-1", {
    id: "scan-1",
    orgId: "org-1",
    scopeId: "scope-1",
    assetId: "asset-apex",
    engine: "DISCOVERY",
    status: "QUEUED",
    approvedById: null,
    killedAt: null,
  });
  const assets = new Map<string, { id: string; scopeId: string; kind: AssetKind; address: string; metadata: unknown }>();
  assets.set("asset-apex", { id: "asset-apex", scopeId: "scope-1", kind: "DOMAIN", address: "example.com", metadata: null });

  const findings = new Map<string, { assetId: string; fingerprint: string; status: string; severity: string; title: string; evidence: unknown; seen: number }>();
  const sink = createMemoryAuditSink();
  const store: WorkerStore = {
    audit: sink,
    gate: {
      async findAssetWithScope(id) {
        const a = assets.get(id);
        return a ? { asset: { id: a.id, scopeId: a.scopeId, kind: a.kind, address: a.address }, scope: { ...scope } } : null;
      },
      findOrg: async () => ({ ...org }),
      findScan: async (id) => (scans.has(id) ? { ...scans.get(id)! } : null),
      countActiveScans: async () => 0,
    },
    async markRunning(id) {
      const s = scans.get(id);
      if (s?.status === "QUEUED") {
        s.status = "RUNNING";
        return "started";
      }
      return s?.status === "RUNNING" ? "already_running" : "not_runnable";
    },
    async finish(id, status, _at, error) {
      const s = scans.get(id);
      if (!s || (s.status !== "QUEUED" && s.status !== "RUNNING")) return false;
      s.status = status;
      s.error = error ?? null;
      return true;
    },
    async upsertFinding(f) {
      const k = `${f.assetId}|${f.fingerprint}`;
      const ex = findings.get(k);
      if (!ex) {
        findings.set(k, { assetId: f.assetId, fingerprint: f.fingerprint, status: "OPEN", severity: f.severity, title: f.title, evidence: f.evidence, seen: 1 });
        return "created";
      }
      const reopened = ex.status === "FIXED";
      Object.assign(ex, { severity: f.severity, title: f.title, evidence: f.evidence, seen: ex.seen + 1, status: reopened ? "OPEN" : ex.status });
      return reopened ? "reopened" : "updated";
    },
    async upsertAsset({ scopeId, kind, address, metadata }) {
      const existing = [...assets.values()].find((a) => a.scopeId === scopeId && a.kind === kind && a.address === address);
      if (existing) {
        existing.metadata = metadata;
        return { id: existing.id, created: false };
      }
      const id = `asset-${assets.size + 1}`;
      assets.set(id, { id, scopeId, kind, address, metadata });
      return { id, created: true };
    },
  };
  const gate = createScopeGate({
    repo: store.gate,
    limiter: createMemoryRateLimiter(),
    audit: createAuditLogger(sink),
    now: () => NOW,
  });
  const payload = {
    scanId: "scan-1",
    orgId: "org-1",
    assetId: "asset-apex",
    engine: "DISCOVERY",
    targetAddress: "example.com",
  };
  return { scope, org, scans, assets, findings, sink, store, gate, payload };
}

const quietEngine = (run: EngineImpl["run"]): EngineImpl => ({ engine: "DISCOVERY", run });

describe("runScanJob", () => {
  it("runs an authorized job, records in-scope assets, drops out-of-scope ones", async () => {
    const w = world();
    let seenTarget;
    const engine = quietEngine(async (ctx) => {
      seenTarget = ctx.target;
      expect(await ctx.emitAsset({ kind: "SUBDOMAIN", address: "api.example.com", metadata: { ips: ["93.184.216.34"] } })).toBeTruthy();
      expect(await ctx.emitAsset({ kind: "SUBDOMAIN", address: "API.Example.com" })).toBeTruthy(); // normalized → same asset
      expect(await ctx.emitAsset({ kind: "SUBDOMAIN", address: "example.com.evil.net" })).toBeNull();
      expect(await ctx.emitAsset({ kind: "SUBDOMAIN", address: "evil.com" })).toBeNull();
      expect(await ctx.emitAsset({ kind: "SERVICE", address: "api.example.com:443", metadata: { status: 200 } })).toBeTruthy();
    });

    const out = await runScanJob(w.payload, { gate: w.gate, store: w.store, engine, now: () => NOW });

    expect(out).toEqual({ status: "SUCCEEDED", assetsCreated: 2, assetsUpdated: 1, dropped: 2, findingsCreated: 0, findingsUpdated: 0 });
    expect(seenTarget).toMatchObject({ address: "example.com", scopeValue: "example.com", maxRequestsPerSec: 4 });
    expect(w.scans.get("scan-1")!.status).toBe("SUCCEEDED");
    expect([...w.assets.values()].map((a) => a.address).sort()).toEqual(["api.example.com", "api.example.com:443", "example.com"]);
    expect(w.sink.events.map((e) => e.action)).toEqual(["scan.authorized", "scan.started", "scan.completed"]);
    expect(w.sink.events.at(-1)!.payload).toMatchObject({ assetsCreated: 2, dropped: 2 });
  });

  it("refuses a tampered payload without touching the scan or running the engine", async () => {
    const w = world();
    let ran = false;
    const engine = quietEngine(async () => {
      ran = true;
    });
    const out = await runScanJob({ ...w.payload, targetAddress: "victim.example.net" }, { gate: w.gate, store: w.store, engine });
    expect(out).toEqual({ status: "REFUSED", reason: "TAMPERED_JOB" });
    expect(ran).toBe(false);
    expect(w.scans.get("scan-1")!.status).toBe("QUEUED");
  });

  it("refuses malformed payloads and jobs on the wrong engine queue", async () => {
    const w = world();
    const engine = quietEngine(async () => {});
    expect(await runScanJob({ scanId: "scan-1" }, { gate: w.gate, store: w.store, engine })).toEqual({
      status: "REFUSED",
      reason: "INVALID_PAYLOAD",
    });
    expect(await runScanJob({ ...w.payload, engine: "TLS" }, { gate: w.gate, store: w.store, engine })).toEqual({
      status: "REFUSED",
      reason: "WRONG_ENGINE",
    });
  });

  it("marks the scan FAILED when the scope expired while it was queued", async () => {
    const w = world();
    w.scope.expiresAt = new Date(NOW.getTime() - 1);
    const out = await runScanJob(w.payload, { gate: w.gate, store: w.store, engine: quietEngine(async () => {}), now: () => NOW });
    expect(out).toEqual({ status: "REFUSED", reason: "SCOPE_EXPIRED" });
    expect(w.scans.get("scan-1")).toMatchObject({ status: "FAILED", error: "refused by scope gate: SCOPE_EXPIRED" });
  });

  it("stops a running job when the kill-switch is engaged mid-run", async () => {
    const w = world();
    const engine = quietEngine(async (ctx) => {
      expect(await ctx.emitAsset({ kind: "SUBDOMAIN", address: "a.example.com" })).toBeTruthy();
      w.org.killSwitchEngaged = true;
      // Engine work that only ends when aborted (like a long tool run).
      await new Promise((_resolve, reject) => ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason)));
    });
    const out = await runScanJob(w.payload, { gate: w.gate, store: w.store, engine, heartbeatMs: 10, now: () => NOW });
    expect(out).toEqual({ status: "KILLED", reason: "KILL_SWITCH_ENGAGED" });
    expect(w.scans.get("scan-1")!.status).toBe("KILLED");
    expect(w.sink.events.map((e) => e.action)).toContain("scan.rejected"); // the heartbeat's refusal is audited
  });

  it("does not write assets after it has been stopped", async () => {
    const w = world();
    const engine = quietEngine(async (ctx) => {
      w.org.killSwitchEngaged = true;
      await new Promise((r) => setTimeout(r, 50));
      expect(ctx.signal.aborted).toBe(true);
      expect(await ctx.emitAsset({ kind: "SUBDOMAIN", address: "late.example.com" })).toBeNull();
    });
    await runScanJob(w.payload, { gate: w.gate, store: w.store, engine, heartbeatMs: 5, now: () => NOW });
    expect([...w.assets.values()].some((a) => a.address === "late.example.com")).toBe(false);
  });

  it("marks the scan FAILED on engine errors and on timeout", async () => {
    const w = world();
    const boom = quietEngine(async () => {
      throw new Error("crt.sh unreachable");
    });
    expect(await runScanJob(w.payload, { gate: w.gate, store: w.store, engine: boom, now: () => NOW })).toEqual({
      status: "FAILED",
      error: "crt.sh unreachable",
    });
    expect(w.scans.get("scan-1")).toMatchObject({ status: "FAILED", error: "crt.sh unreachable" });

    const w2 = world();
    const slow = quietEngine(
      (ctx) => new Promise((_r, reject) => ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason))),
    );
    expect(await runScanJob(w2.payload, { gate: w2.gate, store: w2.store, engine: slow, jobTimeoutMs: 30, now: () => NOW })).toEqual({
      status: "FAILED",
      error: "job timed out",
    });
  });

  it("records findings on the target or on assets this job emitted, deduplicated and sanitized", async () => {
    const w = world();
    const engine = quietEngine(async (ctx) => {
      const svc = await ctx.emitAsset({ kind: "SERVICE", address: "example.com:443" });
      expect(await ctx.emitFinding({ type: "web.missing-hsts", severity: "LOW", title: "No HSTS", remediation: "Add HSTS" })).toBe(true);
      expect(
        await ctx.emitFinding({
          assetId: svc!,
          type: "web.exposed-file",
          key: "/.env",
          severity: "HIGH",
          title: ".env exposed",
          remediation: "Remove it",
          evidence: { path: "/.env", body: "DB_PASSWORD=x" },
        }),
      ).toBe(true);
      // Same finding again in the same run → one row.
      await ctx.emitFinding({ type: "web.missing-hsts", severity: "LOW", title: "No HSTS", remediation: "Add HSTS" });
      // An asset this job never touched (another scope's id, say) → refused.
      expect(await ctx.emitFinding({ assetId: "asset-from-elsewhere", type: "x", severity: "HIGH", title: "x", remediation: "x" })).toBe(false);
    });
    const out = await runScanJob(w.payload, { gate: w.gate, store: w.store, engine, now: () => NOW });
    expect(out).toMatchObject({ status: "SUCCEEDED", findingsCreated: 2, findingsUpdated: 1, dropped: 1 });
    const env = [...w.findings.values()].find((f) => f.title === ".env exposed")!;
    expect(env.evidence).toEqual({ path: "/.env", body: "[REDACTED]" });
  });

  it("keeps only well-formed CVE ids and sane CVSS scores", async () => {
    const w = world();
    const captured: { cveRefs: string[]; cvss: number | null }[] = [];
    const store = { ...w.store, upsertFinding: async (f: { cveRefs: string[]; cvss: number | null }) => (captured.push(f), "created" as const) };
    const engine = quietEngine(async (ctx) => {
      await ctx.emitFinding({ type: "t", severity: "HIGH", title: "t", remediation: "r", cveRefs: ["CVE-2016-2183", "cve-2016-2183", "CVE-x", "<script>"], cvss: 7.5 });
      await ctx.emitFinding({ type: "u", severity: "LOW", title: "u", remediation: "r", cvss: 42 });
    });
    await runScanJob(w.payload, { gate: w.gate, store, engine, now: () => NOW });
    expect(captured).toMatchObject([{ cveRefs: ["CVE-2016-2183"], cvss: 7.5 }, { cveRefs: [], cvss: null }]);
  });

  it("reopens a finding previously marked fixed when it is seen again", async () => {
    const w = world();
    const engine = quietEngine(async (ctx) => {
      await ctx.emitFinding({ type: "tls.SSLv3", severity: "HIGH", title: "SSLv3 offered", remediation: "Disable SSLv3" });
    });
    await runScanJob(w.payload, { gate: w.gate, store: w.store, engine, now: () => NOW });
    [...w.findings.values()][0]!.status = "FIXED";
    w.scans.get("scan-1")!.status = "QUEUED";
    const out = await runScanJob(w.payload, { gate: w.gate, store: w.store, engine, now: () => NOW });
    expect(out).toMatchObject({ findingsCreated: 0, findingsUpdated: 1 });
    expect([...w.findings.values()][0]!.status).toBe("OPEN");
  });
});
