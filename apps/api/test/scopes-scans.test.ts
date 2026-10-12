import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createVerifier } from "../src/verification/verifiers.js";
import { bearer, makeApp, register } from "./helpers.js";

/** Verifier whose DNS/HTTP/STS answers the test controls. Never touches the network. */
function fakeVerifier() {
  const published = new Map<string, string>(); // host -> token
  const verifier = createVerifier({
    resolveTxt: async (host) => (published.has(host) ? [[published.get(host)!]] : []),
    fetchWellKnown: async (host) => published.get(host) ?? "",
    assumeRoleAccount: async (arn) => arn.split(":")[4]!,
  });
  return { verifier, publish: (host: string, token: string) => published.set(host, token) };
}

let app: FastifyInstance;
afterEach(async () => {
  await app?.close();
});

async function setup() {
  const fv = fakeVerifier();
  const ctx = await makeApp({}, { verifier: fv.verifier });
  app = ctx.app;
  const owner = await register(app, "owner@acme.io", "Acme");
  const orgId = owner.org!.id;
  const T = owner.accessToken;

  const post = (url: string, token: string, payload?: unknown) =>
    app.inject({ method: "POST", url, headers: bearer(token), payload: payload as object });
  const get = (url: string, token: string) => app.inject({ method: "GET", url, headers: bearer(token) });

  async function member(email: string, role: string) {
    const inv = await post(`/orgs/${orgId}/invites`, T, { email, role });
    const u = await register(app, email);
    await post("/invites/accept", u.accessToken, { token: inv.json().token });
    return u.accessToken;
  }

  /** Creates + verifies a domain scope and returns its id and seeded asset id. */
  async function verifiedDomain(value: string, engines?: string[]) {
    const created = await post(`/orgs/${orgId}/scopes`, T, { type: "DOMAIN", value, allowedEngines: engines });
    expect(created.statusCode).toBe(201);
    const scope = created.json().scope;
    fv.publish(value, scope.verification.DNS_TXT.value);
    const v = await post(`/orgs/${orgId}/scopes/${scope.id}/verify`, T, { method: "DNS_TXT" });
    expect(v.statusCode).toBe(200);
    const assets = (await get(`/orgs/${orgId}/assets?scopeId=${scope.id}`, T)).json().assets;
    return { scopeId: scope.id as string, assetId: assets[0].id as string };
  }

  return { ...ctx, fv, orgId, T, post, get, member, verifiedDomain };
}

describe("scopes + ownership verification", () => {
  it("creates a pending scope with verification instructions and audits it", async () => {
    const s = await setup();
    const res = await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "DOMAIN", value: "Example.COM" });
    expect(res.statusCode).toBe(201);
    const scope = res.json().scope;
    expect(scope).toMatchObject({ value: "example.com", status: "PENDING", allowedEngines: ["DISCOVERY", "NETWORK", "TLS", "WEB"] });
    expect(scope.verification.DNS_TXT.value).toMatch(/^aegis-verify=[\w-]{32}$/);
    expect(scope.verification.HTTP_FILE.url).toBe("https://example.com/.well-known/aegis-verify.txt");
    expect(s.store.auditEvents.at(-1)).toMatchObject({ action: "scope.create", scopeId: scope.id });
  });

  it("rejects wildcards, private IPs, wide ranges, mismatched cloud roles and incompatible engines", async () => {
    const s = await setup();
    const bad = [
      { type: "DOMAIN", value: "*.example.com" },
      { type: "DOMAIN", value: "https://example.com/" },
      { type: "DOMAIN", value: "com" },
      { type: "IP_RANGE", value: "10.0.0.5" },
      { type: "IP_RANGE", value: "169.254.169.254" },
      { type: "IP_RANGE", value: "8.8.8.0/24" },
      { type: "CLOUD_ACCOUNT", value: "aws:123456789012", roleArn: "arn:aws:iam::999999999999:role/X" },
      { type: "DOMAIN", value: "example.com", allowedEngines: ["CLOUD"] },
    ];
    for (const body of bad) {
      const res = await s.post(`/orgs/${s.orgId}/scopes`, s.T, body);
      expect(res.statusCode, JSON.stringify(body)).toBe(400);
    }
    const ok = await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "IP_RANGE", value: "8.8.8.8" });
    expect(ok.json().scope.value).toBe("8.8.8.8/32");
  });

  it("only Admins+ manage scopes", async () => {
    const s = await setup();
    const analyst = await s.member("an@acme.io", "ANALYST");
    expect((await s.post(`/orgs/${s.orgId}/scopes`, analyst, { type: "DOMAIN", value: "example.com" })).statusCode).toBe(403);
    expect((await s.get(`/orgs/${s.orgId}/scopes`, analyst)).statusCode).toBe(200);
  });

  it("fails verification without the token (audited), then verifies and seeds the asset", async () => {
    const s = await setup();
    const scope = (await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "DOMAIN", value: "example.com" })).json().scope;

    const fail = await s.post(`/orgs/${s.orgId}/scopes/${scope.id}/verify`, s.T, { method: "DNS_TXT" });
    expect(fail.statusCode).toBe(422);
    expect(s.store.auditEvents.at(-1)).toMatchObject({ action: "scope.verify_failed", scopeId: scope.id });
    expect((await s.get(`/orgs/${s.orgId}/assets`, s.T)).json().assets).toEqual([]);

    s.fv.publish("example.com", scope.verification.HTTP_FILE.content);
    const ok = await s.post(`/orgs/${s.orgId}/scopes/${scope.id}/verify`, s.T, { method: "HTTP_FILE" });
    expect(ok.statusCode).toBe(200);
    const verified = ok.json().scope;
    expect(verified).toMatchObject({ status: "VERIFIED", verificationMethod: "HTTP_FILE" });
    const days = (new Date(verified.expiresAt).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(89.9);
    expect((await s.get(`/orgs/${s.orgId}/assets`, s.T)).json().assets).toMatchObject([
      { kind: "DOMAIN", address: "example.com" },
    ]);
    expect(s.store.auditEvents.at(-1)).toMatchObject({ action: "scope.verify" });
  });

  it("rejects verification methods that don't fit the scope type", async () => {
    const s = await setup();
    const scope = (await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "IP_RANGE", value: "8.8.8.8" })).json().scope;
    expect((await s.post(`/orgs/${s.orgId}/scopes/${scope.id}/verify`, s.T, { method: "DNS_TXT" })).statusCode).toBe(400);
  });

  it("defaults criticality to MEDIUM and lets an admin change it", async () => {
    const s = await setup();
    const created = await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "DOMAIN", value: "example.com", criticality: "HIGH" });
    expect(created.json().scope.criticality).toBe("HIGH");
    const dflt = await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "DOMAIN", value: "other.example" });
    expect(dflt.json().scope.criticality).toBe("MEDIUM");
    const upd = await s.post(`/orgs/${s.orgId}/scopes/${dflt.json().scope.id}/criticality`, s.T, { criticality: "LOW" });
    expect(upd.statusCode).toBe(200);
    expect(upd.json().scope.criticality).toBe("LOW");

    const analyst = await s.member("an@acme.io", "ANALYST");
    expect((await s.post(`/orgs/${s.orgId}/scopes/${dflt.json().scope.id}/criticality`, analyst, { criticality: "HIGH" })).statusCode).toBe(403);
  });

  it("verifies a cloud account via its read-only role", async () => {
    const s = await setup();
    const scope = (
      await s.post(`/orgs/${s.orgId}/scopes`, s.T, {
        type: "CLOUD_ACCOUNT",
        value: "aws:123456789012",
        roleArn: "arn:aws:iam::123456789012:role/AegisReadOnly",
      })
    ).json().scope;
    expect(scope.allowedEngines).toEqual(["CLOUD"]);
    expect(scope.verification.CLOUD_ROLE.externalId).toMatch(/^aegis-/);
    expect(scope.verification.CLOUD_ROLE.requiredPolicy).toBe("arn:aws:iam::aws:policy/SecurityAudit");
    const v = await s.post(`/orgs/${s.orgId}/scopes/${scope.id}/verify`, s.T, { method: "CLOUD_ROLE" });
    expect(v.json().scope.status).toBe("VERIFIED");
  });

  it("rate-limits verification attempts per scope", async () => {
    const s = await setup();
    const scope = (await s.post(`/orgs/${s.orgId}/scopes`, s.T, { type: "DOMAIN", value: "example.com" })).json().scope;
    const codes: number[] = [];
    for (let i = 0; i < 11; i++) {
      codes.push((await s.post(`/orgs/${s.orgId}/scopes/${scope.id}/verify`, s.T, { method: "DNS_TXT" })).statusCode);
    }
    expect(codes.slice(0, 10).every((c) => c === 422)).toBe(true);
    expect(codes[10]).toBe(429);
  });
});

describe("scans through the gate", () => {
  it("queues a scan on a verified asset and the worker re-check passes", async () => {
    const s = await setup();
    const { assetId, scopeId } = await s.verifiedDomain("example.com");

    const res = await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" });
    expect(res.statusCode).toBe(201);
    const scan = res.json().scan;
    expect(scan).toMatchObject({ status: "QUEUED", scopeId, engine: "TLS" });
    const actions = s.store.auditEvents.map((e) => e.action);
    expect(actions.slice(-2)).toEqual(["scan.authorized", "scan.requested"]);

    // What a worker does at job start: the same gate, wired to the same store.
    const job = { mode: "job_start" as const, orgId: s.orgId, scanId: scan.id, assetId, engine: "TLS" as const, actor: { type: "system" as const } };
    expect(await app.scopeGate.authorize({ ...job, targetAddress: "example.com" })).toMatchObject({
      decision: "ALLOW",
      target: { address: "example.com" },
    });
    expect(await app.scopeGate.authorize({ ...job, targetAddress: "evil.example.net" })).toEqual({
      decision: "REJECT",
      reason: "TAMPERED_JOB",
    });
  });

  it("rejects scans on expired scopes until re-verified", async () => {
    const s = await setup();
    const { assetId, scopeId } = await s.verifiedDomain("example.com");
    s.store.raw.scopes.find((x) => x.id === scopeId)!.expiresAt = new Date(Date.now() - 1000);

    const res = await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: "scan_rejected", reason: "SCOPE_EXPIRED" });
    expect((await s.get(`/orgs/${s.orgId}/scopes/${scopeId}`, s.T)).json().scope.status).toBe("EXPIRED");

    await s.post(`/orgs/${s.orgId}/scopes/${scopeId}/verify`, s.T, { method: "DNS_TXT" });
    expect((await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).statusCode).toBe(201);
  });

  it("hides other orgs' assets (404) and audits the attempt", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com");
    const other = await register(app, "eve@other.io", "Other");
    const res = await app.inject({
      method: "POST",
      url: `/orgs/${other.org!.id}/scans`,
      headers: bearer(other.accessToken),
      payload: { assetId, engine: "TLS" },
    });
    expect(res.statusCode).toBe(404);
    expect(s.store.auditEvents.at(-1)).toMatchObject({
      action: "scan.rejected",
      orgId: other.org!.id,
      payload: { reason: "TENANT_MISMATCH" },
    });
  });

  it("rejects engines the scope doesn't allow, and viewers can't request scans", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com", ["TLS"]);
    expect((await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "WEB" })).json()).toEqual({
      error: "scan_rejected",
      reason: "ENGINE_NOT_ALLOWED",
    });
    const viewer = await s.member("v@acme.io", "VIEWER");
    expect((await s.post(`/orgs/${s.orgId}/scans`, viewer, { assetId, engine: "TLS" })).statusCode).toBe(403);
  });

  it("holds heavy engines for Admin approval, then queues them", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com");
    const analyst = await s.member("an@acme.io", "ANALYST");

    const req = await s.post(`/orgs/${s.orgId}/scans`, analyst, { assetId, engine: "NETWORK" });
    expect(req.statusCode).toBe(202);
    const scan = req.json().scan;
    expect(scan.status).toBe("PENDING_APPROVAL");

    expect((await s.post(`/orgs/${s.orgId}/scans/${scan.id}/approve`, analyst)).statusCode).toBe(403);
    const ok = await s.post(`/orgs/${s.orgId}/scans/${scan.id}/approve`, s.T);
    expect(ok.statusCode).toBe(200);
    expect(ok.json().scan).toMatchObject({ status: "QUEUED" });
    expect(s.store.auditEvents.map((e) => e.action)).toEqual(
      expect.arrayContaining(["scan.needs_approval", "scan.approved", "scan.authorized"]),
    );
    expect((await s.post(`/orgs/${s.orgId}/scans/${scan.id}/approve`, s.T)).statusCode).toBe(409);
  });

  it("throttles with 429 + Retry-After when the per-scope rate limit is hit", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com");
    const codes: number[] = [];
    let last;
    for (let i = 0; i < 6; i++) {
      const r = await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" });
      codes.push(r.statusCode);
      // Free up concurrency so only the per-scope rate limit applies.
      if (r.statusCode === 201) await s.post(`/orgs/${s.orgId}/scans/${r.json().scan.id}/kill`, s.T);
      last = r;
    }
    expect(codes).toEqual([201, 201, 201, 201, 201, 429]);
    expect(last!.headers["retry-after"]).toBeDefined();
    expect(last!.json()).toMatchObject({ error: "throttled", reason: "SCOPE_RATE_LIMIT" });
  });

  it("caps concurrent scans per org", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com");
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).statusCode);
    expect(codes).toEqual([201, 201, 201, 429]);
  });
});

describe("kill-switch and revocation", () => {
  it("org kill-switch stops active scans and blocks new ones; only Admins release it", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com");
    const analyst = await s.member("an@acme.io", "ANALYST");
    const q = (await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).json().scan;
    const p = (await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "NETWORK" })).json().scan;

    // One API call, and an Analyst can pull it.
    const engage = await s.post(`/orgs/${s.orgId}/kill-switch`, analyst, { engaged: true });
    expect(engage.json()).toEqual({ killSwitchEngaged: true, killedScans: 2 });
    const scans = (await s.get(`/orgs/${s.orgId}/scans`, s.T)).json().scans;
    expect(scans.find((x: { id: string }) => x.id === q.id).status).toBe("KILLED");
    expect(scans.find((x: { id: string }) => x.id === p.id).status).toBe("KILLED");

    // Queued job refuses at start.
    expect(
      await app.scopeGate.authorize({
        mode: "job_start",
        orgId: s.orgId,
        scanId: q.id,
        assetId,
        engine: "TLS",
        targetAddress: "example.com",
        actor: { type: "system" },
      }),
    ).toMatchObject({ decision: "REJECT" });

    expect((await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).json()).toEqual({
      error: "scan_rejected",
      reason: "KILL_SWITCH_ENGAGED",
    });

    expect((await s.post(`/orgs/${s.orgId}/kill-switch`, analyst, { engaged: false })).statusCode).toBe(403);
    expect((await s.post(`/orgs/${s.orgId}/kill-switch`, s.T, { engaged: false })).statusCode).toBe(200);
    expect((await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).statusCode).toBe(201);
    expect(s.store.auditEvents.map((e) => e.action)).toEqual(
      expect.arrayContaining(["killswitch.engaged", "killswitch.released"]),
    );
  });

  it("scan-level kill stops one scan", async () => {
    const s = await setup();
    const { assetId } = await s.verifiedDomain("example.com");
    const scan = (await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).json().scan;
    expect((await s.post(`/orgs/${s.orgId}/scans/${scan.id}/kill`, s.T)).json()).toEqual({ scanId: scan.id, status: "KILLED" });
    expect((await s.post(`/orgs/${s.orgId}/scans/${scan.id}/kill`, s.T)).statusCode).toBe(409);
  });

  it("revoking a scope kills its scans and blocks new ones for good", async () => {
    const s = await setup();
    const { assetId, scopeId } = await s.verifiedDomain("example.com");
    await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" });

    expect((await s.post(`/orgs/${s.orgId}/scopes/${scopeId}/revoke`, s.T)).json()).toMatchObject({ killedScans: 1 });
    expect((await s.post(`/orgs/${s.orgId}/scans`, s.T, { assetId, engine: "TLS" })).json()).toEqual({
      error: "scan_rejected",
      reason: "SCOPE_REVOKED",
    });
    expect((await s.post(`/orgs/${s.orgId}/scopes/${scopeId}/verify`, s.T, { method: "DNS_TXT" })).statusCode).toBe(409);
  });
});
