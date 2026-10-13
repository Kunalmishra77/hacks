import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { createSenders } from "../src/notify/senders.js";
import { dispatchScanAlerts } from "../src/notify/dispatch.js";
import { createMemoryStore } from "../src/store/memory.js";

async function seedOrgWithFindings() {
  const store = createMemoryStore();
  const org = await store.orgs.create({ name: "Acme", slug: `acme-${Date.now()}` });
  const scope = await store.scopes.create({
    orgId: org.id, type: "DOMAIN", value: "acme.example", allowedEngines: ["WEB"], criticality: "MEDIUM",
    verificationToken: "t", cloudRoleArn: null, externalId: null, createdById: "u1",
  });
  const asset = await store.assets.upsert({ scopeId: scope.id, kind: "SERVICE", address: "api.acme.example:443", at: new Date() });
  const scanId = randomUUID();
  const since = new Date(Date.now() - 1000);
  const now = new Date();
  const mk = (severity: string, risk: number, kev: boolean, title: string) =>
    store.raw.findings.push({
      id: randomUUID(), assetId: asset.id, scanId, lastScanId: scanId, type: `t.${title}`, severity: severity as never,
      cvss: null, cveRefs: [], title, evidence: null, remediation: "fix", status: "OPEN",
      epss: null, kevListed: kev, riskScore: risk, enrichedAt: now, firstSeenAt: now, lastSeenAt: now,
    });
  mk("CRITICAL", 90, true, "Critical KEV");
  mk("MEDIUM", 40, false, "Medium thing");
  mk("LOW", 5, true, "Low but KEV");
  return { store, orgId: org.id, scanId, since };
}

describe("dispatchScanAlerts", () => {
  it("sends only findings above the channel threshold (plus KEV) to a webhook", async () => {
    const s = await seedOrgWithFindings();
    const posts: unknown[] = [];
    const fetchFn = (async (_url: string, init: RequestInit) => {
      posts.push(JSON.parse(init.body as string));
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch;
    await s.store.channels.create({ orgId: s.orgId, type: "WEBHOOK", name: "ops", target: "https://hooks.example.com/x", minSeverity: "HIGH", kevAlways: true, createdById: "u1" });

    const senders = createSenders({ fetch: fetchFn, resolve: async () => ["93.184.216.34"] });
    const res = await dispatchScanAlerts({ store: s.store, senders }, { orgId: s.orgId, scanId: s.scanId, scopeLabel: "acme.example", since: s.since });

    expect(res).toMatchObject({ newFindings: 3, channelsNotified: 1, channelsFailed: 0 });
    // HIGH threshold + KEV: Critical KEV and Low-but-KEV, not the plain MEDIUM.
    expect((posts[0] as { newFindings: number }).newFindings).toBe(2);
    const titles = (posts[0] as { findings: { title: string }[] }).findings.map((f) => f.title);
    expect(titles).toEqual(["Critical KEV", "Low but KEV"]);
  });

  it("records a per-channel error without throwing", async () => {
    const s = await seedOrgWithFindings();
    const fetchFn = (async () => ({ ok: false, status: 500 }) as Response) as unknown as typeof fetch;
    const ch = await s.store.channels.create({ orgId: s.orgId, type: "SLACK", name: "slack", target: "https://hooks.slack.com/x", minSeverity: "HIGH", kevAlways: true, createdById: "u1" });
    const senders = createSenders({ fetch: fetchFn, resolve: async () => ["93.184.216.34"] });
    const res = await dispatchScanAlerts({ store: s.store, senders }, { orgId: s.orgId, scanId: s.scanId, scopeLabel: "acme.example", since: s.since });
    expect(res.channelsFailed).toBe(1);
    expect((await s.store.channels.find(s.orgId, ch.id))!.lastError).toContain("HTTP 500");
  });

  it("does nothing when there are no new findings or no channels", async () => {
    const s = await seedOrgWithFindings();
    const senders = createSenders({ fetch: (async () => ({ ok: true, status: 200 }) as Response) as unknown as typeof fetch });
    const res = await dispatchScanAlerts({ store: s.store, senders }, { orgId: s.orgId, scanId: s.scanId, scopeLabel: "acme.example", since: new Date() });
    expect(res.newFindings).toBe(0); // 'since' in the future → nothing new
    expect(res.channelsNotified).toBe(0);
  });
});

describe("senders SSRF guard", () => {
  it("refuses to post a webhook to a private/loopback address", async () => {
    const server = createServer((_req, res) => res.end("ok"));
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    const { port } = server.address() as AddressInfo;
    try {
      const senders = createSenders({ resolve: async () => ["127.0.0.1"] });
      await expect(senders.send({ type: "WEBHOOK", target: `https://localhost:${port}/hook` }, { subject: "", text: "", slack: { text: "" }, webhook: { org: "", scope: "", newFindings: 0, findings: [] } })).rejects.toThrow(/non-public/);
    } finally {
      server.close();
    }
  });

  it("requires https for webhooks", async () => {
    const senders = createSenders({ resolve: async () => ["93.184.216.34"] });
    await expect(senders.send({ type: "SLACK", target: "http://hooks.slack.com/x" }, { subject: "", text: "", slack: { text: "x" }, webhook: { org: "", scope: "", newFindings: 0, findings: [] } })).rejects.toThrow(/https/);
  });
});
