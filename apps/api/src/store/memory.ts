import { randomUUID } from "node:crypto";
import type { AuditEvent } from "@aegis/core";
import {
  ACTIVE_SCAN_STATUSES,
  UniqueViolationError,
  type AssetRecord,
  type InviteRecord,
  type MembershipRecord,
  type OrgRecord,
  type FindingRecord,
  type FindingStatus,
  type ReportRecord,
  type ScheduleRecord,
  type ChannelRecord,
  type RefreshTokenRecord,
  type ScanRecord,
  type ScopeRecord,
  type Store,
  type UserRecord,
} from "./types.js";

interface State {
  users: UserRecord[];
  orgs: OrgRecord[];
  memberships: MembershipRecord[];
  invites: (InviteRecord & { tokenHash: string })[];
  refreshTokens: (RefreshTokenRecord & { tokenHash: string; replacedBy: string | null })[];
  scopes: ScopeRecord[];
  assets: AssetRecord[];
  scans: ScanRecord[];
  findings: FindingRecord[];
  reports: (ReportRecord & { content: string })[];
  schedules: ScheduleRecord[];
  channels: ChannelRecord[];
  audit: AuditEvent[];
}

const empty = (): State => ({
  users: [],
  orgs: [],
  memberships: [],
  invites: [],
  refreshTokens: [],
  scopes: [],
  assets: [],
  scans: [],
  findings: [],
  reports: [],
  schedules: [],
  channels: [],
  audit: [],
});

/**
 * In-memory Store for tests. `transaction` snapshots state and restores it if
 * the callback throws, mirroring Postgres rollback semantics.
 */
export function createMemoryStore(): Store & { readonly auditEvents: readonly AuditEvent[]; readonly raw: State } {
  let s = empty();
  const copy = <T>(v: T): T => ({ ...v });
  const isActive = (scan: ScanRecord) => ACTIVE_SCAN_STATUSES.includes(scan.status);

  const store: Store & { readonly auditEvents: readonly AuditEvent[]; readonly raw: State } = {
    get auditEvents() {
      return s.audit.slice();
    },
    /** Direct state access for test setup (e.g. backdating expiry). */
    get raw() {
      return s;
    },
    users: {
      async findByEmail(email) {
        const u = s.users.find((x) => x.email === email);
        return u ? copy(u) : null;
      },
      async findById(id) {
        const u = s.users.find((x) => x.id === id);
        return u ? copy(u) : null;
      },
      async create(input) {
        if (s.users.some((x) => x.email === input.email)) throw new UniqueViolationError("email");
        const u: UserRecord = { id: randomUUID(), disabledAt: null, ...input };
        s.users.push(u);
        return copy(u);
      },
      async touchLogin() {},
    },
    orgs: {
      async create(input) {
        if (s.orgs.some((x) => x.slug === input.slug)) throw new UniqueViolationError("slug");
        const o: OrgRecord = { id: randomUUID(), killSwitchEngaged: false, createdAt: new Date(), ...input };
        s.orgs.push(o);
        return copy(o);
      },
      async findById(id) {
        const o = s.orgs.find((x) => x.id === id);
        return o ? copy(o) : null;
      },
      async setKillSwitch(id, engaged) {
        const o = s.orgs.find((x) => x.id === id);
        if (o) o.killSwitchEngaged = engaged;
      },
    },
    memberships: {
      async find(orgId, userId) {
        const m = s.memberships.find((x) => x.orgId === orgId && x.userId === userId);
        return m ? copy(m) : null;
      },
      async create(input) {
        if (s.memberships.some((x) => x.orgId === input.orgId && x.userId === input.userId)) {
          throw new UniqueViolationError("membership");
        }
        const m: MembershipRecord = { id: randomUUID(), createdAt: new Date(), ...input };
        s.memberships.push(m);
        return copy(m);
      },
      async listByOrg(orgId) {
        return s.memberships
          .filter((m) => m.orgId === orgId)
          .map((m) => {
            const u = s.users.find((x) => x.id === m.userId)!;
            return { ...m, email: u.email, name: u.name };
          });
      },
      async listByUser(userId) {
        return s.memberships
          .filter((m) => m.userId === userId)
          .map((m) => ({ ...m, org: copy(s.orgs.find((o) => o.id === m.orgId)!) }));
      },
    },
    invites: {
      async create(input) {
        const i = { id: randomUUID(), acceptedAt: null, ...input };
        s.invites.push(i);
        const { tokenHash: _t, ...rec } = i;
        return rec;
      },
      async findByTokenHash(tokenHash) {
        const i = s.invites.find((x) => x.tokenHash === tokenHash);
        if (!i) return null;
        const { tokenHash: _t, ...rec } = i;
        return rec;
      },
      async markAccepted(id, at) {
        const i = s.invites.find((x) => x.id === id);
        if (!i || i.acceptedAt) return false;
        i.acceptedAt = at;
        return true;
      },
    },
    refreshTokens: {
      async create(input) {
        const t = { id: randomUUID(), revokedAt: null, replacedBy: null, ...input };
        s.refreshTokens.push(t);
        return { id: t.id, userId: t.userId, familyId: t.familyId, expiresAt: t.expiresAt, revokedAt: null };
      },
      async findByHash(tokenHash) {
        const t = s.refreshTokens.find((x) => x.tokenHash === tokenHash);
        return t
          ? { id: t.id, userId: t.userId, familyId: t.familyId, expiresAt: t.expiresAt, revokedAt: t.revokedAt }
          : null;
      },
      async revoke(id, at, replacedBy) {
        const t = s.refreshTokens.find((x) => x.id === id);
        if (!t || t.revokedAt) return false;
        t.revokedAt = at;
        t.replacedBy = replacedBy ?? null;
        return true;
      },
      async revokeFamily(familyId, at) {
        for (const t of s.refreshTokens) if (t.familyId === familyId && !t.revokedAt) t.revokedAt = at;
      },
    },
    scopes: {
      async create(input) {
        if (s.scopes.some((x) => x.orgId === input.orgId && x.type === input.type && x.value === input.value)) {
          throw new UniqueViolationError("scope");
        }
        const scope: ScopeRecord = {
          id: randomUUID(),
          status: "PENDING",
          verificationMethod: null,
          verifiedAt: null,
          expiresAt: null,
          revokedAt: null,
          maxRequestsPerSec: 5,
          lastVerificationAt: null,
          lastVerificationError: null,
          createdAt: new Date(),
          ...input,
          allowedEngines: [...input.allowedEngines],
        };
        s.scopes.push(scope);
        return copy(scope);
      },
      async find(orgId, id) {
        const x = s.scopes.find((sc) => sc.id === id && sc.orgId === orgId);
        return x ? copy(x) : null;
      },
      async listByOrg(orgId) {
        return s.scopes.filter((sc) => sc.orgId === orgId).map(copy);
      },
      async markVerified(id, { method, at, expiresAt }) {
        const sc = s.scopes.find((x) => x.id === id)!;
        Object.assign(sc, {
          status: "VERIFIED",
          verificationMethod: method,
          verifiedAt: at,
          expiresAt,
          lastVerificationAt: at,
          lastVerificationError: null,
        });
        return copy(sc);
      },
      async recordVerificationFailure(id, at, error) {
        const sc = s.scopes.find((x) => x.id === id);
        if (sc) Object.assign(sc, { lastVerificationAt: at, lastVerificationError: error });
      },
      async setCriticality(orgId, id, criticality) {
        const sc = s.scopes.find((x) => x.id === id && x.orgId === orgId);
        if (!sc) return null;
        sc.criticality = criticality;
        return copy(sc);
      },
      async revoke(id, at) {
        const sc = s.scopes.find((x) => x.id === id);
        if (sc) Object.assign(sc, { status: "REVOKED", revokedAt: at });
      },
    },
    assets: {
      async upsert({ scopeId, kind, address, at }) {
        let a = s.assets.find((x) => x.scopeId === scopeId && x.kind === kind && x.address === address);
        if (a) a.lastSeen = at;
        else {
          a = { id: randomUUID(), scopeId, kind, address, firstSeen: at, lastSeen: at, metadata: null, discoveredByScanId: null };
          s.assets.push(a);
        }
        return copy(a);
      },
      async listByOrg(orgId, scopeId) {
        const scopeIds = new Set(s.scopes.filter((sc) => sc.orgId === orgId).map((sc) => sc.id));
        return s.assets.filter((a) => scopeIds.has(a.scopeId) && (!scopeId || a.scopeId === scopeId)).map(copy);
      },
    },
    scans: {
      async create(input) {
        const scan: ScanRecord = {
          id: randomUUID(),
          approvedById: null,
          approvedAt: null,
          killedAt: null,
          killedById: null,
          createdAt: new Date(),
          ...input,
        };
        s.scans.push(scan);
        return copy(scan);
      },
      async find(orgId, id) {
        const x = s.scans.find((sc) => sc.id === id && sc.orgId === orgId);
        return x ? copy(x) : null;
      },
      async listByOrg(orgId) {
        return s.scans.filter((sc) => sc.orgId === orgId).map(copy);
      },
      async approve(id, approvedById, at) {
        const sc = s.scans.find((x) => x.id === id);
        if (!sc || sc.status !== "PENDING_APPROVAL") return false;
        Object.assign(sc, { approvedById, approvedAt: at });
        return true;
      },
      async resolvePending(id, status) {
        const sc = s.scans.find((x) => x.id === id);
        if (!sc || sc.status !== "PENDING_APPROVAL") return false;
        sc.status = status;
        return true;
      },
      async kill(id, byId, at) {
        const sc = s.scans.find((x) => x.id === id);
        if (!sc || !isActive(sc)) return false;
        Object.assign(sc, { status: "KILLED", killedAt: at, killedById: byId });
        return true;
      },
      async lockOrg() {},
      async markFailed(id) {
        const sc = s.scans.find((x) => x.id === id);
        if (sc && sc.status === "QUEUED") sc.status = "FAILED";
      },
      async killActive({ orgId, scopeId }, byId, at) {
        const killed: { id: string; engine: ScanRecord["engine"] }[] = [];
        for (const sc of s.scans) {
          if (sc.orgId === orgId && (!scopeId || sc.scopeId === scopeId) && isActive(sc)) {
            Object.assign(sc, { status: "KILLED", killedAt: at, killedById: byId });
            killed.push({ id: sc.id, engine: sc.engine });
          }
        }
        return killed;
      },
    },
    schedules: {
      async create(input) {
        const r: ScheduleRecord = { id: randomUUID(), enabled: true, lastRunAt: null, createdAt: new Date(), ...input };
        s.schedules.push(r);
        return copy(r);
      },
      async listByOrg(orgId) {
        return s.schedules.filter((x) => x.orgId === orgId).map(copy);
      },
      async find(orgId, id) {
        const x = s.schedules.find((y) => y.id === id && y.orgId === orgId);
        return x ? copy(x) : null;
      },
      async update(orgId, id, patch) {
        const x = s.schedules.find((y) => y.id === id && y.orgId === orgId);
        if (!x) return null;
        Object.assign(x, patch);
        return copy(x);
      },
      async remove(orgId, id) {
        const i = s.schedules.findIndex((y) => y.id === id && y.orgId === orgId);
        if (i < 0) return false;
        s.schedules.splice(i, 1);
        return true;
      },
      async dueForRun(now, limit) {
        return s.schedules
          .filter((x) => x.enabled && x.nextRunAt !== null && x.nextRunAt <= now)
          .sort((a, b) => (a.nextRunAt!.getTime()) - (b.nextRunAt!.getTime()))
          .slice(0, limit)
          .map(copy);
      },
      async markRun(id, lastRunAt, nextRunAt) {
        const x = s.schedules.find((y) => y.id === id);
        if (x) Object.assign(x, { lastRunAt, nextRunAt });
      },
    },
    channels: {
      async create(input) {
        const c: ChannelRecord = { id: randomUUID(), enabled: true, lastNotifiedAt: null, lastError: null, createdAt: new Date(), ...input };
        s.channels.push(c);
        return copy(c);
      },
      async listByOrg(orgId) {
        return s.channels.filter((x) => x.orgId === orgId).map(copy);
      },
      async enabledForOrg(orgId) {
        return s.channels.filter((x) => x.orgId === orgId && x.enabled).map(copy);
      },
      async find(orgId, id) {
        const x = s.channels.find((y) => y.id === id && y.orgId === orgId);
        return x ? copy(x) : null;
      },
      async update(orgId, id, patch) {
        const x = s.channels.find((y) => y.id === id && y.orgId === orgId);
        if (!x) return null;
        Object.assign(x, patch);
        return copy(x);
      },
      async remove(orgId, id) {
        const i = s.channels.findIndex((y) => y.id === id && y.orgId === orgId);
        if (i < 0) return false;
        s.channels.splice(i, 1);
        return true;
      },
      async recordResult(id, at, error) {
        const x = s.channels.find((y) => y.id === id);
        if (x) Object.assign(x, { lastNotifiedAt: at, lastError: error });
      },
    },
    reports: {
      async create(input) {
        const r = { id: randomUUID(), format: "HTML" as const, createdAt: new Date(), ...input };
        s.reports.push(r);
        const { content: _c, ...rec } = r;
        return copy(rec);
      },
      async listByOrg(orgId) {
        return s.reports.filter((r) => r.orgId === orgId).map(({ content: _c, ...rec }) => copy(rec)).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
      },
      async find(orgId, id) {
        const r = s.reports.find((x) => x.id === id && x.orgId === orgId);
        if (!r) return null;
        const { content: _c, ...rec } = r;
        return copy(rec);
      },
      async loadContent(id) {
        const r = s.reports.find((x) => x.id === id);
        return r ? { orgId: r.orgId, title: r.title, content: r.content } : null;
      },
    },
    findings: {
      async listByOrg(orgId, filter = {}) {
        const scopeIds = new Set(s.scopes.filter((sc) => sc.orgId === orgId).map((sc) => sc.id));
        const order = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
        return s.findings
          .map((f) => ({ f, asset: s.assets.find((a) => a.id === f.assetId)! }))
          .filter(({ f, asset }) => asset && scopeIds.has(asset.scopeId))
          .filter(({ f, asset }) =>
            (!filter.status || f.status === filter.status) &&
            (!filter.severity || f.severity === filter.severity) &&
            (!filter.assetId || f.assetId === filter.assetId) &&
            (!filter.scopeId || asset.scopeId === filter.scopeId))
          .sort((a, b) => (b.f.riskScore ?? -1) - (a.f.riskScore ?? -1) || order[b.f.severity] - order[a.f.severity] || b.f.lastSeenAt.getTime() - a.f.lastSeenAt.getTime())
          .map(({ f, asset }) => ({ ...copy(f), assetAddress: asset.address, assetKind: asset.kind, scopeId: asset.scopeId }));
      },
      async find(orgId, id) {
        const f = s.findings.find((x) => x.id === id);
        if (!f) return null;
        const asset = s.assets.find((a) => a.id === f.assetId);
        const scope = asset && s.scopes.find((sc) => sc.id === asset.scopeId && sc.orgId === orgId);
        return scope ? copy(f) : null;
      },
      async setStatus(orgId, id, status) {
        const f = s.findings.find((x) => x.id === id);
        const asset = f && s.assets.find((a) => a.id === f.assetId);
        const scope = asset && s.scopes.find((sc) => sc.id === asset.scopeId && sc.orgId === orgId);
        if (!f || !scope) return false;
        f.status = status;
        return true;
      },
      async newForScan(scanId, since) {
        return s.findings
          .filter((f) => f.lastScanId === scanId && f.firstSeenAt >= since && (f.status === "OPEN" || f.status === "TRIAGED"))
          .sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1))
          .map((f) => ({ ...copy(f), assetAddress: s.assets.find((a) => a.id === f.assetId)?.address ?? "" }));
      },
      async summary(orgId) {
        const scopeIds = new Set(s.scopes.filter((sc) => sc.orgId === orgId).map((sc) => sc.id));
        const out = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
        for (const f of s.findings) {
          const asset = s.assets.find((a) => a.id === f.assetId);
          if (asset && scopeIds.has(asset.scopeId) && (f.status === "OPEN" || f.status === "TRIAGED")) out[f.severity]++;
        }
        return out;
      },
    },
    gate: {
      async findAssetWithScope(assetId) {
        const asset = s.assets.find((a) => a.id === assetId);
        const scope = asset && s.scopes.find((sc) => sc.id === asset.scopeId);
        if (!asset || !scope) return null;
        return {
          asset: { id: asset.id, scopeId: asset.scopeId, kind: asset.kind, address: asset.address },
          scope: {
            id: scope.id,
            orgId: scope.orgId,
            type: scope.type,
            value: scope.value,
            status: scope.status,
            expiresAt: scope.expiresAt,
            allowedEngines: [...scope.allowedEngines],
            maxRequestsPerSec: scope.maxRequestsPerSec,
          },
        };
      },
      async findOrg(orgId) {
        const o = s.orgs.find((x) => x.id === orgId);
        return o ? { id: o.id, killSwitchEngaged: o.killSwitchEngaged } : null;
      },
      async findScan(scanId) {
        const sc = s.scans.find((x) => x.id === scanId);
        return sc
          ? {
              id: sc.id,
              orgId: sc.orgId,
              scopeId: sc.scopeId,
              assetId: sc.assetId,
              engine: sc.engine,
              status: sc.status,
              approvedById: sc.approvedById,
              killedAt: sc.killedAt,
            }
          : null;
      },
      async countActiveScans(orgId) {
        return s.scans.filter((sc) => sc.orgId === orgId && (sc.status === "QUEUED" || sc.status === "RUNNING")).length;
      },
    },
    audit: {
      async append(event) {
        s.audit.push(event);
      },
    },
    async transaction(fn) {
      const snapshot: State = {
        users: s.users.map(copy),
        orgs: s.orgs.map(copy),
        memberships: s.memberships.map(copy),
        invites: s.invites.map(copy),
        refreshTokens: s.refreshTokens.map(copy),
        scopes: s.scopes.map(copy),
        assets: s.assets.map(copy),
        scans: s.scans.map(copy),
        findings: s.findings.map(copy),
        reports: s.reports.map(copy),
        schedules: s.schedules.map(copy),
        channels: s.channels.map(copy),
        audit: s.audit.slice(),
      };
      try {
        return await fn(store);
      } catch (err) {
        s = snapshot;
        throw err;
      }
    },
  };
  return store;
}
