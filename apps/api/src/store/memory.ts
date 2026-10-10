import { randomUUID } from "node:crypto";
import type { AuditEvent } from "@aegis/core";
import {
  UniqueViolationError,
  type InviteRecord,
  type MembershipRecord,
  type OrgRecord,
  type RefreshTokenRecord,
  type Store,
  type UserRecord,
} from "./types.js";

interface State {
  users: UserRecord[];
  orgs: OrgRecord[];
  memberships: MembershipRecord[];
  invites: (InviteRecord & { tokenHash: string })[];
  refreshTokens: (RefreshTokenRecord & { tokenHash: string; replacedBy: string | null })[];
  audit: AuditEvent[];
}

/**
 * In-memory Store for tests. `transaction` snapshots state and restores it if
 * the callback throws, mirroring Postgres rollback semantics.
 */
export function createMemoryStore(): Store & { readonly auditEvents: readonly AuditEvent[] } {
  let s: State = { users: [], orgs: [], memberships: [], invites: [], refreshTokens: [], audit: [] };
  const copy = <T>(v: T): T => ({ ...v });

  const store: Store & { readonly auditEvents: readonly AuditEvent[] } = {
    get auditEvents() {
      return s.audit.slice();
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
