import type { AuditSink, Role } from "@aegis/core";

// Persistence boundary for the API. Routes depend on this interface only, so
// they run against Postgres (prisma.ts) in production and an in-memory
// implementation (memory.ts) in tests.

export interface UserRecord {
  id: string;
  email: string;
  name: string | null;
  passwordHash: string;
  disabledAt: Date | null;
}

export interface OrgRecord {
  id: string;
  name: string;
  slug: string;
  killSwitchEngaged: boolean;
  createdAt: Date;
}

export interface MembershipRecord {
  id: string;
  orgId: string;
  userId: string;
  role: Role;
  createdAt: Date;
}

export interface InviteRecord {
  id: string;
  orgId: string;
  email: string;
  role: Role;
  invitedById: string;
  expiresAt: Date;
  acceptedAt: Date | null;
}

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  familyId: string;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface Store {
  users: {
    findByEmail(email: string): Promise<UserRecord | null>;
    findById(id: string): Promise<UserRecord | null>;
    create(input: { email: string; name: string | null; passwordHash: string }): Promise<UserRecord>;
    touchLogin(id: string, at: Date): Promise<void>;
  };
  orgs: {
    create(input: { name: string; slug: string }): Promise<OrgRecord>;
    findById(id: string): Promise<OrgRecord | null>;
  };
  memberships: {
    find(orgId: string, userId: string): Promise<MembershipRecord | null>;
    create(input: { orgId: string; userId: string; role: Role }): Promise<MembershipRecord>;
    listByOrg(orgId: string): Promise<(MembershipRecord & { email: string; name: string | null })[]>;
    listByUser(userId: string): Promise<(MembershipRecord & { org: OrgRecord })[]>;
  };
  invites: {
    create(input: {
      orgId: string;
      email: string;
      role: Role;
      tokenHash: string;
      invitedById: string;
      expiresAt: Date;
    }): Promise<InviteRecord>;
    findByTokenHash(tokenHash: string): Promise<InviteRecord | null>;
    /** Marks accepted only if still pending. Returns false if already used. */
    markAccepted(id: string, at: Date): Promise<boolean>;
  };
  refreshTokens: {
    create(input: {
      userId: string;
      tokenHash: string;
      familyId: string;
      expiresAt: Date;
    }): Promise<RefreshTokenRecord>;
    findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
    /**
     * Revokes the token if it is not already revoked. Returns false when it
     * was already revoked, which callers treat as token reuse.
     */
    revoke(id: string, at: Date, replacedBy?: string): Promise<boolean>;
    revokeFamily(familyId: string, at: Date): Promise<void>;
  };
  /** Append-only audit sink. */
  audit: AuditSink;
  /** Runs `fn` atomically. Writes inside, including audit events, commit together. */
  transaction<T>(fn: (tx: Store) => Promise<T>): Promise<T>;
}

export class UniqueViolationError extends Error {
  constructor(public readonly field: string) {
    super(`unique constraint violated: ${field}`);
  }
}
