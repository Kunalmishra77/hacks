import type {
  AssetKind,
  AuditSink,
  Engine,
  GateRepository,
  Role,
  ScanStatus,
  ScopeStatus,
  ScopeType,
  Severity,
  VerificationMethod,
} from "@aegis/core";

export type FindingStatus = "OPEN" | "TRIAGED" | "FIXED" | "FALSE_POSITIVE";

export interface ReportRecord {
  id: string;
  orgId: string;
  scopeId: string | null;
  title: string;
  format: "HTML" | "PDF";
  summary: unknown;
  byteSize: number;
  createdById: string;
  createdAt: Date;
}

export interface FindingRecord {
  id: string;
  assetId: string;
  scanId: string;
  type: string;
  severity: Severity;
  cvss: number | null;
  cveRefs: string[];
  title: string;
  evidence: unknown;
  remediation: string | null;
  status: FindingStatus;
  epss: number | null;
  kevListed: boolean;
  riskScore: number | null;
  enrichedAt: Date | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

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

export interface ScopeRecord {
  id: string;
  orgId: string;
  type: ScopeType;
  value: string;
  status: ScopeStatus;
  verificationMethod: VerificationMethod | null;
  verificationToken: string | null;
  verifiedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  allowedEngines: Engine[];
  maxRequestsPerSec: number;
  criticality: "LOW" | "MEDIUM" | "HIGH";
  cloudRoleArn: string | null;
  externalId: string | null;
  lastVerificationAt: Date | null;
  lastVerificationError: string | null;
  createdById: string;
  createdAt: Date;
}

export interface AssetRecord {
  id: string;
  scopeId: string;
  kind: AssetKind;
  address: string;
  firstSeen: Date;
  lastSeen: Date;
  metadata: unknown;
  discoveredByScanId: string | null;
}

export interface ScanRecord {
  id: string;
  orgId: string;
  scopeId: string;
  assetId: string | null;
  engine: Engine;
  status: ScanStatus;
  requestedById: string;
  approvedById: string | null;
  approvedAt: Date | null;
  killedAt: Date | null;
  killedById: string | null;
  createdAt: Date;
}

/** Statuses a kill (org kill-switch, scope revoke, scan kill) moves to KILLED. */
export const ACTIVE_SCAN_STATUSES: readonly ScanStatus[] = ["PENDING_APPROVAL", "QUEUED", "RUNNING"];

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
    setKillSwitch(id: string, engaged: boolean, byId: string, at: Date): Promise<void>;
  };
  scopes: {
    create(input: {
      orgId: string;
      type: ScopeType;
      value: string;
      allowedEngines: Engine[];
      criticality: "LOW" | "MEDIUM" | "HIGH";
      verificationToken: string;
      cloudRoleArn: string | null;
      externalId: string | null;
      createdById: string;
    }): Promise<ScopeRecord>;
    /** Org-scoped lookup: never returns another org's scope. */
    find(orgId: string, id: string): Promise<ScopeRecord | null>;
    listByOrg(orgId: string): Promise<ScopeRecord[]>;
    markVerified(
      id: string,
      input: { method: VerificationMethod; at: Date; expiresAt: Date },
    ): Promise<ScopeRecord>;
    recordVerificationFailure(id: string, at: Date, error: string): Promise<void>;
    setCriticality(orgId: string, id: string, criticality: "LOW" | "MEDIUM" | "HIGH"): Promise<ScopeRecord | null>;
    revoke(id: string, at: Date): Promise<void>;
  };
  assets: {
    /** Creates or touches (lastSeen) an asset. Only ever called for verified scopes. */
    upsert(input: { scopeId: string; kind: AssetKind; address: string; at: Date }): Promise<AssetRecord>;
    listByOrg(orgId: string, scopeId?: string): Promise<AssetRecord[]>;
  };
  scans: {
    create(input: {
      orgId: string;
      scopeId: string;
      assetId: string;
      engine: Engine;
      status: "PENDING_APPROVAL" | "QUEUED";
      requestedById: string;
    }): Promise<ScanRecord>;
    find(orgId: string, id: string): Promise<ScanRecord | null>;
    listByOrg(orgId: string): Promise<ScanRecord[]>;
    /** Records approval on a PENDING_APPROVAL scan. Returns false if not pending. */
    approve(id: string, approvedById: string, at: Date): Promise<boolean>;
    /** Moves PENDING_APPROVAL → QUEUED or REJECTED. Returns false if no longer pending. */
    resolvePending(id: string, status: "QUEUED" | "REJECTED"): Promise<boolean>;
    /** QUEUED → FAILED (e.g. the queue was unreachable). */
    markFailed(id: string, error: string, at: Date): Promise<void>;
    /** Kills one scan if active. Returns false if it was not active. */
    kill(id: string, byId: string, at: Date): Promise<boolean>;
    /** Kills all active scans for an org (or one scope). Returns the scans it killed. */
    killActive(filter: { orgId: string; scopeId?: string }, byId: string, at: Date): Promise<{ id: string; engine: Engine }[]>;
    /**
     * Serializes scan admission per org until the transaction ends, so the
     * concurrency cap can be checked and the scan created atomically.
     */
    lockOrg(orgId: string): Promise<void>;
  };
  findings: {
    listByOrg(
      orgId: string,
      filter?: { status?: FindingStatus; severity?: Severity; scopeId?: string; assetId?: string },
    ): Promise<(FindingRecord & { assetAddress: string; assetKind: AssetKind; scopeId: string })[]>;
    find(orgId: string, id: string): Promise<FindingRecord | null>;
    /** Changes a finding's triage status. Returns false if it doesn't exist in the org. */
    setStatus(orgId: string, id: string, status: FindingStatus): Promise<boolean>;
    /** Open/triaged counts per severity, for the dashboard summary. */
    summary(orgId: string): Promise<Record<Severity, number>>;
  };
  /** Read-only view the Scope Authorization Gate uses. */
  reports: {
    create(input: {
      orgId: string;
      scopeId: string | null;
      title: string;
      summary: Record<string, unknown>;
      content: string;
      byteSize: number;
      createdById: string;
    }): Promise<ReportRecord>;
    listByOrg(orgId: string): Promise<ReportRecord[]>;
    find(orgId: string, id: string): Promise<ReportRecord | null>;
    /** For download: the stored body. Returns orgId so callers can double-check tenancy. */
    loadContent(id: string): Promise<{ orgId: string; title: string; content: string | null } | null>;
  };
  gate: GateRepository;
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
