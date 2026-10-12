// Browser client for the Aegis API. The access token lives only in memory;
// the refresh token is an httpOnly cookie the browser sends to /auth/*.

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

let accessToken: string | null = null;

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: Record<string, unknown>,
  ) {
    super(typeof body.message === "string" ? body.message : typeof body.error === "string" ? body.error : `HTTP ${status}`);
  }
}

async function raw(path: string, init: RequestInit = {}, auth = true): Promise<Response> {
  const headers = new Headers(init.headers);
  if (auth && accessToken) headers.set("authorization", `Bearer ${accessToken}`);
  if (init.body !== undefined) headers.set("content-type", "application/json");
  return fetch(`${API_URL}${path}`, { ...init, headers, credentials: "include" });
}

/** Swaps the refresh cookie for a new access token. False if the session is gone. */
export async function refreshSession(): Promise<boolean> {
  const res = await raw("/auth/refresh", { method: "POST" }, false);
  if (!res.ok) {
    accessToken = null;
    return false;
  }
  accessToken = ((await res.json()) as { accessToken: string }).accessToken;
  return true;
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const req = { method: init.method ?? "GET", body: init.body === undefined ? undefined : JSON.stringify(init.body) };
  let res = await raw(path, req);
  if (res.status === 401 && (await refreshSession())) res = await raw(path, req);
  const body = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body as Record<string, unknown>);
  return body as T;
}

export async function login(email: string, password: string) {
  const res = await raw("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }, false);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body);
  accessToken = body.accessToken;
}

export async function register(email: string, password: string, orgName: string) {
  const res = await raw("/auth/register", { method: "POST", body: JSON.stringify({ email, password, orgName }) }, false);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body);
  accessToken = body.accessToken;
}

export async function logout() {
  await raw("/auth/logout", { method: "POST" }, false).catch(() => {});
  accessToken = null;
}

// ── Types mirrored from the API responses ──────────────────────────

export type Role = "OWNER" | "ADMIN" | "ANALYST" | "VIEWER";
export type Engine = "DISCOVERY" | "NETWORK" | "TLS" | "WEB" | "CLOUD" | "DEPS";

export interface OrgSummary {
  id: string;
  name: string;
  slug: string;
  role: Role;
}

export interface Scope {
  id: string;
  type: "DOMAIN" | "IP_RANGE" | "CLOUD_ACCOUNT";
  value: string;
  status: "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
  verificationMethod: string | null;
  verifiedAt: string | null;
  expiresAt: string | null;
  allowedEngines: Engine[];
  lastVerificationError: string | null;
  verification: {
    DNS_TXT?: { recordType: string; name: string; value: string };
    HTTP_FILE?: { url: string; content: string };
    CLOUD_ROLE?: { roleArn: string; externalId: string; trustedPrincipal: string; requiredPolicy: string };
  } | null;
}

export interface Asset {
  id: string;
  scopeId: string;
  kind: "DOMAIN" | "SUBDOMAIN" | "IP" | "SERVICE" | "CLOUD_RESOURCE";
  address: string;
  firstSeen: string;
  lastSeen: string;
  metadata: Record<string, unknown> | null;
}

export interface Scan {
  id: string;
  scopeId: string;
  assetId: string | null;
  engine: Engine;
  status: "PENDING_APPROVAL" | "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "KILLED" | "REJECTED";
  approvedById: string | null;
  createdAt: string;
}

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingStatus = "OPEN" | "TRIAGED" | "FIXED" | "FALSE_POSITIVE";

export interface Finding {
  id: string;
  assetId: string;
  assetAddress: string;
  assetKind: Asset["kind"];
  scopeId: string;
  type: string;
  severity: Severity;
  cvss: number | null;
  cveRefs: string[];
  title: string;
  evidence: Record<string, unknown> | null;
  remediation: string | null;
  status: FindingStatus;
  firstSeenAt: string;
  lastSeenAt: string;
}

export type SeveritySummary = Record<Severity, number>;

export const can = {
  manageScopes: (r: Role) => r === "OWNER" || r === "ADMIN",
  runScans: (r: Role) => r !== "VIEWER",
  approve: (r: Role) => r === "OWNER" || r === "ADMIN",
  triage: (r: Role) => r !== "VIEWER",
  releaseKillSwitch: (r: Role) => r === "OWNER" || r === "ADMIN",
};
