// Shared types. Kept free of Prisma imports so the web app and workers can
// use them without pulling in the DB client. String values mirror the
// Prisma enums in packages/db/prisma/schema.prisma.

export const ROLES = ["OWNER", "ADMIN", "ANALYST", "VIEWER"] as const;
export type Role = (typeof ROLES)[number];

export const ENGINES = ["DISCOVERY", "NETWORK", "TLS", "WEB", "CLOUD", "DEPS"] as const;
export type Engine = (typeof ENGINES)[number];

export const SCOPE_TYPES = ["DOMAIN", "IP_RANGE", "CLOUD_ACCOUNT"] as const;
export type ScopeType = (typeof SCOPE_TYPES)[number];

export type ScopeStatus = "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";

export const VERIFICATION_METHODS = ["DNS_TXT", "HTTP_FILE", "CLOUD_ROLE"] as const;
export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];

export type AssetKind = "DOMAIN" | "SUBDOMAIN" | "IP" | "SERVICE" | "CLOUD_RESOURCE";

export type ScanStatus =
  | "PENDING_APPROVAL"
  | "QUEUED"
  | "RUNNING"
  | "SUCCEEDED"
  | "FAILED"
  | "KILLED"
  | "REJECTED";

export type ActorType = "user" | "api_key" | "system" | "anonymous";

export interface Actor {
  type: ActorType;
  /** User id or API key id. Absent for anonymous/system actors. */
  id?: string;
}
