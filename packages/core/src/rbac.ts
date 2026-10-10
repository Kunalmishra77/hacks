import type { Role } from "./types.js";

/**
 * Role ranks. A role holds every permission of the roles ranked below it
 * (PRD §6).
 */
const RANK: Record<Role, number> = {
  OWNER: 40,
  ADMIN: 30,
  ANALYST: 20,
  VIEWER: 10,
};

/** Minimum role required for each permission. */
export const PERMISSIONS = {
  "org.read": "VIEWER",
  "org.update": "OWNER",
  "org.delete": "OWNER",
  "billing.manage": "OWNER",
  "member.read": "VIEWER",
  "member.invite": "ADMIN",
  "member.remove": "ADMIN",
  "scope.read": "VIEWER",
  "scope.manage": "ADMIN",
  "scan.run": "ANALYST",
  "scan.approve": "ADMIN",
  "scan.kill": "ANALYST",
  // Anyone who can start scans can hit the emergency stop; only Admins can
  // lift it again.
  "killswitch.engage": "ANALYST",
  "killswitch.release": "ADMIN",
  "finding.read": "VIEWER",
  "finding.triage": "ANALYST",
  "report.read": "VIEWER",
  "report.create": "ANALYST",
  "audit.read": "ADMIN",
  "apikey.manage": "ADMIN",
} as const satisfies Record<string, Role>;

export type Permission = keyof typeof PERMISSIONS;

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && Object.hasOwn(RANK, value);
}

/** True when `role` is at least as privileged as `minimum`. */
export function hasRole(role: Role, minimum: Role): boolean {
  return RANK[role] >= RANK[minimum];
}

export function can(role: Role, permission: Permission): boolean {
  return hasRole(role, PERMISSIONS[permission]);
}

/**
 * Whether `actorRole` may grant `targetRole` (invite / role change).
 * Only an Owner can create another Owner; otherwise a member manager may grant
 * roles up to and including their own.
 */
export function canGrantRole(actorRole: Role, targetRole: Role): boolean {
  if (!can(actorRole, "member.invite")) return false;
  if (targetRole === "OWNER") return actorRole === "OWNER";
  return hasRole(actorRole, targetRole);
}
