import { describe, expect, it } from "vitest";
import { can, canGrantRole, hasRole, isRole, PERMISSIONS, ROLES } from "../src/index.js";

describe("rbac", () => {
  it("orders roles Owner > Admin > Analyst > Viewer", () => {
    expect(hasRole("OWNER", "ADMIN")).toBe(true);
    expect(hasRole("ADMIN", "ANALYST")).toBe(true);
    expect(hasRole("ANALYST", "VIEWER")).toBe(true);
    expect(hasRole("VIEWER", "ANALYST")).toBe(false);
    expect(hasRole("ANALYST", "ADMIN")).toBe(false);
    expect(hasRole("ADMIN", "OWNER")).toBe(false);
  });

  it("matches the PRD role matrix", () => {
    expect(can("VIEWER", "finding.read")).toBe(true);
    expect(can("VIEWER", "scan.run")).toBe(false);
    expect(can("ANALYST", "scan.run")).toBe(true);
    expect(can("ANALYST", "scan.approve")).toBe(false);
    expect(can("ANALYST", "scope.manage")).toBe(false);
    expect(can("ADMIN", "scope.manage")).toBe(true);
    expect(can("ADMIN", "scan.approve")).toBe(true);
    expect(can("ADMIN", "billing.manage")).toBe(false);
    expect(can("OWNER", "org.delete")).toBe(true);
  });

  it("grants every permission to Owner", () => {
    for (const p of Object.keys(PERMISSIONS) as (keyof typeof PERMISSIONS)[]) {
      expect(can("OWNER", p)).toBe(true);
    }
  });

  it("only lets Owners grant Owner, and never above your own role", () => {
    expect(canGrantRole("OWNER", "OWNER")).toBe(true);
    expect(canGrantRole("ADMIN", "OWNER")).toBe(false);
    expect(canGrantRole("ADMIN", "ADMIN")).toBe(true);
    expect(canGrantRole("ADMIN", "VIEWER")).toBe(true);
    expect(canGrantRole("ANALYST", "VIEWER")).toBe(false);
    expect(canGrantRole("VIEWER", "VIEWER")).toBe(false);
  });

  it("validates role strings strictly", () => {
    for (const r of ROLES) expect(isRole(r)).toBe(true);
    expect(isRole("owner")).toBe(false);
    expect(isRole("toString")).toBe(false);
    expect(isRole(undefined)).toBe(false);
  });
});
