import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const base = {
  JWT_SECRET: "a".repeat(40),
  JWT_REFRESH_SECRET: "b".repeat(40),
};

describe("config", () => {
  it("loads with sane defaults", () => {
    const c = loadConfig({ ...base });
    expect(c).toMatchObject({ port: 4000, accessTokenTtlSeconds: 900, cookieSecure: false });
  });

  it("refuses short, missing, or identical secrets", () => {
    expect(() => loadConfig({})).toThrow(/JWT_SECRET/);
    expect(() => loadConfig({ ...base, JWT_SECRET: "short" })).toThrow(/at least 32/);
    expect(() => loadConfig({ ...base, JWT_REFRESH_SECRET: base.JWT_SECRET })).toThrow(/must differ/);
  });

  it("requires secure cookies and Redis in production", () => {
    const redis = { REDIS_URL: "redis://localhost:6379" };
    expect(() => loadConfig({ ...base, ...redis, NODE_ENV: "production" })).toThrow(/COOKIE_SECURE/);
    expect(() => loadConfig({ ...base, NODE_ENV: "production", COOKIE_SECURE: "true" })).toThrow(/REDIS_URL/);
    const prod = loadConfig({ ...base, ...redis, NODE_ENV: "production", COOKIE_SECURE: "true" });
    expect(prod).toMatchObject({ cookieSecure: true, redisUrl: "redis://localhost:6379" });
  });
});
