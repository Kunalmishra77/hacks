import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { buildApp, type BuildAppOptions } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { REFRESH_COOKIE } from "../src/routes/auth.js";
import { createMemoryStore } from "../src/store/memory.js";

export const testConfig: AppConfig = {
  env: "test",
  host: "127.0.0.1",
  port: 0,
  corsOrigins: ["http://localhost:3000"],
  cookieSecure: false,
  jwtSecret: "test-access-secret-0123456789abcdef0123456789",
  refreshSecret: "test-refresh-secret-0123456789abcdef012345678",
  jwtIssuer: "aegis-test",
  accessTokenTtlSeconds: 900,
  refreshTokenTtlDays: 30,
  inviteTtlHours: 72,
  authRateLimit: { max: 1000, timeWindowMs: 60_000 },
  scopeVerificationTtlDays: 90,
  gateLimits: { maxConcurrentScansPerOrg: 3, scanStartsPerScopePerMinute: 5 },
};

export async function makeApp(
  overrides: Partial<AppConfig> = {},
  deps: Pick<BuildAppOptions, "verifier" | "limiter"> = {},
) {
  const store = createMemoryStore();
  const app = await buildApp({ config: { ...testConfig, ...overrides }, store, ...deps });
  return { app, store };
}

export const PASSWORD = "correct horse battery staple";

export function refreshCookie(res: LightMyRequestResponse): string | undefined {
  return res.cookies.find((c) => c.name === REFRESH_COOKIE)?.value;
}

export async function register(app: FastifyInstance, email: string, orgName?: string) {
  const res = await app.inject({
    method: "POST",
    url: "/auth/register",
    payload: { email, password: PASSWORD, ...(orgName ? { orgName } : {}) },
  });
  if (res.statusCode !== 201) throw new Error(`register failed: ${res.statusCode} ${res.body}`);
  const body = res.json() as { accessToken: string; user: { id: string }; org: { id: string } | null };
  return { ...body, refresh: refreshCookie(res) };
}

export function bearer(token: string) {
  return { authorization: `Bearer ${token}` };
}
