import { z } from "zod";

const secret = z.string().min(32, "must be at least 32 characters");

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    API_HOST: z.string().default("127.0.0.1"),
    API_PORT: z.coerce.number().int().positive().default(4000),
    CORS_ORIGINS: z.string().default("http://localhost:3000"),
    COOKIE_SECURE: z
      .enum(["true", "false"])
      .default("false")
      .transform((v) => v === "true"),
    JWT_SECRET: secret,
    JWT_REFRESH_SECRET: secret,
    JWT_ISSUER: z.string().default("aegis-api"),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(30),
    INVITE_TTL_HOURS: z.coerce.number().int().positive().default(72),
  })
  .refine((e) => e.JWT_SECRET !== e.JWT_REFRESH_SECRET, {
    message: "JWT_SECRET and JWT_REFRESH_SECRET must differ",
    path: ["JWT_REFRESH_SECRET"],
  });

export interface AppConfig {
  env: "development" | "test" | "production";
  host: string;
  port: number;
  corsOrigins: string[];
  cookieSecure: boolean;
  jwtSecret: string;
  refreshSecret: string;
  jwtIssuer: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlDays: number;
  inviteTtlHours: number;
  /** Per-IP limit on credential endpoints. */
  authRateLimit: { max: number; timeWindowMs: number };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  const e = parsed.data;
  if (e.NODE_ENV === "production" && !e.COOKIE_SECURE) {
    throw new Error("COOKIE_SECURE must be true in production");
  }
  return {
    env: e.NODE_ENV,
    host: e.API_HOST,
    port: e.API_PORT,
    corsOrigins: e.CORS_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean),
    cookieSecure: e.COOKIE_SECURE,
    jwtSecret: e.JWT_SECRET,
    refreshSecret: e.JWT_REFRESH_SECRET,
    jwtIssuer: e.JWT_ISSUER,
    accessTokenTtlSeconds: e.ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlDays: e.REFRESH_TOKEN_TTL_DAYS,
    inviteTtlHours: e.INVITE_TTL_HOURS,
    authRateLimit: { max: 10, timeWindowMs: 60_000 },
  };
}
