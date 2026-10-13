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
    REDIS_URL: z.string().url().optional().or(z.literal("").transform(() => undefined)),
    SCOPE_VERIFICATION_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(90),
    MAX_CONCURRENT_SCANS_PER_ORG: z.coerce.number().int().positive().default(3),
    SCAN_STARTS_PER_SCOPE_PER_MINUTE: z.coerce.number().int().positive().default(5),
    AWS_TRUST_PRINCIPAL_ARN: z.string().optional().or(z.literal("").transform(() => undefined)),
    NVD_API_KEY: z.string().optional().or(z.literal("").transform(() => undefined)),
    // Run the CVE enrichment worker in this process. On by default; needs Redis.
    CVE_ENRICHMENT: z.enum(["on", "off"]).default("on"),
    // Absolute base URL of this API, used to build shareable report links.
    API_PUBLIC_URL: z.string().url().optional().or(z.literal("").transform(() => undefined)),
    REPORT_SHARE_TTL_HOURS: z.coerce.number().int().min(1).max(720).default(72),
    // Dashboard URL put into alert messages.
    WEB_PUBLIC_URL: z.string().url().optional().or(z.literal("").transform(() => undefined)),
    // Run the schedule tick in this process. On by default; needs Redis.
    SCHEDULER: z.enum(["on", "off"]).default("on"),
    SMTP_URL: z.string().optional().or(z.literal("").transform(() => undefined)),
    SMTP_FROM: z.string().optional().or(z.literal("").transform(() => undefined)),
    WHATSAPP_PHONE_NUMBER_ID: z.string().optional().or(z.literal("").transform(() => undefined)),
    WHATSAPP_TOKEN: z.string().optional().or(z.literal("").transform(() => undefined)),
    // AI advisory layer (Phase 7): advisory only, never triggers scans.
    AI_PROVIDER: z.enum(["off", "openai", "anthropic"]).default("off"),
    AI_MODEL: z.string().optional().or(z.literal("").transform(() => undefined)),
    OPENAI_API_KEY: z.string().optional().or(z.literal("").transform(() => undefined)),
    ANTHROPIC_API_KEY: z.string().optional().or(z.literal("").transform(() => undefined)),
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
  /** Required in production; dev/test fall back to an in-process limiter. */
  redisUrl?: string;
  scopeVerificationTtlDays: number;
  gateLimits: { maxConcurrentScansPerOrg: number; scanStartsPerScopePerMinute: number };
  /** Our AWS principal customers trust in their read-only role. */
  awsTrustPrincipalArn?: string;
  nvdApiKey?: string;
  cveEnrichment: boolean;
  apiPublicUrl?: string;
  reportShareTtlHours: number;
  webPublicUrl?: string;
  scheduler: boolean;
  smtpUrl?: string;
  smtpFrom?: string;
  whatsapp?: { phoneNumberId: string; token: string };
  ai?: { provider: "openai" | "anthropic"; apiKey: string; model?: string };
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
  if (e.NODE_ENV === "production" && !e.REDIS_URL) {
    // Rate limits must be shared across API processes in production.
    throw new Error("REDIS_URL is required in production");
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
    redisUrl: e.REDIS_URL,
    scopeVerificationTtlDays: e.SCOPE_VERIFICATION_TTL_DAYS,
    gateLimits: {
      maxConcurrentScansPerOrg: e.MAX_CONCURRENT_SCANS_PER_ORG,
      scanStartsPerScopePerMinute: e.SCAN_STARTS_PER_SCOPE_PER_MINUTE,
    },
    awsTrustPrincipalArn: e.AWS_TRUST_PRINCIPAL_ARN,
    nvdApiKey: e.NVD_API_KEY,
    cveEnrichment: e.CVE_ENRICHMENT === "on",
    apiPublicUrl: e.API_PUBLIC_URL,
    reportShareTtlHours: e.REPORT_SHARE_TTL_HOURS,
    webPublicUrl: e.WEB_PUBLIC_URL,
    scheduler: e.SCHEDULER === "on",
    smtpUrl: e.SMTP_URL,
    smtpFrom: e.SMTP_FROM,
    whatsapp: e.WHATSAPP_PHONE_NUMBER_ID && e.WHATSAPP_TOKEN ? { phoneNumberId: e.WHATSAPP_PHONE_NUMBER_ID, token: e.WHATSAPP_TOKEN } : undefined,
    ai:
      e.AI_PROVIDER === "openai" && e.OPENAI_API_KEY
        ? { provider: "openai" as const, apiKey: e.OPENAI_API_KEY, model: e.AI_MODEL }
        : e.AI_PROVIDER === "anthropic" && e.ANTHROPIC_API_KEY
          ? { provider: "anthropic" as const, apiKey: e.ANTHROPIC_API_KEY, model: e.AI_MODEL }
          : undefined,
  };
}
