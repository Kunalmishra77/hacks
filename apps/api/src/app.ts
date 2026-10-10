import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import type { Redis } from "ioredis";
import { createAuditLogger, createMemoryRateLimiter, createScopeGate, type RateLimiter, type ScopeGate } from "@aegis/core";
import type { AppConfig } from "./config.js";
import { authPlugin } from "./plugins/auth.js";
import { authRoutes } from "./routes/auth.js";
import { orgRoutes } from "./routes/orgs.js";
import { scanRoutes } from "./routes/scans.js";
import { scopeRoutes } from "./routes/scopes.js";
import { createVerifier, defaultVerificationDeps, type Verifier } from "./verification/verifiers.js";
import { UniqueViolationError, type Store } from "./store/types.js";

export interface BuildAppOptions {
  config: AppConfig;
  store: Store;
  logger?: boolean;
  /** Shared limiter for the scope gate and verification. Defaults to in-process. */
  limiter?: RateLimiter;
  /** Ownership verifier. Tests inject fakes; defaults to real DNS/HTTPS/STS. */
  verifier?: Verifier;
  /** When given, login rate limits are shared across processes too. */
  redis?: Redis;
}

declare module "fastify" {
  interface FastifyInstance {
    /** The one Scope Authorization Gate instance every scan path uses. */
    scopeGate: ScopeGate;
  }
}

export async function buildApp({
  config,
  store,
  logger = false,
  limiter = createMemoryRateLimiter(),
  verifier = createVerifier(defaultVerificationDeps),
  redis,
}: BuildAppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: logger && {
      redact: ["req.headers.authorization", "req.headers.cookie", 'res.headers["set-cookie"]'],
    },
    trustProxy: config.env === "production", // behind the VPS reverse proxy
    bodyLimit: 64 * 1024,
  });

  await app.register(helmet);
  await app.register(cors, { origin: config.corsOrigins, credentials: true });
  await app.register(cookie);
  // Opt-in per route (credential endpoints), not global.
  await app.register(rateLimit, { global: false, ...(redis ? { redis, nameSpace: "aegis:http-rl:" } : {}) });
  await app.register(authPlugin, { config, store });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({
        error: "validation_error",
        issues: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      });
    }
    if (err instanceof UniqueViolationError) {
      return reply.code(409).send({ error: "conflict" });
    }
    const e = err as { statusCode?: number; code?: string; message?: string };
    if (e.statusCode && e.statusCode >= 400 && e.statusCode < 500) {
      return reply.code(e.statusCode).send({ error: e.code ?? "bad_request", message: e.message });
    }
    req.log.error(err);
    return reply.code(500).send({ error: "internal_error" });
  });

  app.get("/health", async () => ({ status: "ok" }));
  await app.register(authRoutes, { config, store });
  await app.register(orgRoutes, { config, store });

  const gate = createScopeGate({
    repo: store.gate,
    limiter,
    audit: createAuditLogger(store.audit),
    limits: config.gateLimits,
  });
  app.decorate("scopeGate", gate);
  await app.register(scopeRoutes, { config, store, limiter, verifier });
  await app.register(scanRoutes, { store, gate });

  return app;
}
