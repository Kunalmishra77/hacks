import { randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  createAuditLogger,
  ENGINES,
  normalizeDomain,
  parseCidr,
  type AssetKind,
  type Engine,
  type RateLimiter,
  type ScopeType,
  type VerificationMethod,
} from "@aegis/core";
import type { AppConfig } from "../config.js";
import type { ScopeRecord, Store } from "../store/types.js";
import { isPublicAddress } from "../verification/netguard.js";
import { AWS_READ_ONLY_SESSION_POLICY, WELL_KNOWN_PATH, type Verifier } from "../verification/verifiers.js";
import { requestContext } from "./context.js";

/** Engines that make sense for each scope type; also the defaults. */
const ENGINES_BY_TYPE: Record<ScopeType, readonly Engine[]> = {
  DOMAIN: ["DISCOVERY", "NETWORK", "TLS", "WEB"],
  IP_RANGE: ["NETWORK", "TLS", "WEB"],
  CLOUD_ACCOUNT: ["CLOUD"],
};

const METHODS_BY_TYPE: Record<ScopeType, readonly VerificationMethod[]> = {
  DOMAIN: ["DNS_TXT", "HTTP_FILE"],
  // Phase 1: single public hosts only, proven by the HTTPS file on that IP.
  IP_RANGE: ["HTTP_FILE"],
  CLOUD_ACCOUNT: ["CLOUD_ROLE"],
};

const VERIFY_ATTEMPTS_PER_HOUR = 10;

const CreateScopeBody = z.discriminatedUnion("type", [
  z.object({ type: z.literal("DOMAIN"), value: z.string().max(253), allowedEngines: z.array(z.enum(ENGINES)).optional() }),
  z.object({ type: z.literal("IP_RANGE"), value: z.string().max(64), allowedEngines: z.array(z.enum(ENGINES)).optional() }),
  z.object({
    type: z.literal("CLOUD_ACCOUNT"),
    value: z.string().regex(/^aws:\d{12}$/, "must be aws:<12-digit account id>"),
    roleArn: z.string().regex(/^arn:aws:iam::\d{12}:role\/[\w+=,.@\/-]{1,512}$/, "must be an IAM role ARN"),
    allowedEngines: z.array(z.enum(ENGINES)).optional(),
  }),
]);

const VerifyBody = z.object({ method: z.enum(["DNS_TXT", "HTTP_FILE", "CLOUD_ROLE"]) });
const ScopeParams = z.object({ orgId: z.string().uuid(), scopeId: z.string().uuid() });
const AssetsQuery = z.object({ scopeId: z.string().uuid().optional() });

class ScopeValueError extends Error {
  readonly statusCode = 400;
  readonly code = "invalid_scope_value";
}

/** Validates and canonicalizes a scope value. Throws ScopeValueError. */
function canonicalValue(body: z.infer<typeof CreateScopeBody>): string {
  switch (body.type) {
    case "DOMAIN": {
      const d = normalizeDomain(body.value);
      if (!d) throw new ScopeValueError("value must be a plain hostname like example.com (no wildcards, IPs or URLs)");
      return d;
    }
    case "IP_RANGE": {
      const c = parseCidr(body.value);
      if (!c) throw new ScopeValueError("value must be an IP address or CIDR");
      if (c.prefix !== (c.family === "ipv4" ? 32 : 128)) {
        throw new ScopeValueError("only single-host IP scopes (/32 or /128) can be self-verified for now");
      }
      if (!isPublicAddress(c.address)) throw new ScopeValueError("private, loopback and reserved addresses can't be scoped");
      return `${c.address}/${c.prefix}`;
    }
    case "CLOUD_ACCOUNT": {
      const account = body.value.slice(4);
      if (!body.roleArn.startsWith(`arn:aws:iam::${account}:role/`)) {
        throw new ScopeValueError("roleArn must belong to the same AWS account as the scope");
      }
      return body.value;
    }
  }
}

/** The asset a verified scope seeds: its own apex / host / account. */
function seedAsset(scope: ScopeRecord): { kind: AssetKind; address: string } {
  switch (scope.type) {
    case "DOMAIN":
      return { kind: "DOMAIN", address: scope.value };
    case "IP_RANGE":
      return { kind: "IP", address: scope.value.split("/")[0]! };
    case "CLOUD_ACCOUNT":
      return { kind: "CLOUD_RESOURCE", address: scope.value };
  }
}

function verificationHost(scope: ScopeRecord): string {
  return scope.type === "IP_RANGE" ? scope.value.split("/")[0]! : scope.value;
}

export function effectiveStatus(scope: ScopeRecord, now = new Date()) {
  if (scope.status === "VERIFIED" && (!scope.expiresAt || scope.expiresAt <= now)) return "EXPIRED";
  return scope.status;
}

function instructions(scope: ScopeRecord, config: AppConfig) {
  const token = scope.verificationToken!;
  const host = verificationHost(scope);
  switch (scope.type) {
    case "DOMAIN":
      return {
        DNS_TXT: { recordType: "TXT", name: host, value: token },
        HTTP_FILE: { url: `https://${host}${WELL_KNOWN_PATH}`, content: token },
      };
    case "IP_RANGE":
      return { HTTP_FILE: { url: `https://${host}${WELL_KNOWN_PATH}`, content: token } };
    case "CLOUD_ACCOUNT":
      return {
        CLOUD_ROLE: {
          roleArn: scope.cloudRoleArn,
          externalId: scope.externalId,
          trustedPrincipal: config.awsTrustPrincipalArn ?? "(set AWS_TRUST_PRINCIPAL_ARN on the platform)",
          requiredPolicy: AWS_READ_ONLY_SESSION_POLICY,
          note: "Grant read-only access only. Aegis also caps every session with this read-only policy.",
        },
      };
  }
}

function scopeDto(scope: ScopeRecord, config: AppConfig) {
  return {
    id: scope.id,
    type: scope.type,
    value: scope.value,
    status: effectiveStatus(scope),
    verificationMethod: scope.verificationMethod,
    verifiedAt: scope.verifiedAt,
    expiresAt: scope.expiresAt,
    revokedAt: scope.revokedAt,
    allowedEngines: scope.allowedEngines,
    maxRequestsPerSec: scope.maxRequestsPerSec,
    lastVerificationAt: scope.lastVerificationAt,
    lastVerificationError: scope.lastVerificationError,
    createdAt: scope.createdAt,
    verification: scope.status === "REVOKED" ? null : instructions(scope, config),
  };
}

export async function scopeRoutes(
  app: FastifyInstance,
  opts: { config: AppConfig; store: Store; limiter: RateLimiter; verifier: Verifier },
) {
  const { config, store, limiter, verifier } = opts;

  app.post(
    "/orgs/:orgId/scopes",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const body = CreateScopeBody.parse(req.body);
      const member = req.membership!;
      const value = canonicalValue(body);
      const compatible = ENGINES_BY_TYPE[body.type];
      const allowedEngines = body.allowedEngines ? [...new Set(body.allowedEngines)] : [...compatible];
      const bad = allowedEngines.filter((e) => !compatible.includes(e));
      if (bad.length || allowedEngines.length === 0) {
        return reply.code(400).send({ error: "invalid_engines", message: `allowed for ${body.type}: ${compatible.join(", ")}` });
      }

      const scope = await store.transaction(async (tx) => {
        const created = await tx.scopes.create({
          orgId: member.orgId,
          type: body.type,
          value,
          allowedEngines,
          verificationToken: `aegis-verify=${randomBytes(24).toString("base64url")}`,
          cloudRoleArn: body.type === "CLOUD_ACCOUNT" ? body.roleArn : null,
          externalId: body.type === "CLOUD_ACCOUNT" ? `aegis-${randomUUID()}` : null,
          createdById: member.userId,
        });
        await createAuditLogger(tx.audit).record({
          action: "scope.create",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          scopeId: created.id,
          targetId: created.id,
          payload: { type: created.type, value: created.value, allowedEngines },
          ...requestContext(req),
        });
        return created;
      });
      return reply.code(201).send({ scope: scopeDto(scope, config) });
    },
  );

  app.get(
    "/orgs/:orgId/scopes",
    { preHandler: [app.authenticate, app.requirePermission("scope.read")] },
    async (req) => ({ scopes: (await store.scopes.listByOrg(req.membership!.orgId)).map((s) => scopeDto(s, config)) }),
  );

  app.get(
    "/orgs/:orgId/scopes/:scopeId",
    { preHandler: [app.authenticate, app.requirePermission("scope.read")] },
    async (req, reply) => {
      const { scopeId } = ScopeParams.parse(req.params);
      const scope = await store.scopes.find(req.membership!.orgId, scopeId);
      if (!scope) return reply.code(404).send({ error: "not_found" });
      return { scope: scopeDto(scope, config) };
    },
  );

  app.post(
    "/orgs/:orgId/scopes/:scopeId/verify",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const { scopeId } = ScopeParams.parse(req.params);
      const { method } = VerifyBody.parse(req.body);
      const member = req.membership!;
      const scope = await store.scopes.find(member.orgId, scopeId);
      if (!scope) return reply.code(404).send({ error: "not_found" });
      if (scope.status === "REVOKED") return reply.code(409).send({ error: "scope_revoked" });
      if (!METHODS_BY_TYPE[scope.type].includes(method)) {
        return reply.code(400).send({ error: "method_not_supported", allowed: METHODS_BY_TYPE[scope.type] });
      }
      // Verification makes outbound DNS/HTTP/STS calls; cap them so the
      // platform can't be used to hammer a host.
      const rl = await limiter.hit(`verify:scope:${scope.id}`, VERIFY_ATTEMPTS_PER_HOUR, 3_600_000);
      if (!rl.allowed) {
        reply.header("retry-after", Math.ceil(rl.retryAfterMs / 1000));
        return reply.code(429).send({ error: "throttled", retryAfterMs: rl.retryAfterMs });
      }

      const result = await verifier.verify({
        method,
        host: verificationHost(scope),
        token: scope.verificationToken!,
        cloudRoleArn: scope.cloudRoleArn,
        externalId: scope.externalId,
      });
      const now = new Date();
      const actor = { type: "user" as const, id: member.userId };
      const ctx = requestContext(req);

      if (!result.ok) {
        await store.transaction(async (tx) => {
          await tx.scopes.recordVerificationFailure(scope.id, now, result.reason);
          await createAuditLogger(tx.audit).record({
            action: "scope.verify_failed",
            actor,
            orgId: member.orgId,
            scopeId: scope.id,
            payload: { method, reason: result.reason },
            ...ctx,
          });
        });
        return reply.code(422).send({ error: "verification_failed", reason: result.reason });
      }

      const expiresAt = new Date(now.getTime() + config.scopeVerificationTtlDays * 86_400_000);
      const verified = await store.transaction(async (tx) => {
        const updated = await tx.scopes.markVerified(scope.id, { method, at: now, expiresAt });
        const seed = seedAsset(updated);
        const asset = await tx.assets.upsert({ scopeId: updated.id, ...seed, at: now });
        await createAuditLogger(tx.audit).record({
          action: "scope.verify",
          actor,
          orgId: member.orgId,
          scopeId: updated.id,
          targetId: asset.id,
          payload: { method, expiresAt: expiresAt.toISOString(), ...(result.detail ?? {}) },
          ...ctx,
        });
        return updated;
      });
      return { scope: scopeDto(verified, config) };
    },
  );

  app.post(
    "/orgs/:orgId/scopes/:scopeId/revoke",
    { preHandler: [app.authenticate, app.requirePermission("scope.manage")] },
    async (req, reply) => {
      const { scopeId } = ScopeParams.parse(req.params);
      const member = req.membership!;
      const scope = await store.scopes.find(member.orgId, scopeId);
      if (!scope) return reply.code(404).send({ error: "not_found" });
      if (scope.status === "REVOKED") return reply.code(409).send({ error: "scope_revoked" });
      const now = new Date();
      const killed = await store.transaction(async (tx) => {
        await tx.scopes.revoke(scope.id, now);
        const n = await tx.scans.killActive({ orgId: member.orgId, scopeId: scope.id }, member.userId, now);
        await createAuditLogger(tx.audit).record({
          action: "scope.revoke",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          scopeId: scope.id,
          payload: { killedScans: n },
          ...requestContext(req),
        });
        return n;
      });
      return { scopeId: scope.id, status: "REVOKED", killedScans: killed };
    },
  );

  app.get(
    "/orgs/:orgId/assets",
    { preHandler: [app.authenticate, app.requirePermission("scope.read")] },
    async (req) => {
      const { scopeId } = AssetsQuery.parse(req.query);
      return { assets: await store.assets.listByOrg(req.membership!.orgId, scopeId) };
    },
  );
}
