import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createAuditLogger, type RateLimiter } from "@aegis/core";
import { adviseFinding, createProvider, type AdviceFinding, type AiProvider } from "@aegis/ai";
import type { AppConfig } from "../config.js";
import type { FindingRecord, Store } from "../store/types.js";
import { requestContext } from "./context.js";

// AI advisory (Phase 7). Advisory ONLY: this endpoint returns text for a human
// to review. It never starts a scan, picks a target, or acts on model output.
// Costs money per call, so it's Analyst+ and rate-limited, and the result is
// cached on the finding (re-viewing doesn't re-bill; ?refresh=1 regenerates).

const Params = z.object({ orgId: z.string().uuid(), findingId: z.string().uuid() });
const Query = z.object({ refresh: z.coerce.boolean().optional() });

const AI_CALLS_PER_ORG_PER_HOUR = 60;

function toAdviceFinding(f: FindingRecord & { assetAddress: string }): AdviceFinding {
  return {
    type: f.type,
    severity: f.severity,
    title: f.title,
    assetAddress: f.assetAddress,
    cveRefs: f.cveRefs,
    cvss: f.cvss,
    epss: f.epss,
    kevListed: f.kevListed,
    riskScore: f.riskScore,
    remediation: f.remediation,
    evidence: (f.evidence as Record<string, unknown> | null) ?? null,
  };
}

export async function aiRoutes(
  app: FastifyInstance,
  opts: { config: AppConfig; store: Store; limiter: RateLimiter; aiProvider?: AiProvider },
) {
  const { config, store, limiter } = opts;
  const provider: AiProvider | null = opts.aiProvider ?? (config.ai ? createProvider(config.ai) : null);

  app.post(
    "/orgs/:orgId/findings/:findingId/advise",
    { preHandler: [app.authenticate, app.requirePermission("finding.triage")] },
    async (req, reply) => {
      if (!provider) return reply.code(501).send({ error: "ai_not_configured", message: "Set AI_PROVIDER and the matching API key to enable AI advice." });
      const { findingId } = Params.parse(req.params);
      const { refresh } = Query.parse(req.query);
      const member = req.membership!;

      const existing = await store.findings.find(member.orgId, findingId);
      if (!existing) return reply.code(404).send({ error: "not_found" });

      // Return the cached advice unless a refresh was asked for.
      if (!refresh && existing.aiAdvice) {
        return { advice: existing.aiAdvice, model: existing.aiModel, generatedAt: existing.aiAdviceAt, cached: true };
      }

      const rl = await limiter.hit(`ai:org:${member.orgId}`, AI_CALLS_PER_ORG_PER_HOUR, 3_600_000);
      if (!rl.allowed) {
        reply.header("retry-after", Math.ceil(rl.retryAfterMs / 1000));
        return reply.code(429).send({ error: "throttled", retryAfterMs: rl.retryAfterMs });
      }

      let advice;
      try {
        advice = await adviseFinding(provider, toAdviceFinding(existing as FindingRecord & { assetAddress: string }));
      } catch (e) {
        req.log.warn({ error: (e as Error).message }, "ai advise failed");
        return reply.code(502).send({ error: "ai_unavailable", message: "The AI provider could not be reached." });
      }

      const at = new Date();
      await store.transaction(async (tx) => {
        await tx.findings.setAiAdvice(member.orgId, findingId, advice as unknown as Record<string, unknown>, advice.model, at);
        await createAuditLogger(tx.audit).record({
          action: "finding.ai_advised",
          actor: { type: "user", id: member.userId },
          orgId: member.orgId,
          targetId: findingId,
          // Record that advice was generated and by which model — not the advice text.
          payload: { provider: advice.provider, model: advice.model, type: existing.type },
          ...requestContext(req),
        });
      });
      return { advice, model: advice.model, generatedAt: at, cached: false };
    },
  );
}
