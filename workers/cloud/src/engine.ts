import { parseAwsAccountScope, type FindingDraft } from "@aegis/core";
import type { EngineContext, EngineImpl } from "@aegis/worker-kit";
import type { CloudFinding } from "./ocsf.js";

/**
 * CLOUD engine (PRD §7 "Cloud posture"): read-only configuration assessment of
 * a customer's AWS account via prowler. Admin-approved (the gate requires it)
 * and strictly non-destructive — prowler only *reads* the account through an
 * assumed role capped by the SecurityAudit session policy. It never changes,
 * creates, or deletes anything in the account.
 *
 * `scanAccount` is injected: in production it assumes the scope's read-only
 * role, runs prowler, and parses the OCSF output; tests pass findings directly.
 */
export interface CloudDeps {
  scanAccount(input: { scopeId: string; accountId: string; signal: AbortSignal }): Promise<CloudFinding[]>;
}

export function createCloudEngine(deps: CloudDeps): EngineImpl {
  return {
    engine: "CLOUD",
    async run(ctx: EngineContext) {
      const { target, signal } = ctx;
      if (target.kind !== "CLOUD_RESOURCE") {
        ctx.log("cloud scan doesn't apply to this asset kind", { kind: target.kind });
        return;
      }
      const accountId = parseAwsAccountScope(target.scopeValue);
      if (!accountId) {
        ctx.log("scope is not an AWS account", { scopeValue: target.scopeValue });
        return;
      }

      const findings = await deps.scanAccount({ scopeId: target.scopeId, accountId, signal });
      if (signal.aborted) throw signal.reason;
      ctx.log("prowler finished", { account: accountId, failures: findings.length });

      for (const f of findings) {
        if (signal.aborted) throw signal.reason;
        const where = [f.resourceType, f.region].filter(Boolean).join(" · ");
        const draft: FindingDraft = {
          // Findings attach to the account asset; the specific resource lives in
          // the key (for dedupe) and evidence. A resource ARN wouldn't always
          // match the account-scope shape the gate enforces for emitted assets.
          type: `cloud.${f.checkId}`,
          key: f.resourceUid,
          severity: f.severity,
          title: f.title,
          remediation: f.remediation || "See the prowler check documentation for remediation guidance.",
          evidence: {
            check: f.checkId,
            resource: f.resourceUid,
            resourceName: f.resourceName || undefined,
            resourceType: f.resourceType || undefined,
            region: f.region || undefined,
            account: f.accountUid || accountId,
            ...(where ? { location: where } : {}),
          },
        };
        await ctx.emitFinding(draft);
      }
    },
  };
}
