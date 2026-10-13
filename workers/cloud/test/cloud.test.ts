import { describe, expect, it } from "vitest";
import type { AuthorizedTarget, FindingDraft } from "@aegis/core";
import type { EngineContext } from "@aegis/worker-kit";
import { parseProwlerOcsf } from "../src/ocsf.js";
import { createCloudEngine, type CloudDeps } from "../src/engine.js";

// A trimmed sample of prowler's `--output-formats json-ocsf` output: one FAIL,
// one PASS, one MANUAL. Only the FAIL should survive.
const OCSF = [
  {
    status_code: "FAIL",
    severity: "High",
    finding_info: { uid: "prowler-aws-s3_bucket_public_access-123", title: "S3 bucket is publicly accessible" },
    metadata: { event_code: "s3_bucket_public_access" },
    resources: [{ uid: "arn:aws:s3:::my-bucket", name: "my-bucket", type: "AwsS3Bucket", region: "us-east-1" }],
    remediation: { desc: "Block public access on the bucket." },
    cloud: { account: { uid: "123456789012" }, region: "us-east-1" },
  },
  {
    status_code: "PASS",
    severity: "High",
    finding_info: { uid: "prowler-aws-iam_root_mfa-1", title: "Root account has MFA" },
    metadata: { event_code: "iam_root_mfa_enabled" },
    resources: [{ uid: "arn:aws:iam::123456789012:root", name: "root", type: "AwsIamUser", region: "us-east-1" }],
    cloud: { account: { uid: "123456789012" } },
  },
  {
    status_code: "MANUAL",
    severity: "Medium",
    finding_info: { uid: "prowler-aws-manual-1", title: "Review something by hand" },
    metadata: { event_code: "some_manual_check" },
    resources: [{ uid: "arn:aws:iam::123456789012:policy/x", name: "x", type: "AwsIamPolicy", region: "us-east-1" }],
    cloud: { account: { uid: "123456789012" } },
  },
];

describe("parseProwlerOcsf", () => {
  it("keeps only FAILs and maps the fields Aegis records", () => {
    const findings = parseProwlerOcsf(OCSF);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual({
      checkId: "s3_bucket_public_access",
      title: "S3 bucket is publicly accessible",
      severity: "HIGH",
      resourceUid: "arn:aws:s3:::my-bucket",
      resourceName: "my-bucket",
      resourceType: "AwsS3Bucket",
      region: "us-east-1",
      remediation: "Block public access on the bucket.",
      accountUid: "123456789012",
    });
  });

  it("maps prowler severities to Aegis severities, defaulting unknown to INFO", () => {
    const sev = (s: string) =>
      parseProwlerOcsf([
        { status_code: "FAIL", severity: s, metadata: { event_code: "c" }, finding_info: { title: "t" }, resources: [{ uid: "r" }], cloud: {} },
      ])[0]?.severity;
    expect(sev("Critical")).toBe("CRITICAL");
    expect(sev("high")).toBe("HIGH");
    expect(sev("Medium")).toBe("MEDIUM");
    expect(sev("Low")).toBe("LOW");
    expect(sev("Informational")).toBe("INFO");
    expect(sev("wat")).toBe("INFO");
  });

  it("is defensive about junk, missing fields, and non-array input", () => {
    expect(parseProwlerOcsf(null)).toEqual([]);
    expect(parseProwlerOcsf("nope")).toEqual([]);
    expect(parseProwlerOcsf([null, 1, "x", {}])).toEqual([]);
    // FAIL but no resource to key on → dropped.
    expect(parseProwlerOcsf([{ status_code: "FAIL", metadata: { event_code: "c" } }])).toEqual([]);
    // Falls back to resource name when uid is absent.
    const f = parseProwlerOcsf([{ status_code: "FAIL", metadata: { event_code: "c" }, resources: [{ name: "only-a-name" }] }]);
    expect(f[0]?.resourceUid).toBe("only-a-name");
  });
});

const target: AuthorizedTarget = {
  orgId: "o",
  scopeId: "s",
  scopeType: "CLOUD_ACCOUNT",
  scopeValue: "aws:123456789012",
  assetId: "a",
  kind: "CLOUD_RESOURCE",
  address: "aws:123456789012",
  engine: "CLOUD",
  maxRequestsPerSec: 10,
};

function ctxFor(t: AuthorizedTarget) {
  const findings: FindingDraft[] = [];
  const ctx: EngineContext = {
    target: t,
    signal: new AbortController().signal,
    log: () => {},
    async emitAsset() {
      return null;
    },
    async emitFinding(f) {
      findings.push(f);
      return true;
    },
  };
  return { ctx, findings };
}

describe("cloud engine", () => {
  it("passes the account to prowler and emits one finding per FAIL, keyed by resource", async () => {
    const seen: { scopeId: string; accountId: string }[] = [];
    const deps: CloudDeps = {
      async scanAccount({ scopeId, accountId }) {
        seen.push({ scopeId, accountId });
        return parseProwlerOcsf(OCSF);
      },
    };
    const { ctx, findings } = ctxFor(target);
    await createCloudEngine(deps).run(ctx);

    expect(seen).toEqual([{ scopeId: "s", accountId: "123456789012" }]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.type).toBe("cloud.s3_bucket_public_access");
    expect(f.key).toBe("arn:aws:s3:::my-bucket");
    expect(f.severity).toBe("HIGH");
    expect(f.evidence).toMatchObject({ check: "s3_bucket_public_access", resource: "arn:aws:s3:::my-bucket", region: "us-east-1", account: "123456789012" });
  });

  it("supplies a remediation fallback when prowler gives none", async () => {
    const deps: CloudDeps = {
      async scanAccount() {
        return [{ checkId: "c", title: "t", severity: "LOW", resourceUid: "r", resourceName: "", resourceType: "", region: "", remediation: "", accountUid: "123456789012" }];
      },
    };
    const { ctx, findings } = ctxFor(target);
    await createCloudEngine(deps).run(ctx);
    expect(findings[0]!.remediation).toMatch(/prowler check documentation/);
  });

  it("does nothing for a non-cloud asset or a non-AWS scope value", async () => {
    let called = false;
    const deps: CloudDeps = {
      async scanAccount() {
        called = true;
        return [];
      },
    };
    const wrongKind = ctxFor({ ...target, kind: "DOMAIN", address: "example.com" });
    await createCloudEngine(deps).run(wrongKind.ctx);
    const wrongScope = ctxFor({ ...target, scopeValue: "aws:not-an-account" });
    await createCloudEngine(deps).run(wrongScope.ctx);
    expect(called).toBe(false);
    expect(wrongKind.findings).toEqual([]);
    expect(wrongScope.findings).toEqual([]);
  });
});
