import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runTool } from "@aegis/worker-kit";
import type { AwsCredentials } from "./aws.js";
import { parseProwlerOcsf, type CloudFinding } from "./ocsf.js";

/**
 * Runs prowler against one AWS account with temporary read-only credentials and
 * returns the FAILed checks. prowler is invoked non-interactively, failures
 * only, OCSF JSON to a temp dir we then read and delete.
 *
 * Non-destructive by construction: the credentials are capped by the
 * SecurityAudit session policy (see aws.ts), and we pass `--status FAIL` so
 * prowler only reports, never remediates. prowler's own `--fixer`/`--remediate`
 * flags are never passed.
 */
export async function runProwler(
  creds: AwsCredentials,
  accountId: string,
  signal: AbortSignal,
  bin = process.env.PROWLER_BIN ?? "prowler",
  timeoutMs = Number(process.env.PROWLER_JOB_TIMEOUT_MS ?? 15 * 60_000),
): Promise<CloudFinding[]> {
  const dir = await mkdtemp(join(tmpdir(), "aegis-prowler-"));
  try {
    const result = await runTool({
      bin,
      args: [
        "aws",
        "--status",
        "FAIL",
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        dir,
        "--output-filename",
        "scan",
        "--no-banner",
      ],
      timeoutMs,
      signal,
      // Only the ephemeral assumed-role credentials reach prowler — no platform
      // secrets (runTool's base env is a minimal safe allow-list).
      extraEnv: {
        AWS_ACCESS_KEY_ID: creds.accessKeyId,
        AWS_SECRET_ACCESS_KEY: creds.secretAccessKey,
        AWS_SESSION_TOKEN: creds.sessionToken,
        AWS_DEFAULT_REGION: creds.region,
        AWS_REGION: creds.region,
      },
    });

    const file = await findOcsfFile(dir);
    if (!file) {
      // prowler exits non-zero when any check fails, which is normal for us, so
      // a missing output file (not the exit code) is what signals real trouble.
      throw new Error(`prowler produced no OCSF output (exit ${result.exitCode}): ${result.stderr.slice(0, 500)}`);
    }
    const json: unknown = JSON.parse(await readFile(file, "utf8"));
    const findings = parseProwlerOcsf(json);
    // Guard against a role pointed at the wrong account: keep only this account.
    return findings.filter((f) => !f.accountUid || f.accountUid === accountId);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

async function findOcsfFile(dir: string): Promise<string | null> {
  const entries = await readdir(dir).catch(() => [] as string[]);
  const match = entries.find((e) => e.endsWith(".ocsf.json")) ?? entries.find((e) => e.endsWith(".json"));
  return match ? join(dir, match) : null;
}
