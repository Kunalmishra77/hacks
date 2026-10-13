import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";

/**
 * Caps the assumed session to read-only, no matter how broad the customer's
 * role is. Same policy the ownership verifier uses
 * (apps/api/src/verification/verifiers.ts: AWS_READ_ONLY_SESSION_POLICY).
 */
export const AWS_READ_ONLY_SESSION_POLICY = "arn:aws:iam::aws:policy/SecurityAudit";

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  region: string;
}

/**
 * Assumes the customer's role with our external ID and the SecurityAudit
 * session policy, returning temporary read-only credentials. Even if the role
 * grants more, the session policy means the scan can only *read* the account —
 * it cannot change, create, or delete anything (CLAUDE.md rule 2).
 *
 * Platform AWS credentials (to call STS) come from the default provider chain
 * (env / instance role). The returned creds are ephemeral and go only to the
 * prowler subprocess for this one scan.
 */
export async function assumeReadOnlyRole(
  roleArn: string,
  externalId: string,
  signal?: AbortSignal,
): Promise<AwsCredentials> {
  const region = process.env.AWS_REGION ?? "us-east-1";
  const sts = new STSClient({ region });
  const { Credentials } = await sts.send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      ExternalId: externalId,
      RoleSessionName: "aegis-cloud-scan",
      // STS caps a session-policy'd assume-role at 1 hour; prowler finishes well
      // within that for a single account.
      DurationSeconds: 3600,
      PolicyArns: [{ arn: AWS_READ_ONLY_SESSION_POLICY }],
    }),
    { abortSignal: signal },
  );
  if (!Credentials?.AccessKeyId || !Credentials.SecretAccessKey || !Credentials.SessionToken) {
    throw new Error("AssumeRole returned no credentials");
  }
  return {
    accessKeyId: Credentials.AccessKeyId,
    secretAccessKey: Credentials.SecretAccessKey,
    sessionToken: Credentials.SessionToken,
    region,
  };
}
