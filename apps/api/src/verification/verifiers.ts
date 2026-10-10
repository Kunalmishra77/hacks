import { Resolver } from "node:dns/promises";
import https from "node:https";
import { isIP } from "node:net";
import { AssumeRoleCommand, GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { VerificationMethod } from "@aegis/core";
import { guardedLookup, isPublicAddress } from "./netguard.js";

// Ownership verification (docs/SCOPE_AUTHORIZATION.md, "Ownership
// verification methods"). Each verifier only proves control; none of them
// probes, scans, or changes anything on the customer's side.

export const WELL_KNOWN_PATH = "/.well-known/aegis-verify.txt";
/** Read-only AWS managed policy used as a session policy cap on every assumed role. */
export const AWS_READ_ONLY_SESSION_POLICY = "arn:aws:iam::aws:policy/SecurityAudit";

export type VerificationResult = { ok: true; detail?: Record<string, string> } | { ok: false; reason: string };

export interface VerificationTarget {
  method: VerificationMethod;
  /** Hostname (DOMAIN), IP literal (single-host IP_RANGE), or aws:<account> (CLOUD_ACCOUNT). */
  host: string;
  token: string;
  cloudRoleArn?: string | null;
  externalId?: string | null;
}

export interface VerificationDeps {
  resolveTxt(name: string): Promise<string[][]>;
  /** Fetches the well-known file over HTTPS and returns its body (capped). */
  fetchWellKnown(host: string): Promise<string>;
  /** Assumes the role with the external ID and returns the AWS account it belongs to. */
  assumeRoleAccount(roleArn: string, externalId: string): Promise<string>;
}

export interface Verifier {
  verify(target: VerificationTarget): Promise<VerificationResult>;
}

export function createVerifier(deps: VerificationDeps): Verifier {
  return {
    async verify(t) {
      try {
        switch (t.method) {
          case "DNS_TXT": {
            let records: string[][];
            try {
              records = await deps.resolveTxt(t.host);
            } catch (e) {
              const code = (e as NodeJS.ErrnoException).code;
              if (code === "ENODATA" || code === "ENOTFOUND") return { ok: false, reason: "TXT record not found" };
              throw e;
            }
            // TXT records can be split into 255-byte chunks; join each record.
            const found = records.some((chunks) => chunks.join("").trim() === t.token);
            return found ? { ok: true } : { ok: false, reason: "TXT record with the verification token not found" };
          }
          case "HTTP_FILE": {
            const body = await deps.fetchWellKnown(t.host);
            const found = body.split(/\r?\n/).some((line) => line.trim() === t.token);
            return found ? { ok: true } : { ok: false, reason: `token not found at https://${t.host}${WELL_KNOWN_PATH}` };
          }
          case "CLOUD_ROLE": {
            if (!t.cloudRoleArn || !t.externalId) return { ok: false, reason: "scope has no role ARN / external ID" };
            const expected = /^aws:(\d{12})$/.exec(t.host)?.[1];
            const account = await deps.assumeRoleAccount(t.cloudRoleArn, t.externalId);
            return account === expected
              ? { ok: true, detail: { account } }
              : { ok: false, reason: "assumed role belongs to a different AWS account" };
          }
        }
      } catch (e) {
        return { ok: false, reason: (e as Error).message.slice(0, 300) };
      }
    },
  };
}

// ── Default (real network) implementations ──────────────────────────

const MAX_BODY_BYTES = 4096;
const TIMEOUT_MS = 5000;

/** Uses public resolvers so internal split-horizon DNS can't answer for customer domains. */
export function publicResolveTxt(name: string): Promise<string[][]> {
  const r = new Resolver({ timeout: TIMEOUT_MS, tries: 2 });
  r.setServers(["1.1.1.1", "8.8.8.8"]);
  return r.resolveTxt(name);
}

/**
 * GET https://<host>/.well-known/aegis-verify.txt with: TLS validation on,
 * no redirects, a 5s timeout, a 4 KiB body cap, and only public IPs.
 */
export function fetchWellKnown(host: string): Promise<string> {
  if (isIP(host) && !isPublicAddress(host)) return Promise.reject(new Error("non-public address"));
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host,
        path: WELL_KNOWN_PATH,
        method: "GET",
        lookup: guardedLookup,
        servername: isIP(host) ? undefined : host,
        timeout: TIMEOUT_MS,
        headers: { "user-agent": "AegisVerify/1.0 (ownership verification)", accept: "text/plain" },
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} (redirects are not followed)`));
        }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > MAX_BODY_BYTES) {
            req.destroy(new Error("verification file too large"));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    req.end();
  });
}

/**
 * Assumes the customer's role with our external ID, capped by a read-only
 * session policy (SecurityAudit) so even an over-privileged role can only be
 * used read-only, then asks STS which account it is in. Platform AWS
 * credentials come from the default provider chain (env / instance role).
 */
export async function awsAssumeRoleAccount(roleArn: string, externalId: string): Promise<string> {
  const sts = new STSClient({ region: process.env.AWS_REGION ?? "us-east-1" });
  const { Credentials } = await sts.send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      ExternalId: externalId,
      RoleSessionName: "aegis-ownership-verify",
      DurationSeconds: 900,
      PolicyArns: [{ arn: AWS_READ_ONLY_SESSION_POLICY }],
    }),
  );
  if (!Credentials?.AccessKeyId || !Credentials.SecretAccessKey) throw new Error("AssumeRole returned no credentials");
  const assumed = new STSClient({
    region: process.env.AWS_REGION ?? "us-east-1",
    credentials: {
      accessKeyId: Credentials.AccessKeyId,
      secretAccessKey: Credentials.SecretAccessKey,
      sessionToken: Credentials.SessionToken,
    },
  });
  const id = await assumed.send(new GetCallerIdentityCommand({}));
  if (!id.Account) throw new Error("GetCallerIdentity returned no account");
  return id.Account;
}

export const defaultVerificationDeps: VerificationDeps = {
  resolveTxt: publicResolveTxt,
  fetchWellKnown,
  assumeRoleAccount: awsAssumeRoleAccount,
};
