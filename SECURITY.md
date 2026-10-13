# Security policy

Aegis is a defensive security product, so we hold its own security to a high bar.

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do not open a public issue.

- Email the maintainers (see the repository owner's contact), or use GitHub's
  **Security → Report a vulnerability** (private advisory) on this repo.
- Include steps to reproduce, affected version/commit, and impact.
- We aim to acknowledge within a few days and to agree a disclosure timeline.

Please do not run tests against infrastructure you don't own or aren't
authorized to test — that's exactly what this product exists to prevent.

## Scope and design notes for reviewers

The security-critical core is the **Scope Authorization Gate**
(`packages/core/src/scopeGate.ts`): every scan path, manual or scheduled, goes
through it, and it fails closed. See `docs/SCOPE_AUTHORIZATION.md`.

Properties the codebase enforces, with tests:

- **Authorization-first.** Scans only ever target a stored asset under a
  same-org, verified, unexpired scope; the engine must be allowed; the
  kill-switch and approval workflow are honoured. Workers re-check the gate at
  job start and on a heartbeat.
- **Non-destructive.** Engines identify exposure only — no exploitation, brute
  force, payloads, or persistence. Tool flags are pinned and asserted at image
  build.
- **SSRF-guarded egress.** Ownership verification, report webhooks, and alert
  channels refuse private, loopback, link-local and cloud-metadata addresses.
- **Untrusted scan data.** Evidence and the AI advisory layer treat
  scanned-system output as data, never instructions; AI output is advisory and
  never becomes a command or a scan target.
- **Append-only audit.** Every scope change, verification, scan decision,
  kill-switch, report and alert is recorded; a Postgres trigger blocks
  UPDATE/DELETE on the audit table.
- **Secrets.** Passwords use argon2id; refresh tokens rotate with reuse
  detection; opaque tokens are stored as HMACs; secrets are redacted from audit
  payloads and logs; scan workers never receive JWT/AI/SMTP keys.

## Known accepted risks

- Next.js bundles a version of PostCSS with build-time advisories
  (`GHSA-6g55-p6wh-862q` and related). They require attacker-controlled CSS at
  build time; Aegis only builds its own CSS, so this is not runtime-exploitable.
  It clears when we move to Next 16.
