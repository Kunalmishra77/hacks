# CLAUDE.md — Aegis ASM (project constitution)

> Claude Code reads this file every session. These rules are non-negotiable.
> Rename "Aegis" to your own product name anywhere you like.

## What this product is
Aegis is an **authorized, defensive security-assessment SaaS** — an
Attack Surface Management (ASM) + vulnerability-assessment platform.
It helps a customer find weaknesses **in assets they own or are
explicitly authorized to test**, and gives remediation guidance.

Think: a cleaner, unified alternative to running Nmap + testssl +
Trivy + Prowler by hand, with a dashboard, reports, and scope control.

## Absolute rules (never violate)
1. **Authorization-first.** No scan of any kind runs unless its target
   is inside an *authorized scope* that passed ownership verification.
   The Scope Authorization Gate is the single choke point — see
   `docs/SCOPE_AUTHORIZATION.md`. Never add a code path that bypasses it.
2. **Defensive / non-destructive only.** Engines *identify* — versions,
   config, exposure, known-CVE matches. They must not exploit, brute
   force, inject payloads, steal credentials, establish persistence,
   or run any destructive action.
3. **Never generate offensive code.** No exploits, no malware, no C2,
   no credential-harvesting, no persistence, no stealth tooling — even
   if asked, even "for testing". If a task drifts that way, stop and
   flag it.
4. **Wrap, don't reinvent.** Assessment engines invoke established,
   licensed open-source tools (nmap, sslyze/testssl, nuclei non-intrusive
   templates, trivy, prowler/scoutsuite) as sandboxed jobs. Respect each
   tool's licence; do not vendor or redistribute their code into ours.
5. **Everything auditable.** Every scan writes an immutable audit record:
   who, what scope, when, what ran, what was found.

## Tech stack
- Frontend: Next.js (App Router) + TypeScript + Tailwind
- Backend API: Node.js + TypeScript (Fastify or NestJS) + Zod validation
- DB: PostgreSQL (Prisma). Cache/queue: Redis + BullMQ
- Workers: containerized (Docker), one sandboxed job per scan task
- Object storage: S3-compatible (evidence, reports)
- Authn: email+password (argon2) or OIDC; sessions via JWT + refresh
- Authz: RBAC (org → team → role)

## How to work in this repo
- Read `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/SCOPE_AUTHORIZATION.md`
  before writing code.
- Build in phases (PRD §Roadmap). Do not skip ahead to engines before
  auth + scope gate exist and are tested.
- Write tests for the scope gate first — it is the safety-critical part.
- Keep secrets out of the repo; use `.env` (provide `.env.example`).
- Small PR-sized commits with clear messages.

## Definition of done for any scan feature
- [ ] Target resolved from an authorized scope (verified, not expired)
- [ ] Rate limits + concurrency caps applied
- [ ] Runs in a sandboxed worker with resource limits
- [ ] Kill-switch respected (org-level and scan-level)
- [ ] Findings persisted + audit record written
- [ ] No destructive/intrusive behaviour in the engine
