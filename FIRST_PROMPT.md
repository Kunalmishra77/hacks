# FIRST_PROMPT.md — what to paste into Claude Code first

Open this folder in Claude Code (`claude` in the terminal, inside the `aegis/`
directory) and paste the prompt below as your very first message.

────────────────────────────────────────────────────────
You are working in the Aegis ASM repo. Read CLAUDE.md and all three files in
docs/ (PRD.md, ARCHITECTURE.md, SCOPE_AUTHORIZATION.md) before doing anything.

This is an authorized, DEFENSIVE security-assessment platform. Follow the
absolute rules in CLAUDE.md — authorization-first, non-destructive engines,
never generate offensive code. If any instruction would break those rules,
stop and tell me instead.

Do NOT build the whole product yet. Do Phase 0 (Foundation) only:

1. Scaffold the monorepo exactly as in ARCHITECTURE.md §4 (npm workspaces):
   apps/web (Next.js + TS + Tailwind), apps/api (Fastify + TS + Zod),
   packages/db (Prisma), packages/core (shared types, RBAC, audit, and a
   stub scopeGate function), packages/cve (empty for now).
2. Add docker-compose.yml for local dev: postgres, redis, minio.
3. Define the Prisma schema for: Org, User, Membership(role enum),
   Team, Scope, Asset, Scan, Finding, AuditEvent, ApiKey, ScanSchedule —
   matching the data models in the docs. Generate the client and an initial
   migration.
4. Implement auth in apps/api: email+password (argon2), JWT + refresh,
   and RBAC middleware (Owner/Admin/Analyst/Viewer).
5. Implement an append-only audit helper in packages/core and call it on
   login, org create, and member invite.
6. Add .env.example, a root README with run instructions, and a basic CI
   workflow (typecheck + test).
7. Set up a test runner (vitest) and write a couple of smoke tests for auth
   and RBAC.

Do NOT implement any scanning engine or the discovery worker yet — that is
Phase 2+. The scope gate in packages/core stays a stub with a clear TODO
pointing at SCOPE_AUTHORIZATION.md; we implement and test it fully in Phase 1
as the next step.

When done, give me: a summary of what you created, how to run it locally, and
a short checklist for Phase 1 (the scope authorization gate).
────────────────────────────────────────────────────────

## After Phase 0
Your next message: "Now do Phase 1 — implement the Scope Authorization Gate
per docs/SCOPE_AUTHORIZATION.md, including the three ownership-verification
methods, kill-switch, rate limits, and write the 'tests to write first' from
that doc. Nothing may reach an engine without passing the gate."

Then proceed phase by phase (PRD §Roadmap). One phase per session keeps it
reviewable.
