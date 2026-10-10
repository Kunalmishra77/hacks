# Aegis ASM

Authorized, **defensive** attack-surface management and vulnerability assessment.
Aegis helps an organization find weaknesses in assets it **owns or is explicitly
authorized to test**, and tells it how to fix them. It never exploits, brute-forces,
or runs destructive actions. See [CLAUDE.md](CLAUDE.md) for the non-negotiable rules
and [docs/](docs/) for the PRD, architecture, and scope-authorization design.

> **Status: Phase 1 (Scope Authorization Gate) done.** Accounts, orgs, roles,
> audit log, scopes with ownership verification, and the gate every scan must
> pass. No scan **engine** exists yet (Phase 2+): an authorized scan is recorded
> as QUEUED and nothing executes it.

## Repository layout

```
apps/
  api/        Fastify + Zod API: auth (argon2id + JWT + rotating refresh), RBAC, orgs, invites
  web/        Next.js (App Router) + Tailwind dashboard (landing + sign-in for now)
packages/
  core/       Shared types, RBAC matrix, append-only audit helper, scope-gate stub
  db/         Prisma schema, migrations, client
  cve/        NVD mirror + version→CVE matching (empty until Phase 3)
docs/         PRD, ARCHITECTURE, SCOPE_AUTHORIZATION, POWER_UP
docker-compose.yml   Optional local Postgres, Redis, MinIO
```

`workers/` and `infra/` arrive with the discovery and engine phases.

## Prerequisites

- Node.js 22 (see `.nvmrc`), npm 10
- A Postgres database: **Supabase** (default, see docs/POWER_UP.md Part B) or the
  local one from `docker compose`

## Setup

```bash
npm install                  # also runs `prisma generate`
cp .env.example .env         # then fill it in (see below)
```

Fill in `.env`:

| Key | Value |
|---|---|
| `DATABASE_URL` | Supabase **transaction pooler** (port 6543) with `?pgbouncer=true&connection_limit=1` |
| `DIRECT_URL` | Supabase **session pooler** or direct host (port 5432); used by migrations |
| `JWT_SECRET`, `JWT_REFRESH_SECRET` | Two different random strings, at least 32 characters each: `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"` |

URL-encode special characters in the database password (`@` → `%40`).

**Local database instead of Supabase:**

```bash
docker compose up -d         # postgres:5432, redis:6379, minio:9000 (console :9001)
# then set both DATABASE_URL and DIRECT_URL to:
# postgresql://aegis:aegis_dev_password@localhost:5432/aegis?schema=public
```

Apply migrations:

```bash
npm run db:deploy            # applies packages/db/prisma/migrations
npm run db:migrate           # dev only: create a new migration after editing schema.prisma
```

## Run

```bash
npm run dev:api              # http://127.0.0.1:4000  (GET /health)
npm run dev:web              # http://localhost:3000
```

Create an account (there's no sign-up page yet):

```bash
curl -s -X POST http://127.0.0.1:4000/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"a-long-passphrase-here","orgName":"My Org"}'
```

Then sign in at http://localhost:3000/login.

## API (Phase 0)

| Method | Path | Who |
|---|---|---|
| POST | `/auth/register` | anyone; creates user (+ org as Owner if `orgName` given) |
| POST | `/auth/login` | anyone; rate-limited; sets httpOnly refresh cookie |
| POST | `/auth/refresh` | refresh cookie; rotates it; reuse revokes the whole session family |
| POST | `/auth/logout` | refresh cookie |
| GET | `/auth/me` | authenticated |
| POST/GET | `/orgs` | authenticated |
| GET | `/orgs/:orgId` | Viewer+ |
| GET | `/orgs/:orgId/members` | Viewer+ |
| POST | `/orgs/:orgId/invites` | Admin+ (only Owners can grant Owner) |
| POST | `/invites/accept` | authenticated user whose email matches the invite |
| POST | `/orgs/:orgId/scopes` | Admin+; returns verification instructions |
| GET | `/orgs/:orgId/scopes`, `/orgs/:orgId/scopes/:scopeId` | Viewer+ |
| POST | `/orgs/:orgId/scopes/:scopeId/verify` | Admin+; `{"method":"DNS_TXT"|"HTTP_FILE"|"CLOUD_ROLE"}`; 10 tries/hour |
| POST | `/orgs/:orgId/scopes/:scopeId/revoke` | Admin+; kills the scope's active scans |
| GET | `/orgs/:orgId/assets` | Viewer+ |
| POST | `/orgs/:orgId/scans` | Analyst+; `{assetId, engine}` → gate → 201 QUEUED / 202 needs approval / 403 / 429 |
| GET | `/orgs/:orgId/scans` | Viewer+ |
| POST | `/orgs/:orgId/scans/:scanId/approve` | Admin+ |
| POST | `/orgs/:orgId/scans/:scanId/kill` | Analyst+ |
| POST | `/orgs/:orgId/kill-switch` | `{engaged:true}` Analyst+, `{engaged:false}` Admin+ |

Non-members of an org get `404` (not `403`) so org ids can't be probed.
Invite tokens are returned in the API response until email delivery lands in Phase 6.

## Scope Authorization Gate

Every scan goes through `authorize()` in [packages/core/src/scopeGate.ts](packages/core/src/scopeGate.ts),
the single choke point from docs/SCOPE_AUTHORIZATION.md. A scan is allowed only if:

1. it targets a stored **Asset** (never a raw hostname/IP), in a **Scope** of the same org;
2. the scope is **VERIFIED** and not past `expiresAt` (90 days), not revoked;
3. the asset's address is actually inside the scope value (apex/subdomain, CIDR, AWS account);
4. the engine is in the scope's `allowedEngines`;
5. neither the org kill-switch nor the scan's own kill is engaged;
6. heavier engines (NETWORK, CLOUD) have an Admin approval;
7. the org is under its concurrent-scan cap and the scope under its scan-start rate (Redis).

Otherwise it is rejected (403), held for approval (202) or throttled (429 + Retry-After).
Every decision is audited. Workers call the same function in `job_start` mode, and it
refuses jobs whose payload doesn't match the scan record (tampered target, asset, engine or org).

**Ownership verification** (proves control; never probes the target):

| Scope type | Methods | Notes |
|---|---|---|
| DOMAIN (`example.com`) | DNS TXT `aegis-verify=…` on the apex, or HTTPS file `/.well-known/aegis-verify.txt` | public resolvers; HTTPS only, no redirects, 4 KiB cap |
| IP_RANGE (single public host, `/32`/`/128`) | HTTPS file on that IP | wider ranges need a later manual process |
| CLOUD_ACCOUNT (`aws:<12 digits>` + role ARN) | AssumeRole with our external ID | session capped by the read-only SecurityAudit policy |

All outbound verification traffic goes through an SSRF guard that refuses private,
loopback, link-local (incl. 169.254.169.254) and reserved addresses.

## Security notes

- **Passwords:** argon2id (19 MiB, t=2). Logins with unknown emails still run a hash check, so response timing doesn't reveal which accounts exist.
- **Tokens:** HS256 access JWTs, 15 minutes by default. Refresh tokens are opaque, stored only as HMAC-SHA256 hashes, rotated on every use, and revoked as a family if one is reused.
- **Audit:** every register, login (success and failure), refresh, logout, org create, invite and join writes an `AuditEvent`. Secrets in payloads are redacted. A Postgres trigger rejects UPDATE, DELETE and TRUNCATE on that table.
- **Supabase:** the init migration enables RLS on every table with no policies, so Supabase's Data API (anon/authenticated roles) can't read or write anything. The API connects as the table owner.

## Checks

```bash
npm run typecheck
npm test                     # unit tests (in-memory store)
TEST_DATABASE_URL=postgresql://... npm test   # + Postgres integration tests (migrated DB)
TEST_REDIS_URL=redis://... npm test           # + Redis rate-limiter integration test
```

CI (`.github/workflows/ci.yml`) runs install → migrate → web build → typecheck →
tests against a Postgres service on every push and PR.
