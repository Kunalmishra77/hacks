# Aegis ASM

Authorized, **defensive** attack-surface management and vulnerability assessment.
Aegis helps an organization find weaknesses in assets it **owns or is explicitly
authorized to test**, and tells it how to fix them. It never exploits, brute-forces,
or runs destructive actions. See [CLAUDE.md](CLAUDE.md) for the non-negotiable rules
and [docs/](docs/) for the PRD, architecture, and scope-authorization design.

> **Status: Phase 7 (AI advisory) done.** Everything from Phase 0–6, plus an
> **advisory AI layer**: ask an LLM (OpenAI or Anthropic) to explain a finding in
> plain language, judge how likely it's a false positive, and draft remediation —
> output a human reviews, clearly labelled, never acted on automatically. Cloud
> posture (Phase 4, needs real cloud accounts) is the remaining roadmap item.

## Repository layout

```
apps/
  api/        Fastify + Zod API: auth (argon2id + JWT + rotating refresh), RBAC, orgs, invites
  web/        Next.js (App Router) + Tailwind dashboard (landing + sign-in for now)
packages/
  core/       Shared types, RBAC, audit helper, Scope Authorization Gate, SSRF guard
  db/         Prisma schema, migrations, client, gate repository
  worker-kit/ Job lifecycle every worker shares: gate re-check, heartbeat, safe tool runner
  cve/        CVE intel: NVD (CVSS), EPSS, CISA KEV, and the risk-score formula
  report/     Report model + self-contained HTML renderer
  ai/         Advisory LLM client (OpenAI + Anthropic), prompt + parser
  core/ also: cron scheduling (croner) and alert-message building
workers/
  discovery/  crt.sh + subfinder (passive) → DNS → httpx liveness
  tls/        testssl.sh wrapper: protocol, cipher and certificate hygiene
  web/        security headers, cookie flags, exposed-file probes (no external tools)
  network/    naabu (connect scan) + fingerprintx service ID; Admin-approved
docs/         PRD, ARCHITECTURE, SCOPE_AUTHORIZATION, POWER_UP, DEPLOY_VPS
docker-compose.yml   Optional local Postgres, Redis, MinIO
```


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
npm run dev:worker:discovery # local worker (needs subfinder + httpx on PATH)
# TLS/Web/Network workers run on the VPS as Docker containers (docs/DEPLOY_VPS.md)
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
| GET | `/orgs/:orgId/findings`, `/orgs/:orgId/findings/:id` | Viewer+; risk-ranked, filterable |
| POST | `/orgs/:orgId/findings/:id/status` | Analyst+; triage |
| POST | `/orgs/:orgId/findings/:id/advise` | Analyst+; AI advice (cached; `?refresh=1`) |
| GET/POST | `/orgs/:orgId/reports` | list (Viewer+) / generate (Analyst+) |
| GET | `/orgs/:orgId/reports/:id/download` | Viewer+; in-app HTML |
| POST | `/orgs/:orgId/reports/:id/share` | Analyst+; returns a signed link |
| GET | `/reports/download?token=…` | public, signed, expiring |
| GET/POST | `/orgs/:orgId/schedules` | list (Viewer+) / create (Admin+) |
| PATCH/DELETE | `/orgs/:orgId/schedules/:id` | Admin+ |
| GET/POST | `/orgs/:orgId/channels` | list (Viewer+) / create (Admin+) |
| PATCH/DELETE | `/orgs/:orgId/channels/:id` | Admin+ |

Non-members of an org get `404` (not `403`) so org ids can't be probed.
Invite tokens are returned in the API response until email delivery lands in Phase 6.

## Discovery (Phase 2)

"Find assets" on a proven boundary queues a DISCOVERY scan. The worker
([workers/discovery](workers/discovery/)) re-checks the gate, then:

1. **Subdomains, passively:** crt.sh certificate logs + subfinder. Neither contacts your hosts.
2. **DNS** through public resolvers; names that only exist because of wildcard DNS are dropped.
   Names pointing at private/reserved IPs are recorded but **never contacted**.
3. **Liveness:** one ordinary HTTP(S) request per host on 80/443 via httpx, at the scope's
   rate limit, without following redirects.

Anything a tool returns outside the boundary is dropped before it reaches the database.
Port scanning is not part of discovery; it's the approval-gated NETWORK engine (Phase 3).
While a job runs, the worker re-checks the gate every 15 s, so the kill-switch, a scan kill
or a revoked/expired scope stops it. Deploy workers with [docs/DEPLOY_VPS.md](docs/DEPLOY_VPS.md); host the whole app (API, dashboard, workers) on Coolify with [docs/DEPLOY_COOLIFY.md](docs/DEPLOY_COOLIFY.md).

## Assessment engines (Phase 3)

Once an asset is known, run a check on it from the Assets tab. Each engine is its
own sandboxed worker that re-checks the gate, identifies exposure non-intrusively,
and writes **Findings** (severity, plain-language fix, redacted evidence):

| Engine | Tool | What it does | Deliberately does NOT |
|---|---|---|---|
| **TLS** | testssl.sh | protocols, ciphers, certificate hygiene | Heartbleed / CCS / ROBOT / Ticketbleed (memory-read or handshake-flood checks) |
| **Web** | built-in | HSTS/CSP/cookie flags, version disclosure, a curated exposed-file list (`.git`, `.env`, …), security.txt | follow redirects, store response bodies, send payloads |
| **Network** | naabu + fingerprintx | open TCP ports (top 100, connect scan) and the service/version on each | SYN/raw scanning, nmap, logins, brute force, payloads — and it needs **Admin approval** |

Findings are deduplicated per asset: a re-scan updates in place, and a finding
someone marked fixed that reappears is reopened. Evidence is redacted (secret-ish
keys, response bodies, extracted values) and size-capped before storage, so
secrets never land in the database. CVE references a tool reports are kept;
version→CVE matching and EPSS/KEV scoring arrive in Phase 3.5.

**On nmap and nuclei (CLAUDE.md rule 4).** nmap's licence (NPSL) treats
output-parsing wrappers as derivative works, so Network uses naabu (MIT) +
fingerprintx (Apache-2.0) instead; swap in nmap later if you hold a licence for
it. nuclei is not run in Phase 3: even its non-exploit template folders contain
templates that send crafted requests or reach cloud-metadata endpoints, which is
more than "identify", so Web uses a small, auditable set of native checks.

## CVE intel & risk scoring (Phase 3.5)

A flat list of CVEs doesn't tell you what to fix first. After a scan writes
findings, an enrichment pass pulls three signals and combines them:

- **CVSS** (from NVD) — how severe the flaw is, 0–10.
- **EPSS** (from FIRST.org) — the probability it'll be exploited in the next 30 days.
- **CISA KEV** — whether it's *already* being exploited in the wild.

Each finding gets a **risk score (0–100)** = `CVSS × EPSS × asset-importance`,
and anything on the KEV list is escalated to the top (min score 85, at least
HIGH). Findings without a CVE (missing headers, insecure cookies) still get a
score from their engine severity, so one ranked worklist covers everything.
"Importance" is a per-boundary setting (Ownership tab) — mark your production
domain HIGH and a staging box LOW to tune the ranking.

**Where the keys live.** Enrichment runs in the **API process**, next to the
NVD key, as a separate BullMQ worker. The scan workers on the VPS never receive
the key — a scan worker finishes, enqueues `{scanId}`, and the enrichment worker
(with the key) does the lookups. NVD CVSS is cached indefinitely, EPSS daily,
and the KEV catalog on a TTL. The whole pass is advisory and fails soft: if a
source is down, the finding is still scored from what's known, and the scan is
never affected. Set `CVE_ENRICHMENT=off` to disable it.

## Reports (Phase 5)

From the Reports tab, generate a point-in-time report for the whole
organization or a single boundary. A report is a **snapshot**: it captures the
open (and triaged) findings at that moment, risk-ranked, each with its CVE/CVSS/
EPSS/KEV context and remediation, plus a severity summary and an asset count.

The report is a **self-contained HTML document** — inline styles, no scripts, no
external resources — so it opens anywhere and prints straight to PDF from the
browser. Rendering escapes all content and redacts secret-ish evidence keys, so
nothing sensitive leaks into a document meant to be shared.

Two ways to hand it over:

- **In-app**: the dashboard fetches it with your session and opens it in a tab.
- **Shareable link**: mint a signed, expiring URL (`/reports/download?token=…`,
  72 h by default) that opens without a login — for a client or a colleague
  without an account. The token is a stateless HMAC over the report id and
  expiry (ARCHITECTURE §5 "signed, short-lived URLs"); nothing but expiry can be
  inferred from it, and the report body is served with `Content-Security-Policy:
  default-src 'none'` and `Cache-Control: no-store`.

Report bodies are stored in Postgres so a shared link keeps showing the snapshot
even as findings change. (Wire object storage — Supabase Storage or any
S3-compatible endpoint — in a later pass if you'd rather keep large bodies out
of the database.) Every generation and share is audited.

## Scheduling & monitoring (Phase 6)

The Monitoring tab turns one-off scans into continuous coverage.

**Recurring scans.** Schedule a set of engines against a proven boundary on a
standard cron (hourly at most). A tick in the API process fires due schedules,
enumerating the scope's assets per engine and requesting each scan through
`requestScan` — the exact same path a human request takes. A schedule therefore
can't scan anything a user couldn't: the Scope Authorization Gate still enforces
verification, allowed engines, the kill-switch, approval (NETWORK stays
Admin-approved even when scheduled) and the rate/concurrency limits. A failing
schedule still advances to its next run, so one bad entry can't jam the loop.

**New-exposure alerts.** After a scan's findings are enriched (so severity, risk
and KEV are known), anything *new* and notable is pushed to your channels:

- **Slack** (incoming-webhook URL) · **Webhook** (POST a JSON alert) ·
  **Email** (SMTP) · **WhatsApp** (Cloud API).

Each channel has a minimum severity and an "always alert on known-exploited"
toggle. Only findings first seen in that scan count as new, so you're told about
changes, not re-told about everything each run. Delivery is best-effort: a
failing channel is recorded (`lastError`) and skipped, never fatal to the scan.
Customer-supplied Slack/webhook URLs go through the same SSRF guard as ownership
verification — no posting to private or loopback addresses. Alert messages carry
titles, severity and asset — never evidence or secrets.

Both the tick and the dispatcher run in the API process (where Redis and the
SMTP/WhatsApp config live), not on the scan workers. Set `SCHEDULER=off` to
disable the tick.

## AI advisory (Phase 7)

In an expanded finding, **Explain with AI** asks an LLM to turn the finding into
a plain-language explanation, a false-positive judgement, and a remediation
draft. Pick a provider with `AI_PROVIDER` (`openai` or `anthropic`) and set its
key; `off` (the default) hides the feature. The model override is `AI_MODEL`
(defaults: `gpt-4o-mini`, or `claude-opus-5-5` for Anthropic).

It is **advisory only**, and the code enforces the ARCHITECTURE §6 rules:

- The AI never starts a scan, picks a target, or acts. Its output is text the
  UI shows, clearly labelled *"AI suggestion — review before acting"*, with the
  model and a confidence level. Findings of record still come from the engines.
- A finding's title and evidence come from scanned systems, so they're
  **untrusted**: the prompt wraps them and tells the model to treat them as data,
  not instructions, and never to emit shell commands, exploit code, or targets.
  (A live test feeds an injected `rm -rf /` in evidence and asserts it's ignored.)
- Advice is Analyst+, rate-limited per org (it costs money), and cached on the
  finding so re-viewing doesn't re-bill; `?refresh=1` regenerates. The audit log
  records that advice was generated and by which model — never the advice text.

The provider is pluggable (`@aegis/ai`): Anthropic goes through the official SDK,
OpenAI through a small fetch client, both behind one interface.

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
