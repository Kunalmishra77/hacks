# Deploying Aegis on Coolify

Coolify (on your VPS) can host every part of Aegis from this repo: the **API**,
the **dashboard**, and the four **scan workers**. Postgres is Supabase and Redis
is managed, so those stay external — you only point the services at them.

There are two ways to lay this out. Running each piece as its own Coolify
**Application** (recommended) gives independent logs, scaling and restarts. A
single compose is also fine for a quick start.

## 0. Before you start

- A Coolify project connected to this Git repo (`github.com/Kunalmishra77/hacks`).
- Your Supabase `DATABASE_URL` (transaction pooler, port 6543) and `DIRECT_URL`
  (session pooler, port 5432), and a `REDIS_URL`. URL-encode `@` in passwords as `%40`.
- Two different 32+ char secrets for `JWT_SECRET` and `JWT_REFRESH_SECRET`
  (`node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`).
- Decide the two public URLs, e.g. `https://api.aegis.example` and
  `https://app.aegis.example`. Point their DNS at the VPS; Coolify issues TLS.

## 1. API (Application → Dockerfile)

- **Build**: Dockerfile `apps/api/Dockerfile`, build context the repo root.
- **Port**: 4000. **Health check path**: `/ready` (it checks Postgres + Redis;
  `/health` is a plain liveness probe).
- **Domain**: `api.aegis.example`.
- **Environment** (mark secrets as secret):
  ```
  NODE_ENV=production
  API_HOST=0.0.0.0
  API_PORT=4000
  DATABASE_URL=postgresql://postgres.<ref>:<url-encoded-pw>@aws-0-<region>.pooler.supabase.com:6543/postgres?pgbouncer=true&connection_limit=1
  DIRECT_URL=postgresql://postgres.<ref>:<url-encoded-pw>@aws-0-<region>.pooler.supabase.com:5432/postgres
  REDIS_URL=redis://default:<pw>@<host>:<port>
  JWT_SECRET=<48+ random>
  JWT_REFRESH_SECRET=<a different 48+ random>
  COOKIE_SECURE=true
  CORS_ORIGINS=https://app.aegis.example
  API_PUBLIC_URL=https://api.aegis.example
  WEB_PUBLIC_URL=https://app.aegis.example
  NVD_API_KEY=<optional>
  AI_PROVIDER=off            # or openai / anthropic, with the matching key
  # OPENAI_API_KEY / ANTHROPIC_API_KEY / SMTP_URL / SMTP_FROM as needed
  ```

The API container runs `prisma migrate deploy` on start, so deploying it keeps
the Supabase schema up to date — no separate migration step. The scheduler tick
and the enrichment + alert workers run inside this API process (that's where the
NVD/SMTP keys live), so keep the API running for monitoring to work.

## 2. Dashboard (Application → Dockerfile)

- **Build**: Dockerfile `apps/web/Dockerfile`, context the repo root.
- **Build argument**: `NEXT_PUBLIC_API_URL=https://api.aegis.example`
  (inlined into the browser bundle at build time — it must be a *build* variable,
  not only a runtime one).
- **Port**: 3000. **Domain**: `app.aegis.example`.

## 3. Scan workers (one Application each)

The workers run the scanning tools and must sit behind the egress firewall from
[DEPLOY_VPS.md](DEPLOY_VPS.md) §4. For each of `discovery`, `tls`, `web`,
`network`:

- **Build**: Dockerfile `workers/<name>/Dockerfile`, context the repo root.
- **No ports, no domain** (they only make outbound connections).
- **Environment**: just `DATABASE_URL` and `REDIS_URL` (same values as the API).
  Workers never get JWT, AI, or SMTP secrets.

Start with `discovery`, `tls` and `web`; add `network` when you want
Admin-approved port scans. Apply the egress iptables rules on the VPS so a
worker can't reach private networks or the cloud metadata endpoint.

## 4. First run

1. Deploy the API, then the dashboard, then the workers.
2. Open `https://app.aegis.example`, create an account + organization.
3. Add a boundary you own under **Ownership**, verify it, run a check, and watch
   findings appear. Set a schedule and an alert channel under **Monitoring**.

## Updating

Push to `main`; Coolify redeploys the services you've enabled auto-deploy for.
The API re-applies any new migrations on boot.

## Notes

- `COOKIE_SECURE=true` is required in production (the API refuses to start
  otherwise), so the dashboard and API must be served over HTTPS — Coolify does
  this for you once DNS points at the VPS.
- `CORS_ORIGINS` must list the dashboard's exact origin, or the browser blocks
  API calls.
- A single-host alternative to steps 1–2 is `docker-compose.app.yml` (API + web)
  plus `docker-compose.workers.yml` (workers); set the same env in an `.env`.
