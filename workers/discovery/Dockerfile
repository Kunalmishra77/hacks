# syntax=docker/dockerfile:1
# Aegis discovery worker. Build from the repo root:
#   docker build -f workers/discovery/Dockerfile -t aegis/worker-discovery .
#
# subfinder and httpx (ProjectDiscovery, MIT) are copied from their official
# images at pinned versions; their source is not vendored into this repo.

FROM projectdiscovery/subfinder:v2.16.0 AS subfinder
FROM projectdiscovery/httpx:v1.11.0 AS httpx

# ── Dependencies ───────────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app
# All workspace manifests so the lockfile resolves; only the worker's
# dependency tree is installed.
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
COPY packages/cve/package.json packages/cve/
COPY packages/worker-kit/package.json packages/worker-kit/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY workers/discovery/package.json workers/discovery/
COPY workers/web/package.json workers/web/
COPY workers/tls/package.json workers/tls/
COPY workers/network/package.json workers/network/
RUN npm ci --ignore-scripts --no-audit --no-fund --include=dev \
      --workspace @aegis/worker-discovery --include-workspace-root
COPY packages/db/prisma packages/db/prisma
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

# ── Runtime ────────────────────────────────────────────────────────
FROM node:22-alpine
RUN apk add --no-cache ca-certificates openssl tini \
 && addgroup -S aegis && adduser -S -G aegis -H -h /tmp aegis
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx

WORKDIR /app
COPY --from=deps /app /app
COPY packages/core packages/core
COPY packages/db packages/db
COPY packages/worker-kit packages/worker-kit
COPY workers/discovery workers/discovery

# Fail the build if a tool is missing or no longer supports a flag we rely on.
RUN subfinder -version \
 && httpx -version \
 && for f in -td -server -title -sc -rl -duc -nc; do httpx -h 2>&1 | grep -q -- " $f" || { echo "httpx lacks $f"; exit 1; }; done \
 && for f in -max-time -duc -nc -silent; do subfinder -h 2>&1 | grep -q -- " $f" || { echo "subfinder lacks $f"; exit 1; }; done

ENV NODE_ENV=production HOME=/tmp
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--import", "tsx", "workers/discovery/src/main.ts"]
