# syntax=docker/dockerfile:1
# Aegis cloud-posture worker (CLOUD engine; Admin-approved scans only).
# Build from the repo root:
#   docker build -f workers/cloud/Dockerfile -t aegis/worker-cloud .
#
# prowler (Apache-2.0) is installed from PyPI at a pinned version and invoked as
# a separate program; its source is not vendored into this repo. The AWS role
# Aegis assumes is capped read-only by a SecurityAudit session policy (aws.ts),
# and we pass `--status FAIL` so prowler only ever reports — never remediates.

# ── Node dependencies ──────────────────────────────────────────────
# Built on the same glibc base as the runtime so the Prisma engine matches.
FROM node:22-bookworm-slim AS deps
WORKDIR /app
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
COPY workers/cloud/package.json workers/cloud/
RUN npm ci --ignore-scripts --no-audit --no-fund --include=dev \
      --workspace @aegis/worker-cloud --include-workspace-root
COPY packages/db/prisma packages/db/prisma
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

# ── Runtime ────────────────────────────────────────────────────────
FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/prowler \
 && /opt/prowler/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/prowler/bin/pip install --no-cache-dir prowler==5.44.0 \
 && ln -s /opt/prowler/bin/prowler /usr/local/bin/prowler \
 && useradd --system --home-dir /tmp --shell /usr/sbin/nologin aegis

WORKDIR /app
COPY --from=deps /app /app
COPY packages/core packages/core
COPY packages/db packages/db
COPY packages/worker-kit packages/worker-kit
COPY workers/cloud workers/cloud

RUN prowler --version

ENV NODE_ENV=production HOME=/tmp
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--import", "tsx", "workers/cloud/src/main.ts"]
