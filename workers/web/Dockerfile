# syntax=docker/dockerfile:1
# Aegis web-check worker (no external tools). Build from the repo root:
#   docker build -f workers/web/Dockerfile -t aegis/worker-web .
#


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
      --workspace @aegis/worker-web --include-workspace-root
COPY packages/db/prisma packages/db/prisma
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

# ── Runtime ────────────────────────────────────────────────────────
FROM node:22-alpine
RUN apk add --no-cache ca-certificates openssl tini \
 && addgroup -S aegis && adduser -S -G aegis -H -h /tmp aegis

WORKDIR /app
COPY --from=deps /app /app
COPY packages/core packages/core
COPY packages/db packages/db
COPY packages/worker-kit packages/worker-kit
COPY workers/web workers/web


ENV NODE_ENV=production HOME=/tmp
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--import", "tsx", "workers/web/src/main.ts"]
