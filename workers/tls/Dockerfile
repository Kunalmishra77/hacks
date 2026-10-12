# syntax=docker/dockerfile:1
# Aegis TLS-check worker. Build from the repo root:
#   docker build -f workers/tls/Dockerfile -t aegis/worker-tls .
#
# testssl.sh (GPLv2) is copied from its official image and invoked as a
# separate program; its source is not part of this repo.

FROM drwetter/testssl.sh:3.2 AS testssl

# ── Dependencies ───────────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app
# All workspace manifests so the lockfile resolves; only this worker's
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
RUN npm ci --ignore-scripts --no-audit --no-fund \
      --workspace @aegis/worker-tls --include-workspace-root
COPY packages/db/prisma packages/db/prisma
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

# ── Runtime ────────────────────────────────────────────────────────
FROM node:22-alpine
# testssl.sh's runtime needs (the same set its own image installs).
RUN apk add --no-cache ca-certificates openssl tini bash procps drill coreutils libidn curl socat xxd \
 && addgroup -S aegis && adduser -S -G aegis -H -h /tmp aegis
COPY --from=testssl /home/testssl /opt/testssl

WORKDIR /app
COPY --from=deps /app /app
COPY packages/core packages/core
COPY packages/db packages/db
COPY packages/worker-kit packages/worker-kit
COPY workers/tls workers/tls

# Fail the build if testssl is missing or no longer supports a flag we rely on.
RUN /opt/testssl/testssl.sh --version \
 && for f in --nodns --jsonfile --server-preference --fs --crime --drown --sweet32 --ip --openssl-timeout; do \
      /opt/testssl/testssl.sh --help 2>&1 | grep -q -- "$f" || { echo "testssl lacks $f"; exit 1; }; \
    done

ENV NODE_ENV=production HOME=/tmp
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--import", "tsx", "workers/tls/src/main.ts"]
