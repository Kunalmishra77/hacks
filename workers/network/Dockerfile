# syntax=docker/dockerfile:1
# Aegis network-scan worker (NETWORK engine; Admin-approved scans only).
# Build from the repo root:
#   docker build -f workers/network/Dockerfile -t aegis/worker-network .
#
# naabu (MIT) and fingerprintx (Apache-2.0) are copied from their official
# images at pinned versions and invoked as separate programs; their source is
# not vendored into this repo.

FROM projectdiscovery/naabu:v2.6.1 AS naabu
FROM golang:1.23-alpine AS fingerprintx
# fingerprintx has no official image; build the pinned release from source.
RUN apk add --no-cache git \
 && go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@v1.1.19

# ── Dependencies ───────────────────────────────────────────────────
FROM node:22-alpine AS deps
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
RUN npm ci --ignore-scripts --no-audit --no-fund --include=dev \
      --workspace @aegis/worker-network --include-workspace-root
COPY packages/db/prisma packages/db/prisma
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

# ── Runtime ────────────────────────────────────────────────────────
FROM node:22-alpine
RUN apk add --no-cache ca-certificates tini \
 && addgroup -S aegis && adduser -S -G aegis -H -h /tmp aegis
COPY --from=naabu /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=fingerprintx /go/bin/fingerprintx /usr/local/bin/fingerprintx

WORKDIR /app
COPY --from=deps /app /app
COPY packages/core packages/core
COPY packages/db packages/db
COPY packages/worker-kit packages/worker-kit
COPY workers/network workers/network

RUN naabu -version && fingerprintx --help >/dev/null

ENV NODE_ENV=production HOME=/tmp
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--import", "tsx", "workers/network/src/main.ts"]
