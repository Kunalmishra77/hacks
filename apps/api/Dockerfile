# syntax=docker/dockerfile:1
# Aegis API. Build from the repo root:
#   docker build -f apps/api/Dockerfile -t aegis/api .
# Runs migrations on start (idempotent), then the Fastify server. Coolify-ready:
# health check GET /health (liveness), GET /ready (DB + Redis readiness).

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
COPY packages/cve/package.json packages/cve/
COPY packages/report/package.json packages/report/
COPY packages/ai/package.json packages/ai/
COPY packages/worker-kit/package.json packages/worker-kit/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY workers/discovery/package.json workers/discovery/
COPY workers/web/package.json workers/web/
COPY workers/tls/package.json workers/tls/
COPY workers/network/package.json workers/network/
RUN npm ci --ignore-scripts --no-audit --no-fund \
      --workspace @aegis/api --include-workspace-root
COPY packages/db/prisma packages/db/prisma
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

FROM node:22-alpine
RUN apk add --no-cache tini openssl \
 && addgroup -S aegis && adduser -S -G aegis -H -h /tmp aegis
WORKDIR /app
COPY --from=deps /app /app
COPY packages/core packages/core
COPY packages/db packages/db
COPY packages/cve packages/cve
COPY packages/report packages/report
COPY packages/ai packages/ai
COPY packages/worker-kit packages/worker-kit
COPY apps/api apps/api

ENV NODE_ENV=production HOME=/tmp
EXPOSE 4000
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
# Apply any pending migrations, then start the API.
CMD ["sh", "-c", "npx prisma migrate deploy --schema packages/db/prisma/schema.prisma && node --import tsx apps/api/src/server.ts"]
