# syntax=docker/dockerfile:1
# Aegis web dashboard (Next.js standalone). Build from the repo root:
#   docker build -f apps/web/Dockerfile \
#     --build-arg NEXT_PUBLIC_API_URL=https://api.example.com -t aegis/web .
#
# NEXT_PUBLIC_API_URL is inlined into the client bundle at build time, so it
# must be set as a build arg (Coolify: set it under the app's build variables).

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY apps/web/package.json apps/web/
# Workspace manifests the lockfile needs to resolve.
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
COPY packages/cve/package.json packages/cve/
COPY packages/report/package.json packages/report/
COPY packages/ai/package.json packages/ai/
COPY packages/worker-kit/package.json packages/worker-kit/
COPY apps/api/package.json apps/api/
COPY workers/discovery/package.json workers/discovery/
COPY workers/web/package.json workers/web/
COPY workers/tls/package.json workers/tls/
COPY workers/network/package.json workers/network/
RUN npm ci --ignore-scripts --no-audit --no-fund --workspace @aegis/web --include-workspace-root
COPY apps/web apps/web

ARG NEXT_PUBLIC_API_URL="http://localhost:4000"
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} NEXT_TELEMETRY_DISABLED=1
RUN npx next build apps/web

FROM node:22-alpine
RUN apk add --no-cache tini \
 && addgroup -S aegis && adduser -S -G aegis aegis
WORKDIR /app
ENV NODE_ENV=production PORT=3000
# Standalone server + its trimmed node_modules, then static assets.
COPY --from=build /app/apps/web/.next/standalone ./
COPY --from=build /app/apps/web/.next/static ./apps/web/.next/static
EXPOSE 3000
USER aegis
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/web/server.js"]
