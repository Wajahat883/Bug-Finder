FROM node:20-alpine AS builder

WORKDIR /app

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY backend ./backend

RUN npm install -g pnpm@10.33.3
RUN pnpm install --frozen-lockfile

WORKDIR /app/backend
RUN pnpm run build

# ── Nuclei binary stage ───────────────────────────────────────────────────────
FROM projectdiscovery/nuclei:latest AS nuclei-bin

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# curl needed for healthcheck; git + ca-certificates needed for nuclei template updates
RUN apk add --no-cache curl git ca-certificates \
 && addgroup -g 1001 -S appgroup \
 && adduser  -u 1001 -S appuser -G appgroup

# Install nuclei binary — enables Tier 1 native scanning (no Docker-in-Docker needed)
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

# Nuclei templates directory (pre-populated at runtime via NUCLEI_TEMPLATES_DIR env)
RUN mkdir -p /home/appuser/nuclei-templates \
 && chown -R appuser:appgroup /home/appuser

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY backend ./backend

RUN npm install -g pnpm@10.33.3 \
 && pnpm install --prod --frozen-lockfile \
 && chown -R appuser:appgroup /app

COPY --from=builder --chown=appuser:appgroup /app/backend/dist ./backend/dist

USER appuser

WORKDIR /app/backend

EXPOSE 5000

CMD ["node", "--enable-source-maps", "dist/index.mjs"]
