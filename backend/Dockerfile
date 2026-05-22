FROM node:20-alpine AS builder

WORKDIR /app

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY backend ./backend

RUN npm install -g pnpm@10.33.3
RUN pnpm install --frozen-lockfile

WORKDIR /app/backend
RUN pnpm run build

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# curl needed only for Docker healthcheck probe
RUN apk add --no-cache curl \
 && addgroup -g 1001 -S appgroup \
 && adduser  -u 1001 -S appuser -G appgroup

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
