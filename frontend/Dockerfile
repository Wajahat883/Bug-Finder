FROM node:20-alpine AS builder

WORKDIR /app

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY frontend ./frontend

RUN npm install -g pnpm
RUN pnpm install --frozen-lockfile

WORKDIR /app/frontend
RUN PORT=3000 BASE_PATH=/ pnpm run build

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM nginx:1.25-alpine

# Remove default nginx user and run as nobody
RUN rm /etc/nginx/conf.d/default.conf

COPY --from=builder /app/frontend/dist/public /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Allow nginx worker to bind to port 3000 and write to tmp dirs as non-root
RUN chown -R nobody:nobody /usr/share/nginx/html \
 && chown -R nobody:nobody /var/cache/nginx \
 && chown -R nobody:nobody /var/log/nginx \
 && touch /var/run/nginx.pid \
 && chown nobody:nobody /var/run/nginx.pid

USER nobody

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
