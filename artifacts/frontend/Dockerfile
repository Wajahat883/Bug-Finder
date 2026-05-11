# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy workspace root files
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./

# Copy monorepo packages
COPY lib ./lib
COPY artifacts/frontend ./artifacts/frontend

# Install pnpm
RUN npm install -g pnpm

# Install dependencies
RUN pnpm install --no-frozen-lockfile

# Build the frontend (PORT and BASE_PATH required by vite.config.ts)
WORKDIR /app/artifacts/frontend
RUN PORT=3000 BASE_PATH=/ pnpm run build

# Runtime stage
FROM nginx:alpine

# Copy built assets from builder (vite outputs to dist/public)
COPY --from=builder /app/artifacts/frontend/dist/public /usr/share/nginx/html

# Copy nginx config with /api/ proxy to api-server
COPY artifacts/frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
