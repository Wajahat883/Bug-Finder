# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy workspace root files
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./

# Copy monorepo packages
COPY lib ./lib
COPY artifacts/backend ./artifacts/backend

# Install pnpm
RUN npm install -g pnpm

# Install dependencies
RUN pnpm install --no-frozen-lockfile

# Build the API server
WORKDIR /app/artifacts/backend
RUN pnpm run build

# Runtime stage
FROM node:20-alpine

WORKDIR /app

# Copy workspace root files
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./

# Copy monorepo packages
COPY lib ./lib
COPY artifacts/backend ./artifacts/backend

# Install pnpm
RUN npm install -g pnpm

# Install production dependencies only
RUN pnpm install --prod --no-frozen-lockfile

# Copy built files from builder
COPY --from=builder /app/artifacts/backend/dist ./artifacts/backend/dist

WORKDIR /app/artifacts/backend

EXPOSE 5000

CMD ["node", "--enable-source-maps", "dist/index.mjs"]
