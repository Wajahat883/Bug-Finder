FROM node:20-alpine AS builder

WORKDIR /app

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY backend ./backend

RUN npm install -g pnpm
RUN pnpm install --no-frozen-lockfile

WORKDIR /app/backend
RUN pnpm run build

FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY backend ./backend

RUN npm install -g pnpm
RUN pnpm install --prod --no-frozen-lockfile

COPY --from=builder /app/backend/dist ./backend/dist

WORKDIR /app/backend

EXPOSE 5000

CMD ["node", "--enable-source-maps", "dist/index.mjs"]