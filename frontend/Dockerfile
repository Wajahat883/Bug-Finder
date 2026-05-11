FROM node:20-alpine AS builder

WORKDIR /app

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json ./
COPY frontend ./frontend

RUN npm install -g pnpm
RUN pnpm install --no-frozen-lockfile

WORKDIR /app/frontend
RUN PORT=3000 BASE_PATH=/ pnpm run build

FROM nginx:alpine

COPY --from=builder /app/frontend/dist/public /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]