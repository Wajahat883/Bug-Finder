# Production Deployment Checklist

Run through every item before going live. Each item is a real failure mode.

## Secrets & Credentials

- [ ] Copy `.env.production.example` → `.env`, fill in ALL values
- [ ] `SESSION_SECRET` is ≥ 64 random characters (`openssl rand -hex 64`)
- [ ] `CREDENTIAL_VAULT_KEY` is ≥ 32 random characters (`openssl rand -hex 32`)
- [ ] `WEBHOOK_SECRET_KEY` is ≥ 32 random characters (`openssl rand -hex 32`)
- [ ] `ADMIN_PASSWORD` meets complexity requirements (12+ chars, upper, number, symbol)
- [ ] `MONGO_PASSWORD` is strong (24+ random characters)
- [ ] `GRAFANA_ADMIN_PASSWORD` is changed from default
- [ ] `.env` is NOT committed to git (`git status` should not show it)

## Network & CORS

- [ ] `ALLOWED_ORIGINS` set to your real frontend domain only (no localhost)
- [ ] Nginx configured with TLS (HTTPS) — see `config/nginx/nginx.conf`
- [ ] Ports 27017 (MongoDB), 6379 (Redis), 3001 (Grafana) NOT exposed publicly
- [ ] Firewall only allows 80/443 inbound from internet

## Docker

- [ ] Using `docker compose --env-file .env up -d` (not hardcoded values)
- [ ] Confirm containers run as non-root: `docker exec bug-finder-api whoami` → `appuser`
- [ ] Confirm frontend container runs as non-root: `docker exec bug-finder-frontend whoami` → `nobody`

## Database

- [ ] MongoDB authentication enabled (not running with `--noauth`)
- [ ] MongoDB not reachable from public internet
- [ ] Backup cron is running: `docker logs bug-finder-backup`

## Application

- [ ] `NODE_ENV=production` set — app will refuse to start with default secrets
- [ ] `/api/health` returns 200 and all dependencies are green
- [ ] Admin login works at `/admin` with your new ADMIN_PASSWORD
- [ ] Test creating a scan and viewing findings

## Monitoring

- [ ] Grafana accessible at internal URL only (not port 3001 exposed to internet)
- [ ] Grafana login works with your GRAFANA_ADMIN_PASSWORD
- [ ] Loki receiving logs from API server

## Before Each Release

- [ ] Run `pnpm audit` in both `/backend` and `/frontend` — fix critical vulns
- [ ] Run `npx tsc --noEmit` in `/backend` — must be 0 errors
- [ ] Test login, scan creation, and finding detail page as a normal user
- [ ] Test login and admin panel as an admin user
