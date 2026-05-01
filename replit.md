# Bug Bounty Pro

A full-stack enterprise-grade web vulnerability assessment and security scanning platform.

## Stack

- **Frontend**: React + TypeScript + Vite (Tailwind CSS, Recharts, Wouter routing, TanStack Query)
- **Backend**: Express 5 + TypeScript (pnpm monorepo, esbuild)
- **Database**: MongoDB (with automatic in-memory fallback when MONGODB_URI is not set)
- **Code Generation**: OpenAPI → Orval → React Query hooks + Zod schemas

## Architecture

```
artifacts/
  bug-bounty-pro/     — React frontend (port $PORT, preview at /)
  api-server/         — Express API server (port $PORT, preview at /api)
lib/
  api-spec/           — OpenAPI spec + Orval codegen config
  api-client-react/   — Generated React Query hooks
  api-zod/            — Generated Zod validation schemas
  db/                 — Drizzle ORM (PostgreSQL, not used by api-server currently)
```

## Features

### Frontend Pages
- `/` — Command Center Dashboard (KPI cards, severity donut chart, activity feed)
- `/scans` — Scan Jobs list with search, filter, status badges, progress bars
- `/scans/new` — Launch New Scan form (target URL, profile selector, advanced toggles)
- `/scans/:id` — Scan Detail with real-time progress, findings, AI summary, attack surface
- `/findings` — Findings Explorer (filter by severity, validation status, search)
- `/findings/:id` — Finding Detail (CVSS, CWE, evidence, recommended fix)
- `/targets` — Target inventory with risk scores
- `/targets/:id` — Target detail view
- `/remediations` — Remediation task management
- `/system` — System health status
- `/settings` — App configuration and API key

### Backend API Routes (all under /api)
- `GET /api/healthz` — Health check
- `GET/POST /api/auth/me|login|logout` — Authentication
- `GET /api/dashboard/stats` — Dashboard statistics
- `GET /api/dashboard/activity` — Activity feed
- `GET/POST /api/scan-jobs` — List/create scan jobs
- `GET/DELETE /api/scan-jobs/:id` — Get/delete scan job
- `GET /api/scan-jobs/:id/findings` — Job findings
- `GET /api/scan-jobs/:id/attack-surface` — Attack surface graph
- `GET /api/findings` — List all findings (with filters)
- `GET/PATCH /api/findings/:id` — Get/update finding
- `GET /api/targets` — List targets
- `GET /api/targets/:id` — Get target
- `GET/PUT /api/settings` — Get/update settings
- `GET/POST /api/remediations` — List/create remediations
- `GET/PATCH /api/remediations/:id` — Get/update remediation

### Scan Simulation
- When a new scan job is created, the backend automatically simulates scanner execution
- Progress updates from 0 → 100% over 15–50 seconds (depending on profile)
- Findings are generated and persisted when the scan completes

## MongoDB Connection

Set `MONGODB_URI` environment variable to connect to MongoDB Atlas or a MongoDB instance.
If `MONGODB_URI` is not set, the server uses a built-in in-memory store.

## Development

```bash
# Run codegen (after changing openapi.yaml)
cd lib/api-spec && npx orval --config ./orval.config.ts
echo "export * from \"./generated/api\";" > ../api-zod/src/index.ts
pnpm run typecheck:libs

# Build api-server
pnpm --filter @workspace/api-server run build

# The workflows auto-restart via Replit
```

## Seeded Demo Data

On first startup, the server seeds:
- 5 target domains
- 18 scan jobs with various statuses (completed, running, queued, failed)
- ~100 security findings across multiple severity levels
- 20 activity events
- Remediation tasks for critical/high findings
- Default settings with API key
