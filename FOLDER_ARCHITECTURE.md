# Bug Finder Pro — Proposed Folder Architecture

> A clean, scalable, and domain-driven folder structure designed for enterprise-grade maintainability.

---

## Overview

The current monorepo works well, but as the application grows, a more intentional folder structure will help teams navigate faster and reduce coupling. This document proposes a **domain-driven folder architecture** that separates concerns by business capability rather than technical layer.

---

## Proposed Root Structure

```
Bug-Finder/
│
├── 📁 apps/                          ← Deployable applications
│   ├── web/                          ← React frontend (Vite)
│   ├── api/                          ← Express backend
│   └── docs/                         ← Documentation site (optional)
│
├── 📁 packages/                      ← Shared libraries
│   ├── ui/                           ← shadcn/ui component library
│   ├── api-client/                   ← Generated OpenAPI client
│   ├── config/                       ← Shared configs (eslint, tsconfig)
│   └── types/                        ← Shared TypeScript types
│
├── 📁 services/                      ← Background services
│   ├── scanner/                      ← Scan engine modules
│   ├── scheduler/                    ← Cron jobs & SLA enforcement
│   └── notifier/                     ← Email, Slack, webhook sender
│
├── 📁 infrastructure/                ← DevOps & deployment
│   ├── docker/                       ← Dockerfiles & compose
│   ├── terraform/                    ← IaC (optional)
│   ├── k8s/                          ← Kubernetes manifests (optional)
│   └── scripts/                      ← Deployment scripts
│
├── 📁 docs/                          ← Project documentation
│   ├── design/                       ← Design system, mockups
│   ├── architecture/                 ← ADRs, diagrams
│   ├── api/                          ← API documentation
│   └── runbooks/                     ← Operational guides
│
├── 📁 tests/                         ← End-to-end & integration tests
│   ├── e2e/                          ← Playwright/Cypress tests
│   └── integration/                  ← API integration tests
│
├── .env.example
├── pnpm-workspace.yaml
├── turbo.json                        ← Build orchestration
└── README.md
```

---

## Detailed Breakdown

### `apps/web/` — Frontend Application

```
apps/web/
├── public/                           ← Static assets
│   ├── fonts/
│   ├── images/
│   └── favicon.ico
│
├── src/
│   ├── main.tsx                      ← Entry point
│   ├── App.tsx                       ← Root router
│   ├── index.css                     ← Global styles & theme
│   │
│   ├── 📁 domain/                    ← Business domains
│   │   ├── auth/                     ← Authentication
│   │   │   ├── pages/
│   │   │   │   ├── login.tsx
│   │   │   │   ├── register.tsx
│   │   │   │   └── forgot-password.tsx
│   │   │   ├── components/
│   │   │   │   └── auth-guard.tsx
│   │   │   ├── hooks/
│   │   │   │   └── use-auth.ts
│   │   │   └── types/
│   │   │       └── auth.types.ts
│   │   │
│   │   ├── scans/                    ← Scan management
│   │   │   ├── pages/
│   │   │   │   ├── scan-list.tsx
│   │   │   │   ├── scan-detail.tsx
│   │   │   │   ├── new-scan.tsx
│   │   │   │   └── scan-compare.tsx
│   │   │   ├── components/
│   │   │   │   ├── scan-card.tsx
│   │   │   │   ├── scan-progress.tsx
│   │   │   │   ├── finding-stream.tsx
│   │   │   │   └── scan-filters.tsx
│   │   │   ├── hooks/
│   │   │   │   ├── use-scans.ts
│   │   │   │   └── use-scan-stream.ts
│   │   │   └── types/
│   │   │       └── scan.types.ts
│   │   │
│   │   ├── findings/                 ← Vulnerability findings
│   │   │   ├── pages/
│   │   │   │   ├── finding-list.tsx
│   │   │   │   └── finding-detail.tsx
│   │   │   ├── components/
│   │   │   │   ├── severity-badge.tsx
│   │   │   │   ├── cvss-display.tsx
│   │   │   │   └── finding-table.tsx
│   │   │   └── hooks/
│   │   │       └── use-findings.ts
│   │   │
│   │   ├── targets/                  ← Target management
│   │   ├── analytics/                ← Dashboards & reports
│   │   ├── ai/                       ← AI triage & chat
│   │   ├── remediations/             ← Fix tracking
│   │   └── settings/                 ← Platform configuration
│   │
│   ├── 📁 shared/                    ← Cross-cutting concerns
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── sidebar.tsx
│   │   │   │   ├── header.tsx
│   │   │   │   └── app-shell.tsx
│   │   │   ├── command-palette.tsx
│   │   │   ├── notification-toast.tsx
│   │   │   └── theme-toggle.tsx
│   │   ├── hooks/
│   │   │   ├── use-theme.ts
│   │   │   ├── use-notifications.ts
│   │   │   └── use-keyboard.ts
│   │   ├── lib/
│   │   │   ├── utils.ts
│   │   │   ├── api-client.ts
│   │   │   └── constants.ts
│   │   └── types/
│   │       └── global.types.ts
│   │
│   └── 📁 assets/                    ← Imported assets
│       └── icons/
│
├── package.json
├── vite.config.ts
├── tsconfig.json
└── tailwind.config.ts
```

**Why domain-driven?**
- Each feature is self-contained — easy to find, refactor, or delete
- Teams can own specific domains without merge conflicts
- Scales to 50+ pages without folder bloat

---

### `apps/api/` — Backend Application

```
apps/api/
├── src/
│   ├── index.ts                      ← Server bootstrap
│   ├── app.ts                        ← Express app config
│   │
│   ├── 📁 domains/                   ← Business domains
│   │   ├── auth/
│   │   │   ├── auth.routes.ts
│   │   │   ├── auth.controller.ts
│   │   │   ├── auth.service.ts
│   │   │   ├── auth.schema.ts        ← Zod validation
│   │   │   └── auth.types.ts
│   │   │
│   │   ├── scans/
│   │   │   ├── scans.routes.ts
│   │   │   ├── scans.controller.ts
│   │   │   ├── scans.service.ts
│   │   │   └── scans.schema.ts
│   │   │
│   │   ├── findings/
│   │   ├── targets/
│   │   ├── analytics/
│   │   ├── ai/
│   │   ├── webhooks/
│   │   └── settings/
│   │
│   ├── 📁 core/                      ← Shared infrastructure
│   │   ├── database/
│   │   │   ├── connection.ts
│   │   │   ├── migrations/
│   │   │   └── seeds/
│   │   ├── middleware/
│   │   │   ├── auth.middleware.ts
│   │   │   ├── error.middleware.ts
│   │   │   ├── logging.middleware.ts
│   │   │   └── rate-limit.middleware.ts
│   │   ├── services/
│   │   │   ├── logger.service.ts
│   │   │   ├── email.service.ts
│   │   │   └── cache.service.ts
│   │   └── utils/
│   │       ├── http-errors.ts
│   │       ├── async-handler.ts
│   │       └── validators.ts
│   │
│   └── 📁 config/
│       ├── env.ts                    ← Environment validation
│       └── constants.ts
│
├── package.json
├── tsconfig.json
└── Dockerfile
```

**Layer separation:**
- `routes` → HTTP layer (req/res handling)
- `controller` → Request validation & response formatting
- `service` → Business logic & external calls
- `schema` → Zod request/response validation

---

### `packages/ui/` — Shared Component Library

```
packages/ui/
├── src/
│   ├── components/
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── badge.tsx
│   │   ├── input.tsx
│   │   ├── select.tsx
│   │   ├── dialog.tsx
│   │   ├── dropdown-menu.tsx
│   │   ├── table.tsx
│   │   ├── tabs.tsx
│   │   ├── tooltip.tsx
│   │   └── skeleton.tsx
│   ├── hooks/
│   │   └── use-toast.ts
│   ├── lib/
│   │   └── utils.ts
│   └── globals.css
├── package.json
└── tsconfig.json
```

---

### `services/scanner/` — Scan Engine

```
services/scanner/
├── src/
│   ├── index.ts                      ← Scanner orchestrator
│   ├── scanner.ts                    ← Main pipeline
│   ├── context.ts                    ← ScanContext builder
│   ├── events.ts                     ← EventEmitter for SSE
│   │
│   ├── 📁 modules/                   ← 60+ scanner modules
│   │   ├── recon/
│   │   │   ├── crawl.ts
│   │   │   ├── subdomains.ts
│   │   │   └── passive-recon.ts
│   │   ├── injection/
│   │   │   ├── xss.ts
│   │   │   ├── sqli.ts
│   │   │   ├── command-injection.ts
│   │   │   └── ssti.ts
│   │   ├── auth/
│   │   │   ├── auth.ts
│   │   │   ├── jwt.ts
│   │   │   └── oauth.ts
│   │   ├── network/
│   │   │   ├── tls.ts
│   │   │   ├── headers.ts
│   │   │   ├── cors.ts
│   │   │   └── ports.ts
│   │   ├── cloud/
│   │   │   ├── s3-buckets.ts
│   │   │   └── metadata.ts
│   │   └── advanced/
│   │       ├── graphql.ts
│   │       ├── grpc.ts
│   │       └── smuggling.ts
│   │
│   └── 📁 profiles/
│       ├── quick.ts                  ← ~15 modules
│       ├── standard.ts               ← ~30 modules
│       └── deep.ts                   ← 60+ modules
│
└── package.json
```

---

## Data Flow Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      CLIENT (Browser)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  React UI   │  │  TanStack   │  │  SSE EventSource    │  │
│  │  Components │  │  Query      │  │  (Live Streams)     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                    │              │
│         └────────────────┴────────────────────┘              │
│                          │                                   │
│                    HTTP / SSE                                │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                    LOAD BALANCER (Nginx)                     │
│              /api/* → API    / → Static SPA                  │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                 API SERVER (Express + Node)                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │  Routes  │→ │Controller│→ │ Services │→ │ Database   │  │
│  │  (HTTP)  │  │ (Validate)│  │ (Logic)  │  │ (MongoDB)  │  │
│  └──────────┘  └──────────┘  └────┬─────┘  └────────────┘  │
│                                   │                          │
│                     ┌─────────────┼─────────────┐            │
│                     ▼             ▼             ▼            │
│              ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│              │  Scanner │  │   AI     │  │ Webhooks │       │
│              │  Engine  │  │  Service │  │  Service │       │
│              └──────────┘  └──────────┘  └──────────┘       │
│                   │                                        │
│                   ▼                                        │
│              ┌──────────┐                                  │
│              │OWASP ZAP │                                  │
│              └──────────┘                                  │
└──────────────────────────────────────────────────────────────┘
```

---

## Migration Guide

### Phase 1: Move without changing imports (soft migration)
```bash
# Create new structure alongside existing
mkdir -p apps/web/src/domain
mkdir -p apps/api/src/domains
mkdir -p packages/ui
```

### Phase 2: Move shared packages
- Extract `lib/api-spec` → `packages/api-spec`
- Extract `lib/api-zod` → `packages/api-types`
- Extract `lib/api-client-react` → `packages/api-client`
- Extract UI components → `packages/ui`

### Phase 3: Domain extraction
- Move pages into domain folders
- Move routes into domain folders
- Update imports to use path aliases (`@/domain/scans`)

### Phase 4: Clean up
- Remove old `artifacts/` and `lib/` folders
- Update pnpm-workspace.yaml
- Update Docker build contexts

---

*Architecture Proposal v1.0 — Bug Finder Pro*
