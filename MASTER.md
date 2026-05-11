# Bug Finder Pro — Complete Application Design & Architecture

> Single-source comprehensive documentation covering every aspect of the platform.

---

## Table of Contents

1. [Application Overview](#1-application-overview)
2. [System Architecture](#2-system-architecture)
3. [Folder Structure](#3-folder-structure)
4. [How the Application Works](#4-how-the-application-works)
5. [How the Scan Engine Works](#5-how-the-scan-engine-works)
6. [How the AI Works](#6-how-the-ai-works)
7. [AI Pentest Features](#7-ai-pentest-features)
8. [Database Design](#8-database-design)
9. [Design System](#9-design-system)
10. [API Reference](#10-api-reference)
11. [Frontend Architecture](#11-frontend-architecture)
12. [Authentication & RBAC](#12-authentication--rbac)
13. [Deployment & Infrastructure](#13-deployment--infrastructure)

---

## 1. Application Overview

**Bug Finder Pro** is a full-stack autonomous security scanning platform that combines real-time vulnerability detection, AI-powered analysis, OWASP Top 10 coverage, CVSS 3.1 scoring, SLA enforcement, GitHub/Slack integration, and executive dashboards — all in a single modern web application.

### Core Capabilities

| Capability | Description |
|---|---|
| **Security Scanning** | 39+ scanner modules covering injection, auth, network, cloud, recon |
| **Real-Time Streaming** | SSE-powered live scan progress and finding discovery |
| **AI Analysis** | Autonomous pentesting, remediation advice, attack payloads, code patches |
| **Vulnerability Management** | Full CRUD with CVSS, OWASP mapping, CVE enrichment, kill chains |
| **SLA Enforcement** | Auto-deadlines: Critical=24h, High=72h, Medium=7d, Low=30d |
| **Integrations** | GitHub issues, Slack alerts, custom webhooks, email |
| **Reporting** | Executive dashboards, attack surface maps, PDF export, compliance reports |
| **Multi-Tenant** | Role-based access: admin, analyst, viewer |

### Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Wouter, TanStack Query, Recharts, Lucide Icons |
| **Backend** | Node.js, Express 5, TypeScript, esbuild |
| **Database** | MongoDB (with in-memory fallback for dev environments) |
| **AI** | OpenCode API (OpenAI-compatible) with SSE streaming |
| **Scanner** | OWASP ZAP integration + 39 custom scanner modules |
| **Infrastructure** | Docker Compose: MongoDB, Redis, ZAP, Nginx, Grafana, Loki |
| **Auth** | Session-based (express-session + connect-mongo), bcrypt hashing |

---

## 2. System Architecture

### Three-Layer Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    LAYER 1: PRESENTATION                          │
│  Browser → React SPA (Vite) → Tailwind CSS → Wouter Routing      │
│  TanStack Query for data fetching → SSE for real-time streams     │
└──────────────────────────────┬───────────────────────────────────┘
                               │ HTTP / SSE
┌──────────────────────────────▼───────────────────────────────────┐
│                    LAYER 2: API / BUSINESS LOGIC                  │
│  Nginx (port 3000) → /api/* → Express API (port 5000)            │
│  Routes → Controllers → Services → Database                      │
│  Scan Engine → 39 scanner modules → SSE event streaming          │
│  AI Service → OpenCode API → SSE token streaming                 │
│  Scheduler → node-cron → SLA enforcement + scheduled scans       │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                    LAYER 3: DATA & INFRASTRUCTURE                 │
│  MongoDB 7 (primary DB + session store)                           │
│  Redis 7 (caching, rate limiting)                                 │
│  OWASP ZAP (active vulnerability scanner on port 8080)           │
│  OpenCode AI (streaming analysis via OpenAI-compatible API)      │
│  Grafana + Loki (observability on ports 3001/3100)               │
│  Docker Compose (full stack orchestration)                        │
└──────────────────────────────────────────────────────────────────┘
```

### Request Lifecycle

```
Browser                Nginx(:3000)           Express(:5000)        MongoDB
  │                        │                       │                    │
  │ GET /api/findings      │                       │                    │
  │───────────────────────→│                       │                    │
  │                        │ proxy_pass /api/*     │                    │
  │                        │──────────────────────→│                    │
  │                        │                       │ session middleware │
  │                        │                       │ → validate cookie  │
  │                        │                       │ → requireAuth      │
  │                        │                       │                    │
  │                        │                       │ col("findings")    │
  │                        │                       │───────────────────→│
  │                        │                       │←───────────────────│
  │                        │                       │ formatFinding()    │
  │                        │                       │ → JSON response    │
  │                        │←──────────────────────│                    │
  │←───────────────────────│                       │                    │
  │  { items: [...], total: 12 }                  │                    │
```

### Middleware Stack (in order)

```
1. pino-http          → Request logging (method, path, status)
2. cors               → Cross-origin with credentials (origin: true)
3. express-session    → MongoDB-backed sessions (7-day TTL, httpOnly)
4. express.json()     → JSON body parsing
5. apiKeyAuth         → X-API-Key header validation (optional session)
6. ipAllowlist        → IP-based access control
7. Route handlers     → All under /api prefix
```

---

## 3. Folder Structure

```
Bug-Finder/
│
├── backend/                              ← All backend code
│   ├── src/
│   │   ├── index.ts                      ← Server bootstrap & listen
│   │   ├── app.ts                        ← Express app config, middleware
│   │   ├── routes/                       ← 22 API route modules
│   │   │   ├── index.ts                  ← Master router — mounts all
│   │   │   ├── auth.ts                   ← Login, register, logout, me, demo, 2FA, OAuth
│   │   │   ├── scans.ts                  ← Scan CRUD, formatFinding export
│   │   │   ├── findings.ts               ← Findings CRUD, CVE, kill chains, diff, export
│   │   │   ├── targets.ts                ← Target CRUD, bulk import, risk trend, attack surface
│   │   │   ├── remediations.ts           ← Remediation CRUD
│   │   │   ├── sla.ts                    ← SLA summary, velocity, burn-down, heatmap, exceptions
│   │   │   ├── compliance.ts             ← OWASP Top 10, PCI-DSS, SOC2, ISO, attestations
│   │   │   ├── analytics.ts              ← Dashboard aggregate stats
│   │   │   ├── dashboard.ts              ← Dashboard KPI + activity feed
│   │   │   ├── ai.ts                     ← AI streaming endpoints (18 total)
│   │   │   ├── stream.ts                 ← SSE scan progress streaming
│   │   │   ├── settings.ts               ← Platform settings CRUD
│   │   │   ├── integrations.ts           ← GitHub, Slack, webhook config
│   │   │   ├── auditlog.ts               ← Security audit trail
│   │   │   ├── webhooks.ts               ← Outbound webhook management
│   │   │   ├── comparison.ts             ← Side-by-side scan comparison
│   │   │   ├── scan-templates.ts         ← Saved scan configurations
│   │   │   ├── report-schedules.ts       ← Scheduled report delivery
│   │   │   ├── comments.ts               ← Finding comments
│   │   │   ├── risk-trend.ts             ← Risk trending data
│   │   │   └── health.ts                 ← Health check endpoint
│   │   ├── services/
│   │   │   ├── scanner/                  ← 39 scanner modules
│   │   │   │   ├── index.ts              ← Main pipeline orchestrator
│   │   │   │   ├── types.ts              ← ScanFinding, ScanContext types
│   │   │   │   ├── crawl.ts, recon.ts, passive-recon.ts, subdomains.ts
│   │   │   │   ├── tls.ts, headers.ts, cookies.ts, cors.ts, csrf.ts
│   │   │   │   ├── dns.ts, ports.ts, infrastructure.ts, fingerprint.ts
│   │   │   │   ├── xss.ts, sqli.ts, injection-advanced.ts
│   │   │   │   ├── auth.ts, auth-advanced.ts, jwt.ts, oauth.ts, idor.ts
│   │   │   │   ├── redirect.ts, pathtraversal.ts, file-upload.ts
│   │   │   │   ├── graphql.ts, grpc.ts, api-advanced.ts
│   │   │   │   ├── js-secrets.ts, cve-lookup.ts, data-exposure.ts
│   │   │   │   ├── smuggling.ts, cache-poisoning.ts, business-logic.ts
│   │   │   │   ├── cloud.ts, xxe.ts, nuclei.ts, zap.ts
│   │   │   ├── ai-pentest/               ← Autonomous AI pentest features
│   │   │   │   ├── orchestrator.ts       ← Multi-phase AI pentest agent
│   │   │   │   ├── verification.ts       ← Safe exploit verification engine
│   │   │   │   ├── patch-generator.ts    ← Auto-patch code generation
│   │   │   │   └── reasoning-chain.ts    ← Explainable AI reasoning
│   │   │   ├── scheduler.ts              ← node-cron: scheduled scans + SLA
│   │   │   └── email.ts                  ← Nodemailer email service
│   │   ├── middlewares/
│   │   │   ├── rbac.ts                   ← requireAuth, requireRole, requireAdmin
│   │   │   ├── apikey.ts                 ← X-API-Key header authentication
│   │   │   └── ip-allowlist.ts           ← IP whitelist middleware
│   │   ├── lib/
│   │   │   ├── db.ts                     ← MongoDB connection + in-memory fallback
│   │   │   ├── logger.ts                 ← Pino logger singleton
│   │   │   ├── schema.ts                 ← DB schema creation & migrations
│   │   │   ├── seed.ts                   ← Default admin + demo data seeder
│   │   │   └── audit.ts                  ← Audit log helper
│   │   └── api-zod/                      ← Generated Zod validation schemas
│   ├── Dockerfile
│   ├── build.mjs                         ← esbuild production bundler
│   ├── package.json
│   └── tsconfig.json
│
├── frontend/                             ← All frontend code
│   ├── src/
│   │   ├── main.tsx                      ← React entry point
│   │   ├── App.tsx                       ← Root router (Wouter) + ThemeProvider
│   │   ├── index.css                     ← Global styles + 3-theme design system
│   │   ├── pages/                        ← 31 page components
│   │   │   ├── landing.tsx               ← Public landing page
│   │   │   ├── login.tsx                 ← Split-panel user auth
│   │   │   ├── admin-login.tsx           ← Dedicated admin login portal
│   │   │   ├── admin-panel.tsx           ← Admin dashboard (new)
│   │   │   ├── dashboard.tsx             ← Main KPI dashboard
│   │   │   ├── scans.tsx, scan-detail.tsx, new-scan.tsx
│   │   │   ├── scan-compare.tsx, scan-templates.tsx
│   │   │   ├── findings.tsx, finding-detail.tsx
│   │   │   ├── targets.tsx, target-detail.tsx
│   │   │   ├── remediations.tsx
│   │   │   ├── executive.tsx, attack-surface.tsx
│   │   │   ├── owasp.tsx, timeline.tsx
│   │   │   ├── compliance-dashboard.tsx, sla-dashboard.tsx
│   │   │   ├── cvss.tsx, ai-triage.tsx
│   │   │   ├── audit-log.tsx, integrations.tsx, settings.tsx
│   │   │   ├── system.tsx, admin-users.tsx, notifications.tsx
│   │   │   └── forgot-password.tsx, reset-password.tsx, not-found.tsx
│   │   ├── components/
│   │   │   ├── layout.tsx               ← App shell: sidebar + header + auth guard
│   │   │   ├── command-palette.tsx      ← ⌘K global search
│   │   │   ├── command-search.tsx       ← Full-text search component
│   │   │   └── ui/                      ← 19 shadcn/ui components
│   │   │       ├── button.tsx, card.tsx, badge.tsx, input.tsx
│   │   │       ├── select.tsx, dialog.tsx, tabs.tsx
│   │   │       ├── alert.tsx, progress.tsx, switch.tsx, checkbox.tsx
│   │   │       ├── textarea.tsx, label.tsx, radio-group.tsx, slider.tsx
│   │   │       ├── dropdown-menu.tsx, tooltip.tsx
│   │   │       └── toast.tsx, toaster.tsx
│   │   ├── hooks/
│   │   │   ├── use-toast.ts             ← Toast notification hook
│   │   │   └── use-notifications.ts     ← Real-time notification system
│   │   ├── lib/
│   │   │   ├── utils.ts                 ← cn() helper (clsx + tailwind-merge)
│   │   │   ├── sla.ts                   ← getSlaStatus() — SLA deadline calculator
│   │   │   └── markdown.tsx             ← MarkdownContent renderer for AI output
│   │   └── api-client/                  ← Generated React Query hooks
│   │       ├── index.ts                 ← Re-exports
│   │       ├── custom-fetch.ts          ← Authenticated fetch wrapper
│   │       └── generated/
│   │           ├── api.ts               ← All API hooks (useGetMe, useListScanJobs, etc.)
│   │           └── api.schemas.ts        ← TypeScript types
│   ├── public/                           ← Static assets
│   ├── index.html                        ← SPA entry HTML
│   ├── nginx.conf                        ← Production nginx config
│   ├── Dockerfile
│   ├── vite.config.ts                    ← Vite config + dev proxy
│   ├── components.json                   ← shadcn/ui config
│   ├── package.json
│   └── tsconfig.json
│
├── config/                               ← Grafana dashboards (Docker reference)
├── docker-compose.yml                    ← Full stack orchestration
├── pnpm-workspace.yaml                   ← Monorepo workspace config
├── tsconfig.base.json                    ← Shared TypeScript config
├── tsconfig.json                         ← Root workspace references
├── package.json                          ← Root workspace package
├── .env / .env.example                   ← Environment variables
├── .gitignore / .dockerignore / .npmrc
└── README.md / MASTER.md                 ← Documentation
```

---

## 4. How the Application Works

### Authentication Flow

```
User arrives at "/"
    │
    ├─ No session? → Landing page (/) shown
    │
    ├─ Clicks "Sign In" → /login
    │    │
    │    ├─ Enters email + password
    │    ├─ POST /api/auth/login → bcrypt.compare(password, hash)
    │    ├─ If admin creds (Waji2156@gmail.com): auto-creates admin user
    │    ├─ Sets session: userId, username, role in MongoDB sessions collection
    │    ├─ Returns { id, username, email, role }
    │    ├─ Frontend: nav(d.role === "admin" ? "/adminW" : "/dashboard")
    │    │
    │    └─ Or clicks "Create Account" tab → POST /api/auth/register
    │         → bcrypt.hash(password, 10) → creates user with role "analyst"
    │
    ├─ Admin login → /admin (separate portal, red-themed)
    │    └─ POST /api/auth/login → checks d.role === "admin"
    │       └─ If yes → nav("/adminW")
    │       └─ If no → logout + error "Access denied"
    │
    └─ AppLayout (sidebar + header) loads for authenticated users
        ├─ GET /api/auth/me → validates session, returns user info
        ├─ No session → redirects to /login
        └─ Theme applied from localStorage or system preference
```

### Scan Lifecycle

```
1. User creates target → POST /api/targets or bulk import
2. User clicks "New Scan" → /scans/new
   ├─ Enters target URL
   ├─ Selects profile: Quick (~15 modules), Standard (~30), Deep (~60)
   ├─ Checks authorization acknowledgment (compliance)
   └─ POST /api/scan-jobs → Creates scan_jobs document (status: "queued")
3. runScanPipeline() executes asynchronously:
   ├─ Updates status → "running"
   ├─ Runs crawl first → discovers endpoints
   ├─ Iterates modules by profile
   ├─ Each finding: deduplication → save → SSE emit
   ├─ Updates progress, severity counts in real-time
   └─ Status → "completed" or "failed"
4. Client watches via SSE:
   ├─ EventSource on /api/stream/:jobId
   ├─ Events: progress, finding, engine_start, complete, error
   └─ New findings slide in with animation
5. After completion:
   ├─ updateTargetAfterScan(): tech stack, subdomains, risk history
   ├─ Slack alert if critical/high findings found
   └─ AI auto-triage runs on all findings
```

### Notification System

```
Scanner discovers finding (severity: critical or high)
    │
    ├─ SSE event emitted to connected clients
    ├─ Client receives event in layout.tsx polling loop
    ├─ Adds to notifications array (stored in memory + localStorage)
    ├─ If not muted + severity === "critical" → AudioContext beep (880Hz)
    ├─ Toast popup shows with "View" button
    ├─ Notification bell badge increments
    └─ Persistent in /notifications page

SLA Breach (via hourly cron):
    ├─ Checks remediations for past-due items
    ├─ Marks sla_breached: true
    └─ Slack alert if configured (danger color for critical)
```

---

## 5. How the Scan Engine Works

### Scanner Architecture

```
POST /api/scan-jobs
    │
    ▼
runScanPipeline(opts) — Main Orchestrator
    │
    ├─ Creates ScanContext { targetUrl, profile, emit, discoveredEndpoints, ... }
    ├─ Selects pipeline based on profile
    │
    ├─ PIPELINE_QUICK (~15 modules):
    │   crawl → tls → headers → cookies → recon → dns → js-secrets →
    │   cve-lookup → fingerprint → infrastructure → passive-recon →
    │   data-exposure → cloud → cors → ports
    │
    ├─ PIPELINE_STANDARD (~30 modules, includes QUICK +):
    │   xss → sqli → redirect → jwt → rate-limit → graphql →
    │   websocket → csrf → oauth → api-advanced → crlf →
    │   prototype-pollution → dep-confusion → grpc → cache-poisoning →
    │   zap → nuclei
    │
    └─ PIPELINE_DEEP (~60 modules, includes STANDARD +):
        auth → auth-advanced → idor → pathtraversal → subdomain-enum →
        wayback → ssti → xxe → file-upload → smuggling →
        business-logic → zap → nuclei
    │
    ▼
For each module:
    │
    ├─ Emit: engine_start → "Running: TLS/HTTPS"
    ├─ Execute module function → returns ScanFinding[]
    ├─ For each finding:
    │   ├─ Deduplicate: check fp_suppressions by domain+title+endpoint
    │   ├─ Save to findings collection with CVSS + OWASP + risk score
    │   ├─ Create remediation for critical/high findings
    │   ├─ Emit SSE: finding event
    │   └─ Update scan_job severity counts
    └─ Update progress percentage (i / totalSteps * 95)
    │
    ▼
After all modules:
    ├─ Calculate final risk score
    ├─ Build quick AI summary
    ├─ Update scan_jobs → status: "completed", progress: 100
    ├─ updateTargetAfterScan()
    │   ├─ Extract tech stack from fingerprint findings (regex)
    │   ├─ Extract subdomains from enum findings
    │   ├─ Append risk_history entry (capped at 10)
    │   └─ Upsert target document
    ├─ Slack alert if GITHUB_TOKEN or SLACK_WEBHOOK_URL configured
    └─ AI auto-triage: scores each finding with AI confidence
```

### All 39 Scanner Modules

| Module | Category | What It Checks |
|--------|----------|----------------|
| `crawl.ts` | Recon | Spider target, discover endpoints, extract forms |
| `recon.ts` | Recon | Sensitive paths (/.git, /admin, /phpinfo, /backup) |
| `passive-recon.ts` | Recon | Wayback Machine history, leaked URLs |
| `subdomains.ts` | Recon | DNS + Wayback Machine subdomain enumeration |
| `tls.ts` | Network | TLS version, cipher suites, certificate expiry, HSTS |
| `headers.ts` | Network | Missing CSP, X-Frame, HSTS, X-Content-Type headers |
| `cookies.ts` | Network | Missing Secure/HttpOnly/SameSite flags |
| `cors.ts` | Network | CORS wildcard origins, credentialed CORS misconfigs |
| `dns.ts` | Network | SPF/DMARC/DNSSEC, zone transfer, subdomain takeover |
| `ports.ts` | Network | Open port scan (21,22,23,25,80,443,3306,5432,etc.) |
| `xss.ts` | Injection | Reflected XSS via parameter injection |
| `sqli.ts` | Injection | SQL injection via error-based + boolean-based probes |
| `injection-advanced.ts` | Injection | SSTI, CRLF injection, prototype pollution |
| `xxe.ts` | Injection | XML External Entity injection |
| `auth.ts` | Auth | Login endpoint discovery, rate limits, default creds |
| `auth-advanced.ts` | Auth | Account enumeration, MFA bypass |
| `jwt.ts` | Auth | Weak secrets, algorithm confusion (none/RS256→HS256) |
| `oauth.ts` | Auth | OAuth flow issues (state, implicit flow, token leaks) |
| `idor.ts` | Auth | Insecure Direct Object Reference via sequential IDs |
| `csrf.ts` | Auth | Missing CSRF tokens on state-changing forms |
| `redirect.ts` | Web | Open redirect via ?redirect=, ?url=, ?next= |
| `pathtraversal.ts` | Web | Directory traversal (../etc/passwd) |
| `file-upload.ts` | Web | Unrestricted file upload, dependency confusion |
| `graphql.ts` | API | GraphQL introspection, batching attacks, NoSQL injection |
| `grpc.ts` | API | gRPC endpoint detection and reflection abuse |
| `api-advanced.ts` | API | Mass assignment, versioning issues, hidden params |
| `smuggling.ts` | Web | HTTP request smuggling (CL-TE, TE-CL) |
| `cache-poisoning.ts` | Web | Web cache poisoning via unkeyed headers |
| `business-logic.ts` | Web | Price manipulation, workflow bypass, privilege escalation |
| `cloud.ts` | Cloud | Metadata endpoints (AWS/GCP/Azure), S3 buckets |
| `infrastructure.ts` | Recon | WAF detection, load balancer fingerprinting |
| `fingerprint.ts` | Recon | Technology stack identification |
| `js-secrets.ts` | Data | API keys, tokens, passwords in JS files |
| `cve-lookup.ts` | Data | Match server banners against known CVEs |
| `data-exposure.ts` | Data | Sensitive data in responses (PII, keys, stack traces) |
| `nuclei.ts` | Scanner | Nuclei template-based scanning |
| `zap.ts` | Scanner | OWASP ZAP active scanner via REST API |

### Pipeline Profile Comparison

```
    QUICK (15 modules)        STANDARD (30)            DEEP (60)
    ─────────────────        ─────────────            ─────────
    crawl                     [all QUICK +]            [all STANDARD +]
    tls                       xss probe                auth/session
    headers                   sqli probe               advanced auth/MFA
    cookies                   open redirect            IDOR
    recon                     JWT security             path traversal
    dns                       rate limit               subdomain enum
    js-secrets                GraphQL                  wayback crawl
    cve-lookup                WebSocket                SSTI
    fingerprint               CSRF                     XXE injection
    infrastructure            OAuth                    file upload
    passive-recon             API version abuse        request smuggling
    data-exposure             CRLF injection           business logic
    cloud                     prototype pollution      zap active scan
    cors                      dep confusion            nuclei templates
    ports                     gRPC detection
                              cache poisoning
                              zap active scan
                              nuclei templates
```

---

## 6. How the AI Works

### AI Infrastructure

```
Backend AI Layer:
├── routes/ai.ts                    ← 18 SSE streaming endpoints
├── services/ai-pentest/            ← Autonomous pentest features
│   ├── orchestrator.ts             ← Multi-phase pentest agent
│   ├── verification.ts             ← Safe exploit verification
│   ├── patch-generator.ts          ← Auto-patch with tech detection
│   └── reasoning-chain.ts          ← Explainable AI reasoning
├── AI Client: OpenAI SDK pointed at OpenCode API
│   ├── baseURL: https://opencode.ai/zen/v1
│   └── model: nemotron-3-super-free (configurable)
└── Shared Utilities:
    ├── aiCache (Map with 1hr TTL, max 200 entries)
    ├── streamWithRetry (exponential backoff, max 2 retries)
    ├── SSE heartbeat (15s keep-alive to prevent Nginx timeout)
    ├── Prompt injection sanitization
    ├── Token usage tracking (logUsage to ai_usage collection)
    └── securityExpertSystem() — shared system prompt persona
```

### All 18 AI Endpoints

| Endpoint | Method | Purpose | Cache Key |
|----------|--------|---------|-----------|
| `/ai/scan-summary/:id` | POST | 3-paragraph executive summary | `scan-summary:${id}` |
| `/ai/finding-advice/:id` | POST | Root cause + step-by-step fix | `finding-advice:${id}` |
| `/ai/chat` | POST | Free-form security chat with history | - |
| `/ai/payloads/:id` | POST | Category-specific attack payloads | `payloads:${id}` |
| `/ai/patch/:id` | POST | Production-ready code patch | `patch:${id}:${tech_stack}` |
| `/ai/executive-narrative/:id` | POST | CISO-level security briefing | `exec-narrative:${id}` |
| `/ai/attack-chain/:scanId` | POST | Multi-step attack chain analysis | `attack-chain:${scanId}` |
| `/ai/poc/:findingId` | POST | Complete PoC with curl + Python script | `poc:${findingId}` |
| `/ai/scan-config` | POST | Natural language → scan config JSON | - |
| `/ai/patch-diff/:findingId` | POST | Unified diff patch | `patch-diff:${findingId}` |
| `/ai/bug-bounty-report/:findingId` | POST | HackerOne/Bugcrowd format report | `bb-report:${findingId}` |
| `/ai/attack-narrative/:findingId` | POST | Hacker-perspective attack story | `attack-narrative:${findingId}` |
| `/ai/tools/:findingId` | POST | Burp, nuclei, CLI tool recommendations | `tools:${findingId}` |
| `/ai/remediation-plan/:scanId` | POST | Sprint-based fix plan with effort estimates | `remediation-plan:${scanId}` |
| `/ai/false-positive/:findingId` | POST | FP analysis with confidence score | `fp-analysis:${findingId}` |
| `/ai/cvss-breakdown/:findingId` | POST | Plain-English CVSS metric explanation | `cvss-breakdown:${findingId}` |
| `/ai/scan-compare/:scanId1/:scanId2` | POST | Delta analysis between two scans | `scan-compare:${scanId1}:${scanId2}` |
| `/ai/deduplicate/:scanId` | POST | AI-powered finding deduplication | - |

### SSE Streaming Architecture

```
Browser                     Express Route               OpenCode API
  │                              │                           │
  │ POST /api/ai/scan-summary    │                           │
  │─────────────────────────────→│                           │
  │                              │ Setup SSE headers         │
  │                              │ Content-Type: text/event-stream
  │                              │ Cache-Control: no-cache   │
  │                              │                           │
  │                              │ Build prompt:             │
  │                              │ - Target URL              │
  │                              │ - All findings            │
  │                              │ - CVSS scores             │
  │                              │ - OWASP categories        │
  │                              │                           │
  │                              │ POST /completions         │
  │                              │ stream: true              │
  │                              │──────────────────────────→│
  │                              │                           │
  │                              │←── chunk: "The scan..."───│
  │←── data: {"content":"The"}──│                           │
  │←── data: {"content":" scan"}│←── chunk: " scan "... ────│
  │←── data: {"content":" of"}─│←── chunk: " of "... ───────│
  │←── data: {"done":true}─────│←── [DONE] ────────────────│
  │                              │                           │
  │  : keep-alive (every 15s)    │                           │
```

### Caching System

```
Request arrives
    │
    ├─ cacheKey generated (e.g., "finding-advice:abc123")
    ├─ Check aiCache.get(cacheKey)
    │   ├─ HIT → serveCachedSse(res, cachedText) → immediate response
    │   └─ MISS → generate AI response
    │              ├─ streamWithRetry() → SSE to client
    │              ├─ aiCache.set(cacheKey, accumulatedText)
    │              └─ logUsage(endpoint, resourceId, text) → ai_usage collection
    │
    └─ Cache eviction:
        ├─ Max 200 entries
        ├─ TTL: 1 hour (60 * 60 * 1000ms)
        └─ LRU: deletes oldest entry when full
```

### Retry Logic (streamWithRetry)

```
Attempt 0: Send request immediately
    ├─ Success → stream tokens → done
    └─ Error (524 timeout, Provider error, ECONNRESET)
        ├─ Wait 2 seconds (delay = 2000 * 2^0)
        └─ Attempt 1...
            ├─ Wait 4 seconds (delay = 2000 * 2^1)
            └─ Attempt 2 (final)
                └─ Fail → throw error to client
```

---

## 7. AI Pentest Features

### Autonomous Pentest Orchestrator

```
Target selected → POST /api/ai/autonomous-pentest/:targetId
    │
    ▼
AutonomousPentestAgent Created
    │
    ├─ Phase 1: PLANNING → AI analyzes attack surface
    │   Emits: "agent-start", "reasoning"
    │
    ├─ Phase 2: RECON → AI probes target, discovers endpoints
    │   Agent thinks: "Found /admin → Let me try default creds"
    │   Emits: "action" (type: recon), "observation" (newEndpoints)
    │
    ├─ Phase 3: EXPLOITING → AI chains vulnerabilities
    │   Agent thinks: "Got access → Now escalate privileges"
    │   Emits: "vulnerability-found" (title, severity, CWE, confidence)
    │
    ├─ Phase 4: VERIFICATION → AI confirms findings
    │   Generates safe PoC payloads
    │
    ├─ Phase 5: CONCLUSION → Reports findings
    │   riskScore: 0-100, vulnerability count
    │   Emits: "session-complete"
    │
    └─ Max 15 iterations (configurable)
```

### Safe Exploit Verification

```
Finding selected → POST /api/ai/verify-finding/:findingId
    │
    ▼
AI analyzes finding evidence
    │
    ├─ Verdict: CONFIRMED | FALSE_POSITIVE | NEEDS_MANUAL
    ├─ Confidence: 0.0 - 1.0 (float)
    ├─ Safe PoC: Never destructive
    │   - SQLi → SLEEP / version()
    │   - XSS → alert(document.domain)
    │   - RCE → ping -c 1 callback.server
    ├─ Exploit Difficulty: trivial | easy | moderate | hard | impossible
    ├─ Estimated Time to Exploit
    └─ Saves to finding: ai_verification { verdict, confidence, reasoning, ... }
```

### Auto-Patch Generator

```
Finding selected → POST /api/ai/generate-patch/:findingId
    │
    ▼
1. Lookup finding details (title, severity, CWE, endpoint, description)
2. Lookup target tech_stack from fingerprint detection
3. Select language-appropriate prompt:
    ├─ node/express → pg parameterized queries, helmet, express-validator
    ├─ python/django → SQLAlchemy, Django ORM, python-dotenv
    ├─ java/spring → PreparedStatement, Spring Security, ESAPI
    ├─ php/laravel → Eloquent ORM, Laravel Sanctum, prepared statements
    ├─ go → database/sql, gorilla/csrf, crypto/rand
    └─ default → Generic OWASP best practices
4. AI generates:
    ├─ Vulnerable code (language-tagged)
    ├─ Fixed code (language-tagged with inline comments)
    ├─ Unified diff (```diff block)
    ├─ Security unit test
    ├─ Deployment checklist
    └─ References (CWE links, OWASP cheat sheets, CVEs)
5. Saves to finding: ai_patch { vulnerable_code, patched_code, diff, language }
```

### Explainable AI Reasoning Chain

```
Finding selected → POST /api/ai/reasoning-chain/:findingId
    │
    ▼
AI generates 5-step reasoning chain:
    │
    ├─ Step 1: DISCOVERY
    │   "How would an attacker find this? What recon technique?"
    │
    ├─ Step 2: CONFIRMATION
    │   "How do you confirm it's real, not a false positive?"
    │
    ├─ Step 3: EXPLOITATION MECHANISM
    │   "What happens at code level? What security control is missing?"
    │
    ├─ Step 4: IMPACT ASSESSMENT
    │   "Worst case: data exposure, RCE, privilege escalation?"
    │
    └─ Step 5: ATTACK CHAIN
        "How does this fit into a larger attack chain?"
    │
    ▼
Additional metadata:
    ├─ MITRE ATT&CK TTPs (T1190, T1059, T1078, etc.)
    ├─ Similar CVEs (2-3 matched)
    ├─ Root Cause (specific code/arch flaw, not generic)
    ├─ Fix Complexity (trivial | simple | moderate | complex | architectural)
    ├─ Estimated Fix Time (realistic engineering hours)
    ├─ Business Impact (financial, reputational, regulatory)
    └─ Prevention Pattern (CI/CD check, library adoption)
```

---

## 8. Database Design

### Collections & Schema

```
┌──────────────────────────────────────────────────────────────┐
│ users                                                        │
├──────────────────────────────────────────────────────────────┤
│ _id: ObjectId      username: string     email: string         │
│ password: bcrypt   role: admin|analyst|viewer                 │
│ first_name: string last_name: string                          │
│ avatar_url: string|null     two_fa_enabled: bool              │
│ totp_secret: string|null    api_key: string|null              │
│ oauth_provider: google|github|null                            │
│ created_at: Date    updated_at: Date    last_login: Date       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ scan_jobs                                                    │
├──────────────────────────────────────────────────────────────┤
│ _id: ObjectId      target_url: string                         │
│ scan_profile: quick|standard|deep                             │
│ status: queued|running|completed|failed|cancelled|paused      │
│ progress: 0-100    risk_score: 0-100                          │
│ findings_count: int  critical_count: int  high_count: int    │
│ medium_count: int   low_count: int      info_count: int       │
│ validation_enabled: bool  fuzzing_enabled: bool               │
│ bug_bounty_mode: bool  authorization_acknowledged: bool       │
│ ai_summary: string|null  error_message: string|null           │
│ created_at: Date  started_at: Date  completed_at: Date        │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ findings                                                     │
├──────────────────────────────────────────────────────────────┤
│ _id: ObjectId      scan_job_id: ObjectId                      │
│ title: string      severity: critical|high|medium|low|info   │
│ category: string   endpoint: string                           │
│ description: string  evidence: string  recommended_fix: string│
│ cvss_score: float  cwe_id: string                             │
│ validation_status: real|false_positive|needs_review            │
│ scanner_name: string  scanner_family: string                  │
│ target_url: string  confidence: float                         │
│ cve_enrichment: []  ai_verification: { verdict, confidence }   │
│ ai_patch: { vulnerable_code, patched_code, diff }              │
│ ai_reasoning_chain: { steps, attackPath, mitreTtps, rootCause }│
│ created_at: Date  resolved_at: Date|null                      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ targets                                                      │
├──────────────────────────────────────────────────────────────┤
│ _id: ObjectId      url: string       domain: string           │
│ risk_score: 0-100  total_scans: int  total_findings: int     │
│ critical_findings: int  high_findings: int                    │
│ status: active|inactive                                       │
│ tags: string[]     tech_stack: string[]                       │
│ subdomains: string[]                                          │
│ risk_history: [{ score: int, date: string }]  (capped at 10)  │
│ last_scanned: Date  created_at: Date  updated_at: Date        │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ remediations                                                 │
├──────────────────────────────────────────────────────────────┤
│ _id: ObjectId      finding_id: ObjectId|null                  │
│ scan_job_id: ObjectId|null                                   │
│ title: string      description: string                        │
│ patch_snippet: string|null                                    │
│ status: pending|in_progress|completed|accepted_risk           │
│ created_at: Date   updated_at: Date                           │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Additional Collections                                       │
├──────────────────────────────────────────────────────────────┤
│ sessions          ← connect-mongo session store (auto)       │
│ settings          ← Platform config (AI model, SMTP, etc.)   │
│ activity_events   ← Scan start/complete, finding created     │
│ audit_log         ← User actions (login, scan, update)       │
│ fp_suppressions   ← False positive suppression rules         │
│ sla_exceptions    ← SLA extension requests                   │
│ compliance_attestations ← Manual control attestations        │
│ webhooks          ← Outbound webhook configurations          │
│ scheduled_scans   ← Cron-based recurring scans               │
│ password_resets   ← Password reset tokens                    │
│ ai_usage          ← Token usage tracking                     │
│ comments          ← Finding discussion threads               │
└──────────────────────────────────────────────────────────────┘
```

### In-Memory Fallback Database

When `MONGODB_URI` is not set, the API uses an in-memory database with:
- Full `findOne`, `find`, `insertOne`, `updateOne`, `deleteOne`, `countDocuments` support
- ObjectId generation and comparison
- `$regex`, `$in`, `$gte`, `$lte`, `$ne` query operators
- Data resets on server restart (demo/development only)

---

## 9. Design System

### Color Palette

| Token | Dark Theme | Light Theme | Usage |
|-------|-----------|------------|-------|
| `background` | `#0a0a0f` | `#f7f7f8` | Page background |
| `foreground` | `#e8e8ef` | `#18181b` | Primary text |
| `card` | `#111118` | `#ffffff` | Card surfaces |
| `sidebar` | `#08080c` | `#fafafa` | Navigation sidebar |
| `border` | `#1e1e2e` | `#e4e4e7` | Borders, dividers |
| `primary` | `#7c3aed` | `#7c3aed` | Buttons, active states |
| `muted` | `#1e1e2e` | `#f4f4f5` | Secondary backgrounds |
| `muted-foreground` | `#6b6b80` | `#71717a` | Secondary text |

### Severity Colors

| Severity | Dark Theme | Light Theme | Hex |
|----------|-----------|------------|-----|
| Critical | Neon red | Deep red | `#ef4444` |
| High | Neon orange | Deep orange | `#f97316` |
| Medium | Neon yellow | Deep amber | `#eab308` |
| Low | Neon cyan | Deep teal | `#22d3ee` |
| Info | Neon green | Deep green | `#34d399` |

### Typography

| Level | Size | Weight | Font |
|-------|------|--------|------|
| Hero | 48px | 900 | Inter |
| H1 | 32px | 700 | Inter |
| H2 | 24px | 600 | Inter |
| H3 | 18px | 600 | Inter |
| Body | 14px | 400 | Inter |
| Small | 12px | 500 | Inter |
| Micro | 10px | 600 | Inter |
| Code | 13px | 400 | Space Mono |

### Component Patterns

```
BUTTONS:
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  bg: #7c3aed     │  │  bg: muted       │  │  bg: transparent │
│  text: white     │  │  text: fg        │  │  text: primary   │
│  class: primary  │  │  class: outline  │  │  class: ghost    │
└──────────────────┘  └──────────────────┘  └──────────────────┘

BADGES:
  [CRITICAL]  bg: #ef4444/10  text: #ef4444  border: #ef4444/30
  [HIGH]      bg: #f97316/10  text: #f97316  border: #f97316/30
  [MEDIUM]    bg: #eab308/10  text: #eab308  border: #eab308/30
  [LOW]       bg: #22d3ee/10  text: #22d3ee  border: #22d3ee/30

CARDS:
  bg: hsl(var(--card))  border: 1px solid hsl(var(--border))
  radius: 6px (rounded-md) or 12px (rounded-xl)
  shadow: 0 1px 3px rgba(0,0,0,0.3)

INPUTS:
  bg: rgba(255,255,255,0.04)  border: 1px solid rgba(255,255,255,0.08)
  radius: 12px  padding: 14px  focus: border-color → purple
```

### 3-Theme System

```
┌─────────────────┬──────────────────┬────────────────────┐
│ DARK (default)   │ LIGHT            │ HIGH CONTRAST      │
├─────────────────┼──────────────────┼────────────────────┤
│ bg: deep black  │ bg: white-gray  │ bg: pure black     │
│ Cards: elevated │ Cards: white     │ Cards: near-black  │
│ Neon severity   │ Deep severity    │ Max saturation     │
│ Cyberpunk vibe  │ Clean/professional│ Accessibility      │
└─────────────────┴──────────────────┴────────────────────┘

Switch: Press "T" or click theme icon in header
Storage: localStorage key "theme"
Transition: 200ms smooth color transition
```

### Spacing Scale

| Token | Size | Usage |
|-------|------|-------|
| `xs` | 4px | Tight internal padding, icon gaps |
| `sm` | 8px | Button padding, small gaps |
| `md` | 16px | Card padding, section gaps |
| `lg` | 24px | Page padding (p-6), major separations |
| `xl` | 32px | Hero sections |

### Z-Index Scale

| Layer | z-index | Element |
|-------|---------|---------|
| Content | 0 | Page content, cards |
| Elevated | 10 | Sticky headers, sidebars |
| Overlay | 500 | Modals, backdrops |
| Dropdown | 1000 | Menus, tooltips, popovers |
| Toast | 9999 | Toast notifications |
| Command | 10000 | ⌘K command palette |

---

## 10. API Reference

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/register` | None | Register new account (role: analyst) |
| `POST` | `/api/auth/login` | None | Login with email/password |
| `POST` | `/api/auth/logout` | Session | Destroy session |
| `GET` | `/api/auth/me` | Session | Current user info |
| `POST` | `/api/auth/demo` | None | Auto-create demo admin |
| `PATCH` | `/api/auth/profile` | Session | Update profile |
| `POST` | `/api/auth/forgot-password` | None | Send reset email |
| `POST` | `/api/auth/reset-password` | None | Reset with token |

### Scan Jobs

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/scan-jobs` | Session | List all scans |
| `POST` | `/api/scan-jobs` | Session | Create scan |
| `GET` | `/api/scan-jobs/:id` | Session | Get scan details |
| `DELETE` | `/api/scan-jobs/:id` | Session | Delete scan |
| `GET` | `/api/scan-jobs/:id/findings` | Session | Get scan findings |
| `GET` | `/api/scan-jobs/:id/stream` | None | SSE stream |
| `GET` | `/api/scan-jobs/:id/attack-surface` | Session | Attack surface graph |
| `GET` | `/api/scan-jobs/:id/diff` | Session | Scan comparison |
| `GET` | `/api/scan-jobs/:id/kill-chains` | Session | Kill chain analysis |
| `POST` | `/api/scan-jobs/:id/cancel` | Session | Cancel running scan |
| `POST` | `/api/scan-jobs/:id/pause` | Session | Pause running scan |
| `POST` | `/api/scan-jobs/:id/resume` | Session | Resume paused scan |

### Findings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/findings` | Session | List findings (filterable) |
| `GET` | `/api/findings/:id` | Session | Get finding |
| `PATCH` | `/api/findings/:id` | Session | Update finding (status, FP) |
| `DELETE` | `/api/findings/:id` | Session | Delete finding |
| `GET` | `/api/findings/:id/cve` | Session | CVE enrichment |
| `POST` | `/api/findings/:id/retest` | Session | Retest finding |
| `POST` | `/api/findings/:id/assign` | Session | Assign to engineer |
| `GET` | `/api/findings/export/:format` | Session | Export as JSON/CSV |
| `GET` | `/api/fp-suppressions` | Session | List FP suppressions |
| `DELETE` | `/api/fp-suppressions/:id` | Session | Remove FP suppression |

### Targets

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/targets` | Session | List targets |
| `GET` | `/api/targets/:id` | Session | Get target |
| `POST` | `/api/targets/bulk-import` | Session | Bulk import URLs |
| `PATCH` | `/api/targets/:id/tags` | Session | Update tags |
| `GET` | `/api/targets/:id/risk-trend` | Session | Risk trend chart |
| `GET` | `/api/targets/:id/recurring-findings` | Session | Recurring findings |

### Remediations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/remediations` | Session | List remediations |
| `POST` | `/api/remediations` | Session | Create remediation |
| `GET` | `/api/remediations/:id` | Session | Get remediation |
| `PATCH` | `/api/remediations/:id` | Session | Update status |

### SLA

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/sla/summary` | None | SLA status: on_track/at_risk/breached |
| `GET` | `/api/sla/finding/:id` | None | SLA info for finding |
| `POST` | `/api/sla/finding/:id/resolve` | None | Mark finding resolved |
| `GET` | `/api/sla/velocity` | None | Avg time-to-fix by severity |
| `GET` | `/api/sla/heatmap` | None | Breach density by day |
| `GET` | `/api/sla/burn-down` | None | Weekly SLA trends |
| `GET` | `/api/sla/exceptions` | None | List extension requests |
| `POST` | `/api/sla/exceptions` | None | Request extension |
| `PATCH` | `/api/sla/exceptions/:id` | None | Approve/deny extension |

### AI

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/ai/scan-summary/:id` | None | Executive scan summary (SSE) |
| `POST` | `/api/ai/finding-advice/:id` | None | Remediation guidance (SSE) |
| `POST` | `/api/ai/chat` | None | Free-form security chat (SSE) |
| `POST` | `/api/ai/payloads/:id` | None | Attack payloads (SSE) |
| `POST` | `/api/ai/patch/:id` | None | Code patch (SSE) |
| `POST` | `/api/ai/patch-diff/:id` | None | Unified diff (SSE) |
| `POST` | `/api/ai/poc/:id` | None | Proof of concept (SSE) |
| `POST` | `/api/ai/attack-chain/:scanId` | None | Attack chain analysis (SSE) |
| `POST` | `/api/ai/executive-narrative/:id` | None | CISO briefing (SSE) |
| `POST` | `/api/ai/remediation-plan/:scanId` | None | Sprint fix plan (SSE) |
| `POST` | `/api/ai/scan-compare/:id1/:id2` | None | Scan delta analysis (SSE) |
| `POST` | `/api/ai/false-positive/:id` | None | FP analysis (SSE) |
| `POST` | `/api/ai/cvss-breakdown/:id` | None | CVSS explanation (SSE) |
| `POST` | `/api/ai/bug-bounty-report/:id` | None | BB report (SSE) |
| `POST` | `/api/ai/attack-narrative/:id` | None | Attack story (SSE) |
| `POST` | `/api/ai/tools/:id` | None | Tool recommendations (SSE) |
| `POST` | `/api/ai/deduplicate/:scanId` | None | AI dedup (JSON) |
| `POST` | `/api/ai/scan-config` | None | NL→config (JSON) |

### AI Pentest (New)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/ai/autonomous-pentest/:targetId` | Session | Full autonomous pentest (SSE) |
| `POST` | `/api/ai/verify-finding/:findingId` | Session | Safe exploit verification (SSE) |
| `POST` | `/api/ai/generate-patch/:findingId` | Session | Production-ready patch (SSE) |
| `POST` | `/api/ai/reasoning-chain/:findingId` | Session | Explainable AI reasoning (SSE) |

### Compliance

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/compliance/report` | None | OWASP/PCI/SOC2/ISO report |
| `GET` | `/api/compliance/findings/:id` | None | Compliance tags for finding |
| `GET` | `/api/compliance/history` | None | Weekly compliance trend |
| `GET` | `/api/compliance/owasp/findings/:catId` | None | Findings by OWASP category |
| `GET` | `/api/compliance/attestations` | None | Control attestations |
| `POST` | `/api/compliance/attestations` | None | Create attestation |
| `DELETE` | `/api/compliance/attestations/:id` | None | Delete attestation |
| `GET` | `/api/compliance/export/:framework` | None | Export audit pack |

### Other

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/dashboard/stats` | None | Dashboard KPIs |
| `GET` | `/api/dashboard/activity` | None | Recent activity feed |
| `GET` | `/api/attack-surface` | Session | Global attack surface |
| `GET` | `/api/stream/:id` | None | Scan SSE stream (alias) |
| `GET` | `/api/settings` | None | Get platform settings |
| `PUT` | `/api/settings` | Admin | Update platform settings |
| `GET` | `/api/admin/users` | Admin | List users |
| `PATCH` | `/api/admin/users/:id` | Admin | Update user role |
| `DELETE` | `/api/admin/users/:id` | Admin | Delete user |
| `GET` | `/api/admin/stats` | Admin | Admin dashboard stats |
| `GET` | `/api/healthz` | None | Health check |

---

## 11. Frontend Architecture

### Routing (Wouter)

```
/                          → Landing (public)
/login                     → Login (public, no demo/admin links)
/admin                     → AdminLogin (separate portal)
/adminW                    → AdminPanel (AdminRoute guard)
/forgot-password           → ForgotPassword (public)
/reset-password            → ResetPassword (public)

─── AppLayout (authenticated sidebar + header) ───

/dashboard                 → Dashboard
/scans/new                 → NewScan
/scans/compare             → ScanCompare
/scans/:id                 → ScanDetail (SSE stream)
/scans                     → Scans
/findings/:id              → FindingDetail (Tabs: verify, reasoning, patch-gen)
/findings                  → Findings
/targets/:id               → TargetDetail (AI Pentest button)
/targets                   → Targets
/remediations              → Remediations
/executive                 → Executive
/attack-surface            → AttackSurface
/owasp                     → OWASPPage
/timeline                  → Timeline
/compliance                → ComplianceDashboard
/sla                       → SlaDashboard
/ai-triage                 → AiTriage
/scan-templates            → ScanTemplates
/cvss                      → CVSSCalculator
/settings                  → Settings
/system                    → System
/notifications             → Notifications
/integrations              → Integrations (AdminRoute)
/audit-log                 → AuditLog (AdminRoute)
/admin/users               → AdminUsers (AdminRoute)
```

### Data Fetching Pattern

```ts
// Generated API hooks (frontend/src/api-client/generated/api.ts)
// Auto-generated from OpenAPI spec via Orval

// Query example:
const { data: scans, isLoading } = useListScanJobs({ status: "running" });

// Mutation example:
const createScan = useCreateScanJob({
  onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/scan-jobs"] }),
});

// Native fetch for SSE (AI endpoints):
const reader = res.body.getReader();
const decoder = new TextDecoder();
// Parse "data: {...}" lines, accumulate text, render with MarkdownContent
```

### Navigation Groups (Sidebar)

```
CORE:          Dashboard, Scans, Findings, Targets, Remediations
ANALYTICS:     Executive, Attack Surface, OWASP Top 10, Timeline, Compliance, SLA
AI & TOOLS:    AI Triage, Scan Compare, Templates, CVSS Calc
CONFIG:        Integrations, Audit Log, System, Settings, User Management
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `⌘K` / `Ctrl+K` | Open Command Palette |
| `/` | Open Command Palette |
| `N` | Navigate to New Scan |
| `F` | Navigate to Findings |
| `R` | Navigate to Remediations |
| `T` | Cycle Theme |
| `Esc` | Close modals/dropdowns |

---

## 12. Authentication & RBAC

### Session Management

```
Session config:
├─ name: "bbp.sid" (httpOnly cookie)
├─ store: MongoDB (connect-mongo, collection: sessions)
├─ TTL: 7 days
├─ sameSite: lax
├─ secret: SESSION_SECRET env var (min 32 chars recommended)
└─ secure: true in production (NODE_ENV === "production")
```

### Default Admin Auto-Creation

```
Login with email "Waji2156@gmail.com" and password "Waji2156.."
    │
    ├─ FindOne({ email }) → not found
    ├─ Check: email === DEFAULT_ADMIN_EMAIL && password === DEFAULT_ADMIN_PASSWORD
    ├─ TRUE → auto-create user:
    │   { username: "waji_admin", email, password: bcrypt hash, role: "admin" }
    ├─ Set session: userId, username, role
    └─ Return: { id, username, email, role: "admin" }
```

### Role Permissions

| Role | Permissions |
|------|-------------|
| `admin` | Full access: user management, settings, audit log, integrations, all data |
| `analyst` | Create/run scans, manage findings, create remediations, view all data |
| `viewer` | Read-only access to all data (future) |

### Admin-Only Routes (Frontend)

```tsx
function AdminRoute({ component: Component }) {
  const { data: user } = useGetMe();
  if (user?.role !== "admin") { nav("/admin"); return null; }
  return <Component />;
}
```

### Admin-Only Routes (Backend)

```ts
// requireAdmin middleware checks session.role === "admin"
router.get("/admin/users", requireAdmin, ...);
router.get("/admin/stats", requireAdmin, ...);
```

---

## 13. Deployment & Infrastructure

### Docker Compose Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `mongodb` | mongo:7-jammy | 27017 | Primary database |
| `redis` | redis:7-alpine | 6379 | Caching, rate limiting |
| `zap` | ghcr.io/zaproxy/zaproxy:stable | 8080 (8090) | Active scanner |
| `api-server` | node:20-alpine (build) | 5000 | Express backend |
| `frontend` | nginx:alpine (build) | 3000 | Static SPA + API proxy |
| `mongo-backup` | mongo:7-jammy | - | Daily mongodump, 7-day retention |
| `loki` | grafana/loki:2.9.0 | 3100 | Log aggregation |
| `grafana` | grafana/grafana:10.2.0 | 3001 | Log visualization |

### Running the Application

```bash
# Full Docker deployment
docker-compose up -d --build
# App: http://localhost:3000
# API: http://localhost:5000/api/healthz
# Grafana: http://localhost:3001

# Development mode (without Docker)
# Terminal 1: Backend
cd backend && npm run dev
# Terminal 2: Frontend (with API proxy)
cd frontend && npx vite --port 5173
# Frontend: http://localhost:5173 (proxies /api/* to :5000)
```

### Default Credentials

| Field | Value |
|-------|-------|
| Email | `Waji2156@gmail.com` |
| Password | `Waji2156..` |
| Role | `admin` |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGODB_URI` | No | MongoDB connection string (in-memory fallback if not set) |
| `SESSION_SECRET` | No | Session signing secret |
| `OPENCODE_API_KEY` | No | OpenCode API key for AI features |
| `OPENCODE_API_BASE` | No | OpenCode API base URL (default: https://opencode.ai/zen/v1) |
| `OPENCODE_MODEL` | No | AI model (default: nemotron-3-super-free) |
| `GITHUB_TOKEN` | No | GitHub PAT for issue creation |
| `SLACK_WEBHOOK_URL` | No | Slack webhook for alerts |
| `SMTP_HOST/PORT/USER/PASS/FROM` | No | Email configuration |
| `NODE_ENV` | No | production/development |
| `PORT` | No | API server port (default: 5000) |
| `ZAP_URL` | No | OWASP ZAP URL (default: http://zap:8080) |

---

*Complete Application Design — Bug Finder Pro v1.0*
