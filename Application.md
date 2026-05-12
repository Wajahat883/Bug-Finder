# Bug Finder Pro — Complete Application Documentation

> **Stack:** Express.js · MongoDB · React · Vite · TanStack Query · Wouter · Tailwind CSS · OpenAI-compatible AI API  
> **Architecture:** pnpm monorepo · esbuild backend build · Vite frontend build · SSE real-time streaming  
> **Scale:** 176 TypeScript files · 39+ scanner modules · 18 AI endpoints · 42 frontend pages

---

## Table of Contents

1. [Overview](#1-overview)
2. [Project Structure](#2-project-structure)
3. [Backend Architecture](#3-backend-architecture)
4. [Scanner Engine](#4-scanner-engine)
5. [AI System](#5-ai-system)
6. [Frontend Architecture](#6-frontend-architecture)
7. [All Pages](#7-all-pages)
8. [Database Collections](#8-database-collections)
9. [Authentication & Security](#9-authentication--security)
10. [Real-Time Streaming (SSE)](#10-real-time-streaming-sse)
11. [SLA & Scheduler System](#11-sla--scheduler-system)
12. [Integrations & Webhooks](#12-integrations--webhooks)
13. [API Reference](#13-api-reference)
14. [How a Scan Works End-to-End](#14-how-a-scan-works-end-to-end)
15. [Environment Variables](#15-environment-variables)

---

## 1. Overview

Bug Finder Pro is an enterprise-grade web application vulnerability scanner and security operations platform. Users add target URLs, run automated scans using 39+ modules, receive AI-powered remediation advice, track findings through SLA deadlines, and generate executive reports — all in one platform.

**Core capabilities:**
- Automated multi-module vulnerability scanning (Quick / Standard / Deep profiles)
- Real-time scan progress and findings streamed via Server-Sent Events (SSE)
- AI analysis using an OpenAI-compatible API (OpenCode / nemotron-3-super-free model)
- CVSS 3.1 scoring, CWE classification, OWASP Top 10 mapping
- SLA enforcement with automated deadline tracking and breach alerts
- GitHub issue creation, Slack alerts, webhook delivery with HMAC signing
- Engagement management grouping targets/scans/findings into pentest projects
- Executive dashboards, compliance mapping (PCI-DSS, HIPAA, SOC2), SARIF export
- Role-based access control (Admin / Analyst / Viewer)
- Full audit logging of all user actions

---

## 2. Project Structure

```
Bug-Finder/
├── backend/                    # Express.js API server
│   ├── src/
│   │   ├── index.ts            # Server entry point
│   │   ├── app.ts              # Express app factory
│   │   ├── routes/             # 29 route files (mounted at /api)
│   │   ├── services/           # Business logic
│   │   │   ├── scanner/        # 39+ scanner modules
│   │   │   ├── ai-pentest/     # AI orchestration
│   │   │   ├── monitor/        # Attack surface monitor
│   │   │   └── queue/          # Job queue manager
│   │   ├── middlewares/        # Auth, RBAC, rate limiting, IP allowlist
│   │   ├── lib/                # DB, logger, audit, seed, schema
│   │   └── api-zod/            # Zod validation schemas
│   ├── build.mjs               # esbuild production build script
│   └── package.json
│
├── frontend/                   # React SPA
│   ├── src/
│   │   ├── main.tsx            # React DOM root
│   │   ├── App.tsx             # Router (35+ routes)
│   │   ├── pages/              # 42 page components
│   │   ├── components/         # Layout, UI primitives, wizard
│   │   ├── api-client/         # Auto-generated TanStack Query hooks
│   │   ├── hooks/              # Toast, notifications
│   │   └── lib/                # Utils, SLA helpers, markdown
│   ├── public/                 # Static assets (robot.jpg, etc.)
│   └── package.json
│
├── node_modules/               # pnpm workspace shared modules
├── pnpm-workspace.yaml
└── Application.md              # This file
```

---

## 3. Backend Architecture

### 3.1 Entry Point — `backend/src/index.ts`
Starts the HTTP server on `process.env.PORT`. Calls `connectDb()` for MongoDB, then `initScheduler()` for cron jobs, then listens.

### 3.2 App Factory — `backend/src/app.ts`
Sets up the full Express pipeline in order:
1. `pino-http` request logging
2. `cors` with configurable origins
3. `express.json()` body parser
4. `cookie-parser`
5. `express-session` with `connect-mongo` store (sessions stored in MongoDB `sessions` collection)
6. `globalLimiter` — rate limiter applied to all routes
7. `ipAllowlistMiddleware` — blocks IPs not on allowlist (if configured)
8. `apiKeyAuth` — allows API key in `X-API-Key` header as alternative to session auth
9. All API routes mounted at `/api`
10. Global error handler

### 3.3 Core Libraries

| File | Purpose |
|------|---------|
| `lib/db.ts` | MongoDB connection via `mongoose`/`mongodb` driver. Exports `col(name)` helper returning a collection. Falls back to an in-memory implementation when `MONGODB_URI` is not set (dev/test). Supports: `find`, `findOne`, `insertOne`, `insertMany`, `updateOne`, `updateMany`, `deleteOne`, `deleteMany`, `countDocuments`, `aggregate`. |
| `lib/logger.ts` | Pino structured logger. Redacts `authorization` and `cookie` headers. Used everywhere via `import { logger } from "../lib/logger"`. |
| `lib/audit.ts` | Records every sensitive action (login, scan start, finding update, user delete, etc.) to the `audit_log` collection with: `userId`, `username`, `action`, `resource`, `resourceId`, `ip`, `userAgent`, `timestamp`, `details`. |
| `lib/seed.ts` | Seeds demo data (demo user, sample targets, findings) for development and demo logins. |

### 3.4 Middleware

| File | Middleware | What it does |
|------|-----------|-------------|
| `middlewares/rbac.ts` | `requireAuth` | Returns 401 if no session `userId`. Used on all protected routes. |
| `middlewares/rbac.ts` | `requireRole(...roles)` | Returns 403 if session `role` not in allowed list. |
| `middlewares/rbac.ts` | `requireAdmin` | Shorthand for `requireRole("admin")`. |
| `middlewares/apikey.ts` | `apiKeyAuth` | Reads `X-API-Key` header, looks up in `api_keys` collection, injects synthetic session if valid. |
| `middlewares/rate-limit.ts` | `globalLimiter` | 500 req/15min per IP global cap. |
| `middlewares/ip-allowlist.ts` | `ipAllowlistMiddleware` | Reads allowlist from `settings` collection; bypassed if empty. |

Specific route-level limiters are also defined in `routes/ai.ts`:
- `authLimiter` — 20 req/15min on login/register
- `aiLimiter` — 30 req/min on AI endpoints
- `scanLimiter` — 10 concurrent scan starts per IP

### 3.5 Routes Index — `backend/src/routes/index.ts`
Mounts every router at `/api`:

```
/api/auth              → auth.ts
/api/scan-jobs         → scans.ts
/api/findings          → findings.ts
/api/targets           → targets.ts
/api/remediations      → remediations.ts
/api/dashboard         → dashboard.ts
/api/analytics         → analytics.ts
/api                   → analytics-metrics.ts  (metrics/*, analytics/*)
/api/reports           → reports.ts
/api/compliance        → compliance.ts
/api/sla               → sla.ts
/api/ai                → ai.ts
/api/scheduled-scans   → scheduled-scans.ts
/api/report-schedules  → report-schedules.ts
/api/webhooks          → webhooks.ts
/api/webhook-log       → webhook-log.ts
/api/integrations      → integrations.ts
/api/audit-log         → auditlog.ts
/api/settings          → settings.ts
/api/notifications     → notifications.ts
/api/comments          → comments.ts
/api/certs             → certs.ts
/api/search            → search.ts
/api/risk-trend        → risk-trend.ts
/api/dashboard-layout  → dashboard-layout.ts
/api/scanner-rules     → scanner-rules.ts
/api/engagements       → engagements.ts
/api/stream            → stream.ts
/api/scan-templates    → scan-templates.ts
/api/comparison        → comparison.ts
/api                   → health.ts  (/healthz, /healthz/ai)
```

---

## 4. Scanner Engine

### 4.1 How the Scanner Works

When a scan job starts, `backend/src/services/scanner/index.ts` is the orchestrator. It:

1. Reads the scan profile (`quick` / `standard` / `deep`)
2. Selects the appropriate pipeline of modules
3. Creates a `ScanContext` object passed to every module
4. Runs modules sequentially (some in parallel batches)
5. Each module emits `ScanFinding[]` and progress events
6. Findings are saved to MongoDB `findings` collection in real time
7. SSE pushes each finding to any connected frontend clients

### 4.2 ScanContext Object

```typescript
interface ScanContext {
  targetUrl: string;               // The URL being scanned
  profile: "quick" | "standard" | "deep";
  scanJobId: string;               // MongoDB ObjectId of the scan_job
  emit: (event: ScannerEvent) => void;  // SSE push function
  discoveredEndpoints: Set<string>; // Endpoints found during crawl, shared across modules
  cancelled: boolean;              // Set to true on cancel signal
  options?: {
    customHeaders?: Record<string, string>;
    authToken?: string;
    cookies?: string;
    followRedirects?: boolean;
  };
}
```

### 4.3 ScanFinding Shape

```typescript
interface ScanFinding {
  title: string;           // e.g. "SQL Injection in /api/users"
  category: string;        // e.g. "Injection", "Broken Access Control"
  severity: "critical" | "high" | "medium" | "low" | "info";
  endpoint: string;        // The specific URL/path affected
  description: string;     // Full description of the vulnerability
  evidence: string;        // Proof — request/response snippets, payloads used
  recommended_fix: string; // Remediation steps
  cvss_score: number;      // 0.0–10.0
  cwe_id: string;          // e.g. "CWE-89"
  owasp_category: string;  // e.g. "A03:2021 – Injection"
  scanner_name: string;    // Which module found this
  scanner_family: string;  // Module family (injection, recon, auth, etc.)
  confidence: number;      // 0.0–1.0
  is_duplicate?: boolean;
  validation_status: "needs_review" | "confirmed" | "false_positive" | "fixed";
}
```

### 4.4 Scan Profiles / Pipelines

| Profile | Modules Run | Typical Duration |
|---------|------------|-----------------|
| **Quick** | 15 modules: TLS, headers, cookies, CORS, basic SQLi, XSS, redirect, recon, fingerprint, DNS, CSRF, data-exposure, js-secrets, auth, ports | 1–3 minutes |
| **Standard** | 30 modules: all Quick + path traversal, XXe, IDOR, JWT, OAuth, GraphQL, API advanced, injection advanced, file upload, cloud, crawl, subdomains, passive recon, cve-lookup | 5–15 minutes |
| **Deep** | 60+ modules: all Standard + ZAP integration, Nuclei templates, Playwright browser automation, business logic, gRPC, smuggling, OSINT, custom rules, time-based SQLi, boolean SQLi | 20–60+ minutes |

### 4.5 All 39+ Scanner Modules

#### Network & Infrastructure
| Module | File | What it scans |
|--------|------|--------------|
| TLS/SSL | `tls.ts` | Certificate expiry, weak ciphers, TLS version, HSTS |
| DNS Security | `dns.ts` | DNSSEC, zone transfer, SPF/DMARC/DKIM misconfiguration |
| Security Headers | `headers.ts` | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookie Security | `cookies.ts` | Missing HttpOnly, Secure, SameSite flags; overly broad domain scope |
| CORS | `cors.ts` | Wildcard origins, credentials with wildcard, pre-flight bypass |
| Port Scan | `ports.ts` | Common ports (21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, etc.) |
| Infrastructure | `infrastructure.ts` | WAF detection, CDN fingerprinting, load balancer detection |
| Fingerprinting | `fingerprint.ts` | Web framework, server version, CMS detection (WordPress, Drupal, etc.) |
| Subdomains | `subdomains.ts` | DNS brute-force, certificate transparency logs, Wayback Machine crawl |

#### Web Vulnerabilities
| Module | File | What it scans |
|--------|------|--------------|
| XSS | `xss.ts` | Reflected XSS with 20+ payloads; DOM-based XSS patterns; Content-Security-Policy bypass |
| SQL Injection | `sqli.ts` | **Error-based** (MySQL/PG/MSSQL error patterns), **Boolean-based** (response length differential), **Time-based** (SLEEP/WAITFOR/pg_sleep with 2800ms threshold) |
| Open Redirect | `redirect.ts` | URL parameter redirect payloads; header injection for redirect |
| Path Traversal | `pathtraversal.ts` | `../` traversal sequences; null byte injection; Windows path variants |
| CSRF | `csrf.ts` | Missing CSRF tokens; SameSite=None without Secure; CORS+credentials |
| XXE | `xxe.ts` | XML external entity injection in upload endpoints and XML APIs |
| Cache Poisoning | `cache-poisoning.ts` | Unkeyed header injection; cache deception attacks |

#### Authentication & Authorization
| Module | File | What it scans |
|--------|------|--------------|
| Auth Basics | `auth.ts` | Default credentials, basic auth bypass, password in URL |
| Auth Advanced | `auth-advanced.ts` | Account enumeration, password reset flaws, MFA bypass patterns |
| IDOR | `idor.ts` | Sequential ID enumeration on common endpoints; horizontal privilege escalation |
| OAuth | `oauth.ts` | `redirect_uri` bypass, PKCE missing, implicit flow, state parameter missing |
| JWT | `jwt.ts` | `alg:none` attack, weak HMAC secrets (common wordlist), RS256→HS256 confusion |

#### API & Advanced Injection
| Module | File | What it scans |
|--------|------|--------------|
| GraphQL | `graphql.ts` | Introspection enabled, query depth attacks, batch query abuse |
| gRPC | `grpc.ts` | Reflection API enabled, service enumeration |
| API Advanced | `api-advanced.ts` | API versioning abuse (`/v0`, `/v2`), HTTP method override, mass assignment |
| Injection Advanced | `injection-advanced.ts` | Server-Side Template Injection (SSTI), CRLF injection, prototype pollution, log injection |
| Business Logic | `business-logic.ts` | Negative quantity abuse, price manipulation, workflow bypass |

#### File & Data
| Module | File | What it scans |
|--------|------|--------------|
| File Upload | `file-upload.ts` | Unrestricted file type upload, polyglot files, dependency confusion |
| Data Exposure | `data-exposure.ts` | Exposed `.env`, API keys in responses, PII in URLs, stack traces |
| JS Secrets | `js-secrets.ts` | Secrets in JavaScript source files: AWS keys, API tokens, private keys |

#### Reconnaissance
| Module | File | What it scans |
|--------|------|--------------|
| Crawler | `crawl.ts` | Discovers all reachable endpoints; extracts forms, links, JS files |
| Recon | `recon.ts` | Checks robots.txt, sitemap.xml, `.git`, `.svn`, backup files (`.bak`, `~`, `.old`) |
| Passive Recon | `passive-recon.ts` | WHOIS lookup, passive DNS, Shodan-style data (no active probing) |
| OSINT | `osint.ts` | Public breach data, LinkedIn org footprint, GitHub org repos |

#### External Tool Integrations
| Module | File | What it scans |
|--------|------|--------------|
| OWASP ZAP | `zap.ts` | Delegates scan to ZAP daemon at `ZAP_URL`; imports ZAP findings |
| Nuclei | `nuclei.ts` | Runs Nuclei templates against target; imports structured results |
| Playwright | `playwright.ts` | Browser-based scanning via Playwright service at `PLAYWRIGHT_URL`; renders JS before scanning |
| CVE Lookup | `cve-lookup.ts` | Enriches findings with CVE IDs from NVD; fetches CVSS vectors |
| Custom Rules | `custom-rules.ts` | User-defined regex/path rules from `scanner_rules` collection |

#### Cloud & Infrastructure
| Module | File | What it scans |
|--------|------|--------------|
| Cloud | `cloud.ts` | S3 bucket public access, GCS bucket enumeration, Docker API exposed, Kubernetes dashboard |
| HTTP Smuggling | `smuggling.ts` | CL.TE / TE.CL desync attacks; rate limit bypass via smuggling |

### 4.6 Deduplication — `services/dedup.ts`
After each scan, findings are deduplicated using **Levenshtein distance**:
- Two findings are considered duplicates if: same `category` + same `endpoint` + title similarity ≥ 85%
- `similarity(a, b)` = `1 - levenshtein(a, b) / max(len(a), len(b))`
- Duplicate findings get `is_duplicate: true` and reference `duplicate_of` ID
- `clusterFindings(scanJobId)` groups all near-duplicates into clusters for review

---

## 5. AI System

### 5.1 AI Configuration
The app uses an **OpenAI-compatible API** client:
- **Model:** `OPENCODE_MODEL` env var (default: `nemotron-3-super-free`)
- **Base URL:** `OPENCODE_API_BASE` env var (default: `https://opencode.ai/zen/v1`)
- **API Key:** `OPENCODE_API_KEY` env var
- **Client:** `openai` npm package pointed at the custom base URL

### 5.2 AI Routes — `backend/src/routes/ai.ts`
All 18 endpoints are protected by `requireAuth` + `aiLimiter`. All stream responses via **SSE** (`text/event-stream`).

| Endpoint | What the AI does |
|----------|-----------------|
| `POST /ai/summary` | Streams an executive summary of all findings for a scan job |
| `POST /ai/remediation` | Streams detailed remediation steps for a specific finding |
| `POST /ai/explain` | Explains a vulnerability in plain English (tailored to severity) |
| `POST /ai/classify` | Re-classifies a finding's OWASP category and severity |
| `POST /ai/patch` | Generates code patch suggestions for a finding |
| `POST /ai/triage` | Prioritizes findings by exploitability and business impact |
| `POST /ai/attack-path` | Maps potential attack chains between multiple findings |
| `POST /ai/compliance` | Maps findings to compliance controls (PCI-DSS, HIPAA, SOC2) |
| `POST /ai/report` | Generates a full pentest report narrative |
| `POST /ai/risk-score` | Calculates a contextual risk score (beyond raw CVSS) |
| `POST /ai/false-positive` | Analyzes evidence to determine if a finding is a false positive |
| `POST /ai/retest` | Generates retest instructions for a finding |
| `POST /ai/compare` | Compares two scans and summarizes security posture changes |
| `POST /ai/exploit` | Explains how a vulnerability could be exploited (educational) |
| `POST /ai/mitre` | Maps findings to MITRE ATT&CK techniques |
| `POST /ai/custom` | Free-form prompt about findings (analyst Q&A) |
| `POST /ai/pentest-plan` | Generates a pentest engagement plan for a target |
| `POST /ai/threat-model` | Builds a threat model for an application based on fingerprint |

### 5.3 How AI Streaming Works
```
Frontend                    Backend                     AI API
   │                           │                           │
   │  POST /api/ai/remediation │                           │
   │──────────────────────────>│                           │
   │                           │  OpenAI.chat.completions  │
   │                           │  .create({ stream:true }) │
   │                           │──────────────────────────>│
   │  SSE: data: {chunk}       │  SSE chunks stream back   │
   │<──────────────────────────│<──────────────────────────│
   │  SSE: data: {chunk}       │                           │
   │<──────────────────────────│                           │
   │  SSE: data: [DONE]        │                           │
   │<──────────────────────────│                           │
```

### 5.4 AI Pentest Orchestrator — `services/ai-pentest/orchestrator.ts`
An autonomous pentesting agent that:
1. **Plans** — AI generates a pentest plan for the target based on fingerprint results
2. **Recon** — Directs scanner modules for information gathering
3. **Exploitation** — Sequences attack modules based on discovered vulnerabilities
4. **Verification** — Re-tests to confirm findings are exploitable
5. **Reporting** — Generates chain-of-thought reasoning for each finding

Sub-services:
- `patch-generator.ts` — Produces language-specific code patches
- `verification.ts` — Automated retest with evidence capture
- `reasoning-chain.ts` — Builds step-by-step exploit reasoning shown to analyst

### 5.5 Vulnerability Intelligence — `services/vuln-intel.ts`
Enriches findings that have CVE IDs:
- **EPSS Score:** Fetches from `https://api.first.org/data/v1/epss?cve={id}` — probability of exploitation in the wild (0.0–1.0)
- **CISA KEV:** Checks CISA's Known Exploited Vulnerabilities catalog (24-hour cache). If a CVE is in KEV, the finding gets `is_cisa_kev: true` and displays a red "⚠ CISA KEV — Actively Exploited" badge
- Updated fields: `epss_score`, `epss_percentile`, `is_cisa_kev`, `intel_enriched_at`

---

## 6. Frontend Architecture

### 6.1 Tech Stack
- **React 19** with hooks
- **Vite** — dev server and production bundler
- **Wouter** — lightweight client-side router
- **TanStack Query (React Query v5)** — server state, caching, background refetch
- **Tailwind CSS v4** — utility-first styling
- **Radix UI** — accessible headless UI primitives
- **Recharts** — charts (severity distribution, risk trends, timeline)
- **Lucide React** — icons

### 6.2 App Entry — `frontend/src/App.tsx`
Wraps the entire app in:
```tsx
<QueryClientProvider client={queryClient}>
  <TooltipProvider>
    <Router>         {/* Wouter router */}
      <Switch>       {/* Route matching */}
        ...routes
      </Switch>
    </Router>
    <Toaster />
  </TooltipProvider>
</QueryClientProvider>
```

Route structure:
- **Public routes** (no layout): `/` (landing), `/login`, `/admin`, `/forgot-password`, `/reset-password`
- **Protected routes** (inside `<AppLayout>`): all dashboard routes — wrapped in auth check that redirects to `/login` if no session

### 6.3 API Client — `frontend/src/api-client/`
Auto-generated TanStack Query hooks from the OpenAPI spec:

```typescript
// Example generated hooks:
useGetMe()                     // GET /api/auth/me
useGetScanJobs(params)         // GET /api/scan-jobs
usePostScanJob()               // POST /api/scan-jobs (mutation)
useGetFindings(params)         // GET /api/findings
useGetDashboardStats()         // GET /api/dashboard/stats
useGetTargets()                // GET /api/targets
usePatchFinding(id)            // PATCH /api/findings/:id
```

All hooks use `custom-fetch.ts` which:
- Adds `/api` base path prefix
- Attaches session cookie automatically (`credentials: "include"`)
- Throws structured errors with HTTP status codes
- Returns typed response data

### 6.4 Layout — `frontend/src/components/layout.tsx`
The `AppLayout` component renders on all authenticated pages:
- **Top bar:** Logo, global search (Cmd+K), notifications bell, user avatar/menu, theme toggle
- **Sidebar:** Collapsible navigation with sections:
  - SCANNING: Dashboard, Scans, New Scan, Templates, Targets
  - FINDINGS: All Findings, Remediations, AI Triage, CVSS Calculator
  - ANALYTICS: Executive, Attack Surface, OWASP, Timeline, Compliance, SLA, Metrics, Analytics+
  - COLLABORATION: Engagements, Comments, Notifications
  - REPORTS: Reports, Scheduled Reports
  - CONFIG: Settings, Integrations, API Keys, Scanner Rules, Scheduled Scans
  - ADMIN (admin role only): Admin Panel, Users, Audit Log, System Health
- **Breadcrumbs:** Auto-generated from current route path

---

## 7. All Pages

### Authentication Pages
| Route | File | Purpose |
|-------|------|---------|
| `/` | `landing.tsx` | Marketing page with robot hero, feature cards, OWASP grid, CTA |
| `/login` | `login.tsx` | Username + password form; links to forgot password and 2FA |
| `/admin` | `admin-login.tsx` | Separate admin login with additional PIN verification |
| `/forgot-password` | `forgot-password.tsx` | Email form to trigger password reset email |
| `/reset-password` | `reset-password.tsx` | Token-validated new password form |

### Core Dashboard & Scanning
| Route | File | Purpose |
|-------|------|---------|
| `/dashboard` | `dashboard.tsx` | Stats cards (active scans, total findings, risk score, SLA status), severity donut chart, recent scans list, onboarding wizard on first visit |
| `/scans` | `scans.tsx` | Paginated scan job list with status filters (running, completed, failed), start new scan button |
| `/scans/new` | `new-scan.tsx` | Scan creation: target URL, profile selector (Quick/Standard/Deep), custom headers, auth token, schedule options |
| `/scans/:id` | `scan-detail.tsx` | Live scan view: progress bar (SSE), findings feed as they arrive, module status indicators, cancel button, AI summary trigger |
| `/scans/compare` | `scan-compare.tsx` | Side-by-side comparison of two scans: new findings, fixed findings, regressed findings, severity changes |
| `/scan-templates` | `scan-templates.tsx` | Pre-built scan configurations (API Security, Full Web App, Quick Check, etc.) |

### Findings Management
| Route | File | Purpose |
|-------|------|---------|
| `/findings` | `findings.tsx` | Full findings table with: bulk selection, filter by severity/category/status/OWASP/scanner, SARIF export, bulk actions (mark FP, assign, delete) |
| `/findings/:id` | `finding-detail.tsx` | Single finding: full description, evidence panel, CVSS breakdown, CWE link, EPSS score badge, CISA KEV badge, remediation AI stream, status history, comments thread, GitHub issue button |
| `/remediations` | `remediations.tsx` | Remediation tickets list with SLA countdown timers, assignee, status workflow |
| `/cvss` | `cvss.tsx` | Interactive CVSS 3.1 calculator: all 8 metric groups with radio selectors, auto-calculates Base/Temporal/Environmental score and severity label |

### Target Management
| Route | File | Purpose |
|-------|------|---------|
| `/targets` | `targets.tsx` | Asset list: add target URL, view last scan date, overall risk score, active finding count |
| `/targets/:id` | `target-detail.tsx` | Single target: scan history timeline, risk trend chart, top findings, attack surface subdomains/ports, last monitored timestamp |

### Analysis & Intelligence
| Route | File | Purpose |
|-------|------|---------|
| `/executive` | `executive.tsx` | Board-level dashboard: risk posture over time (Recharts line chart), top 5 critical findings, OWASP heat map, remediation velocity |
| `/attack-surface` | `attack-surface.tsx` | Interactive node graph of discovered subdomains, IPs, open ports; edges show relationships; click node to see findings |
| `/owasp` | `owasp.tsx` | OWASP Top 10 grid: finding count per category, coverage percentage, click-through to filtered findings |
| `/timeline` | `timeline.tsx` | Chronological feed of all events: scan started, finding discovered, finding fixed, SLA breached, user login |
| `/compliance` | `compliance-dashboard.tsx` | Maps findings to compliance controls: PCI-DSS, HIPAA, SOC2, ISO27001; pass/fail per control |
| `/sla` | `sla-dashboard.tsx` | SLA compliance table: findings grouped by deadline, color-coded urgency (green → red), breach notifications |
| `/ai-triage` | `ai-triage.tsx` | AI-powered priority queue: findings ranked by exploitability × impact × business context; one-click AI explain/remediate |
| `/metrics` | `metrics-dashboard.tsx` | KPI cards: MTTR (Mean Time to Remediate), SLA compliance %, false positive rate, recurrence rate, risk velocity |
| `/analytics-enhanced` | `analytics-enhanced.tsx` | Advanced charts: scanner performance (findings per module), finding trends over time, top vulnerable targets |

### Collaboration & Engagements
| Route | File | Purpose |
|-------|------|---------|
| `/engagements` | `engagements.tsx` | List of pentest engagements (projects), create new, status badges |
| `/engagements/:id` | `engagement-detail.tsx` | Single engagement: scope targets, team members, rules of engagement, all findings from in-scope targets, risk summary |
| `/notifications` | `notifications.tsx` | Notification center: scan completions, SLA breach alerts, new finding alerts, mark read/unread |

### Reports & Scheduling
| Route | File | Purpose |
|-------|------|---------|
| `/reports` | *(reports page)* | Report list: generate PDF/HTML reports, executive vs technical detail level, download or email |
| `/scheduled-scans` | `scheduled-scans.tsx` | Cron-based recurring scan setup: frequency (daily/weekly/monthly), profile, target, notification settings |

### Administration
| Route | File | Purpose |
|-------|------|---------|
| `/settings` | `settings.tsx` | User profile, change password, notification preferences, 2FA setup/disable |
| `/api-keys` | `api-keys.tsx` | Generate/revoke API keys for programmatic access; view key permissions and last-used timestamp |
| `/integrations` | `integrations.tsx` | Configure GitHub (repo + token), Slack (webhook URL), JIRA, generic webhooks |
| `/audit-log` | `audit-log.tsx` | Admin-only: full audit trail table with filters by user, action, date range, resource type |
| `/admin/panel` | `admin-panel.tsx` | System administration: DB stats, user counts, queue status, flush caches |
| `/admin/users` | `admin-users.tsx` | User management: list all users, change roles, suspend accounts, reset passwords |
| `/system` | `system.tsx` | System health: service statuses (DB, Redis, ZAP, Playwright), memory usage, queue depth, error rates |

---

## 8. Database Collections

### `users`
```
_id, username, email, password_hash, role ("admin"|"analyst"|"viewer"),
created_at, last_login, is_active, two_factor_secret, two_factor_enabled,
password_reset_token, password_reset_expires
```

### `scan_jobs`
```
_id, target_url, profile ("quick"|"standard"|"deep"), status ("queued"|"running"|"completed"|"failed"|"cancelled"),
started_at, completed_at, created_by, risk_score (0-100),
findings_count, critical_count, high_count, medium_count, low_count, info_count,
options: { customHeaders, authToken, cookies, followRedirects },
error_message, cancelled_at
```

### `findings`
```
_id, scan_job_id (ObjectId), target_url, title, category, severity,
endpoint, description, evidence, recommended_fix,
cvss_score, cvss_vector, cwe_id, owasp_category,
scanner_name, scanner_family, confidence,
validation_status ("needs_review"|"confirmed"|"false_positive"|"fixed"),
is_duplicate, duplicate_of (ObjectId),
assigned_to, due_date, fixed_at,
epss_score, epss_percentile, is_cisa_kev, intel_enriched_at,
cve_enrichment: [{ id, description, cvss }],
status_history: [{ status, changed_by, changed_at, note }],
created_at, updated_at
```

### `targets`
```
_id, url, name, description, status ("active"|"inactive"),
last_scan_at, risk_score, findings_count,
monitored_subdomains: [string], monitored_ports: [string], last_monitored,
tags: [string], created_by, created_at, updated_at
```

### `remediations`
```
_id, finding_id (ObjectId), target_url, title, severity,
status ("open"|"in_progress"|"fixed"|"accepted_risk"),
assigned_to, due_date, sla_breached,
notes, ai_patch, created_at, updated_at
```

### `engagements`
```
_id, name, description, status ("active"|"completed"|"archived"),
start_date, end_date, scope_targets: [string (target ObjectId)],
team_members: [{ userId, role }], rules_of_engagement,
created_by, created_at, updated_at
```

### `webhooks`
```
_id, url, secret, events: [string], is_active,
created_by, created_at, last_triggered, last_status
```

### `api_keys`
```
_id, key_hash, key_prefix (first 8 chars for display),
name, user_id, permissions: [string],
last_used, expires_at, is_active, created_at
```

### `audit_log`
```
_id, user_id, username, action, resource, resource_id,
ip, user_agent, details, timestamp
```

### `activity_events`
```
_id, type, message, timestamp, target_url, severity, metadata
```

### `sessions`
Managed by `connect-mongo`. Standard express-session format.

### `settings`
```
_id, key, value, updated_at
```
Keys include: `ip_allowlist`, `github_token`, `slack_webhook`, `smtp_config`, `scanner_concurrency`, etc.

### `scheduled_scans`
```
_id, target_url, profile, cron_expression, is_active,
last_run, next_run, notify_email, created_by, created_at
```

### `notifications`
```
_id, user_id, type, message, is_read, link, created_at
```

### `comments`
```
_id, resource_type ("finding"|"scan"), resource_id, author_id,
author_username, body, created_at, updated_at
```

### `scanner_rules`
```
_id, name, pattern, match_type ("regex"|"contains"|"path"),
severity, category, description, is_active, created_by, created_at
```

---

## 9. Authentication & Security

### Session-Based Auth
- Sessions stored in MongoDB via `connect-mongo`
- Session cookie: `HttpOnly`, `SameSite: lax`, `Secure` in production
- Session data: `{ userId, username, role, loginAt }`

### API Key Auth
- `X-API-Key` header accepted as alternative to session cookie
- Keys stored as bcrypt hashes in `api_keys` collection
- Inject synthetic session so all route handlers work identically

### Password Security
- bcrypt with cost factor 12
- Password reset via signed token (24h expiry) sent by email
- Optional TOTP 2FA (speakeasy compatible)

### RBAC Roles
| Role | Access |
|------|--------|
| `admin` | Everything including user management, audit log, system settings |
| `analyst` | All scanning, findings, reports, integrations |
| `viewer` | Read-only: findings, dashboard, reports |

### Rate Limiting
| Limiter | Limit | Applied to |
|---------|-------|-----------|
| `globalLimiter` | 500 req / 15 min | All routes |
| `authLimiter` | 20 req / 15 min | `/auth/login`, `/auth/register` |
| `aiLimiter` | 30 req / min | All `/ai/*` endpoints |
| `scanLimiter` | 10 req / 15 min | `POST /scan-jobs` |

### Webhook Security
All outgoing webhooks include `X-Hub-Signature-256` header — HMAC-SHA256 of the payload body signed with the webhook secret. Recipients should verify this signature before processing.

---

## 10. Real-Time Streaming (SSE)

### Scan Progress Streaming
When a scan starts, the frontend opens an SSE connection:
```
GET /api/stream?scanJobId={id}
```
The server holds the connection open and pushes events as the scanner runs:
```
data: {"type":"progress","module":"xss","percent":45,"message":"Testing XSS payloads..."}
data: {"type":"finding","finding":{ ...ScanFinding }}
data: {"type":"module_complete","module":"sqli","findings_count":2}
data: {"type":"scan_complete","total_findings":14,"risk_score":78}
data: {"type":"error","message":"..."}
```

### AI Response Streaming
All AI endpoints stream via SSE:
```
POST /api/ai/remediation   (body: { findingId })
→ Response: text/event-stream
data: {"chunk": "The SQL injection vulnerability in"}
data: {"chunk": " /api/users can be remediated by"}
data: {"chunk": " using parameterized queries..."}
data: [DONE]
```

The frontend uses a custom SSE reader hook that appends chunks to a string state, rendering markdown in real time as words arrive.

---

## 11. SLA & Scheduler System

### SLA Deadlines
Findings automatically get SLA deadlines based on severity:
| Severity | Deadline |
|----------|---------|
| Critical | 24 hours |
| High | 72 hours (3 days) |
| Medium | 168 hours (7 days) |
| Low | 720 hours (30 days) |
| Info | No SLA |

### Scheduler — `services/scheduler.ts`
Runs on backend startup via `node-cron`. Scheduled jobs:

| Job | Schedule | What it does |
|-----|----------|-------------|
| SLA enforcement | Every 30 min | Finds findings past deadline, marks `sla_breached: true`, sends notifications, triggers webhooks |
| Attack surface monitor | Every 6 hours | Runs `runAttackSurfaceMonitor()` on all active targets — compares current vs previous subdomains/ports, creates "Attack Surface Change" findings for anything new |
| Scheduled scans | Every 5 min | Checks `scheduled_scans` collection for due jobs, enqueues them |
| Report generation | Daily 06:00 | Generates PDF reports for all active `report_schedules`, emails to recipients |
| Intel enrichment | Every hour | Enriches new findings that have CVE IDs with EPSS scores + CISA KEV status |

### Attack Surface Monitor — `services/monitor/attack-surface-monitor.ts`
For each active target:
1. Loads previous `monitored_subdomains` and `monitored_ports` from the target document
2. Runs `runSubdomainEnum` and `runPortScan` with `quick` profile
3. Compares current results to previous
4. Creates `Attack Surface Change` findings for any new subdomains or ports
5. Updates target document with new monitored state and `last_monitored` timestamp
6. Creates an `activity_events` entry summarizing changes

---

## 12. Integrations & Webhooks

### GitHub Integration
- Configured in Settings → Integrations: repo owner, repo name, GitHub token
- From any finding detail page, click "Create GitHub Issue" → sends `POST /api/webhooks/github` → creates issue via GitHub API with finding title, severity, evidence, remediation steps, CVSS score

### Slack Integration
- Configured with a Slack webhook URL
- Triggered on: critical/high findings discovered, SLA breach, scan completion
- Message includes: finding title, severity badge, target URL, direct link to finding

### Generic Webhooks
- Admin can configure multiple webhook URLs with custom secrets
- Events: `scan.started`, `scan.completed`, `finding.created`, `finding.validated`, `sla.breached`, `surface.changed`
- All payloads signed with HMAC-SHA256 in `X-Hub-Signature-256` header
- Delivery log stored in `webhook_log` collection with retry on failure

### Email (Nodemailer)
- SMTP config from `settings` collection
- Sends: password reset emails, scan completion summaries, SLA breach alerts, scheduled report PDFs, user invitation emails

---

## 13. API Reference

### Auth
```
POST   /api/auth/register          Create new user account
POST   /api/auth/login             Session login
POST   /api/auth/logout            Clear session
GET    /api/auth/me                Current user info
POST   /api/auth/demo              Login as demo user (no password)
POST   /api/auth/password-reset    Request reset email
POST   /api/auth/password-reset/:token  Confirm new password
POST   /api/auth/2fa/setup         Initialize TOTP 2FA
POST   /api/auth/2fa/verify        Verify TOTP token
```

### Scans
```
GET    /api/scan-jobs              List scans (filter: status, target, profile)
POST   /api/scan-jobs              Start new scan { targetUrl, profile, options }
GET    /api/scan-jobs/:id          Scan details + findings count
DELETE /api/scan-jobs/:id          Cancel running scan
GET    /api/scan-jobs/:id/findings All findings for scan
POST   /api/scan-jobs/:id/deduplicate  Run dedup clustering on scan
GET    /api/stream?scanJobId=:id   SSE stream for live scan progress
```

### Findings
```
GET    /api/findings               List (filter: severity, category, status, target, scanJobId, owasp)
GET    /api/findings/:id           Single finding detail
PATCH  /api/findings/:id           Update status, assignee, validation_status
GET    /api/findings/:id/history   Status change history
POST   /api/findings/:id/enrich    Trigger EPSS + CISA KEV enrichment
POST   /api/findings/bulk          Bulk actions on up to 200 findings
GET    /api/findings/export/sarif  SARIF format export for GitHub code scanning
```

### Targets
```
GET    /api/targets                List all targets
POST   /api/targets                Create target { url, name, description }
GET    /api/targets/:id            Target detail with risk metrics
PATCH  /api/targets/:id            Update target
DELETE /api/targets/:id            Delete target
```

### Analytics & Metrics
```
GET    /api/dashboard/stats        Summary counts and severity distribution
GET    /api/analytics/executive    Risk posture, OWASP heatmap, top findings
GET    /api/analytics/attack-surface  Subdomain/port topology data
GET    /api/analytics/timeline     Event timeline
GET    /api/risk-trend             Risk score over time per target
GET    /api/metrics/mttr           Mean time to remediate by severity
GET    /api/metrics/sla-compliance SLA pass/fail percentage
GET    /api/metrics/false-positive-rate  FP rate over time
GET    /api/metrics/recurrence-rate  Recurring vulnerability rate
GET    /api/metrics/risk-velocity   Rate of new critical/high findings
GET    /api/analytics/scanner-performance  Findings per scanner module
GET    /api/analytics/finding-trends  New/closed findings over time
GET    /api/analytics/top-vulnerable-targets  Targets ranked by risk
```

### AI (all stream SSE)
```
POST   /api/ai/summary             Executive summary for scan
POST   /api/ai/remediation         Remediation steps for finding
POST   /api/ai/explain             Plain-English explanation
POST   /api/ai/classify            Re-classify OWASP + severity
POST   /api/ai/patch               Code patch generation
POST   /api/ai/triage              Finding prioritization
POST   /api/ai/attack-path         Attack chain mapping
POST   /api/ai/compliance          Compliance control mapping
POST   /api/ai/report              Full report narrative
POST   /api/ai/risk-score          Contextual risk scoring
POST   /api/ai/false-positive      FP analysis
POST   /api/ai/retest              Retest instructions
POST   /api/ai/compare             Scan comparison narrative
POST   /api/ai/exploit             Exploit explanation (educational)
POST   /api/ai/mitre               MITRE ATT&CK mapping
POST   /api/ai/custom              Free-form analyst Q&A
POST   /api/ai/pentest-plan        Engagement planning
POST   /api/ai/threat-model        Threat model generation
```

### Engagements
```
GET    /api/engagements            List all engagements
POST   /api/engagements            Create engagement
GET    /api/engagements/:id        Engagement detail
PATCH  /api/engagements/:id        Update engagement
DELETE /api/engagements/:id        Delete engagement
POST   /api/engagements/:id/targets       Add target to scope
DELETE /api/engagements/:id/targets/:tid  Remove target from scope
GET    /api/engagements/:id/findings      All findings from in-scope targets
GET    /api/engagements/:id/summary       Stats: scans, findings by severity, avg risk
```

### Health
```
GET    /api/healthz                Full system health (DB, Redis, ZAP, Playwright, memory, queue)
GET    /api/healthz/ai             AI API connectivity and latency check
```

---

## 14. How a Scan Works End-to-End

```
1. USER clicks "Launch Scan" in frontend (new-scan.tsx)
        │
2. POST /api/scan-jobs  { targetUrl, profile: "standard", options }
        │
3. Backend creates scan_job document  { status: "queued", ... }
   Returns { scanJobId }
        │
4. Frontend navigates to /scans/:id  (scan-detail.tsx)
   Opens SSE connection: GET /api/stream?scanJobId=xxx
        │
5. Backend scan job dequeued from queue/manager.ts
   Status updated to "running"
        │
6. scanner/index.ts builds PIPELINE_STANDARD (30 modules)
   Creates ScanContext { targetUrl, profile, scanJobId, emit, ... }
        │
7. Module 1: crawl.ts
   - Fetches target URL, parses links, forms, JS files
   - Populates ctx.discoveredEndpoints
   - emit({ type: "progress", module: "crawl", percent: 3 })
        │
8. Module 2: fingerprint.ts
   - Reads Server header, X-Powered-By, HTML patterns
   - Identifies: Node.js/Express, React frontend, MongoDB
   - emit({ type: "progress", module: "fingerprint", percent: 6 })
        │
9. Module 3: headers.ts
   - Fetches target, checks for: CSP, HSTS, X-Frame-Options
   - Missing CSP → creates ScanFinding (medium)
   - emit({ type: "finding", finding: { ... } })
   - Finding saved to MongoDB findings collection
        │
   ... (modules continue) ...
        │
10. Module 17: sqli.ts  (example critical finding)
    - Layer 1: Error-based — sends `'` in each parameter
    - Layer 2: Boolean-based — compares response length for `1=1` vs `1=2`
    - Layer 3: Time-based — sends SLEEP(3) payload, measures response time
    - Response time > 2800ms → confirmed time-based blind SQLi
    - emit({ type: "finding", finding: { title: "SQL Injection in /api/users", severity: "critical", ... } })
        │
11. Each finding received by frontend via SSE
    - Appended to live findings list in scan-detail.tsx
    - Severity count badges update in real time
        │
12. All 30 modules complete
    - dedup.ts clusters similar findings, marks duplicates
    - Risk score calculated: weighted sum of CVSS scores
    - scan_job updated: { status: "completed", risk_score: 82, findings_count: 14 }
    - emit({ type: "scan_complete", total_findings: 14, risk_score: 82 })
    - SSE connection closed
        │
13. Scheduler (background)
    - Assigns SLA deadlines to new findings
    - Triggers webhooks (Slack alert for critical findings)
    - Queues EPSS enrichment for findings with CVE IDs
        │
14. USER clicks "AI Summary" in scan-detail.tsx
    POST /api/ai/summary { scanJobId }
    - Backend loads all findings for scan
    - Calls AI API with findings as context
    - Streams summary chunk by chunk to frontend via SSE
    - Frontend renders markdown in real time as words arrive
        │
15. USER opens a finding → finding-detail.tsx
    - Shows: evidence, CVSS breakdown, EPSS score, CISA KEV badge (if applicable)
    - Clicks "Generate Remediation" → POST /api/ai/remediation
    - AI streams code-level fix advice
    - Clicks "Create GitHub Issue" → issue created in configured repo
```

---

## 15. Environment Variables

### Backend
```bash
PORT=5000                          # HTTP server port
MONGODB_URI=mongodb://...          # MongoDB connection string (falls back to in-memory)
SESSION_SECRET=changeme            # Express session secret (change in production!)
OPENCODE_API_KEY=sk-...            # AI API key
OPENCODE_API_BASE=https://...      # AI API base URL (OpenAI-compatible)
OPENCODE_MODEL=nemotron-3-super-free  # AI model name
ZAP_URL=http://zap:8080            # OWASP ZAP daemon URL
PLAYWRIGHT_URL=http://localhost:3005  # Playwright scanning service URL
REDIS_URL=redis://localhost:6379   # Redis URL (for rate limiting persistence)
SMTP_HOST=smtp.example.com         # Email server
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=password
SMTP_FROM=noreply@bugfinderpro.com
NODE_ENV=production                # Enables secure cookies, disables seed data
```

### Frontend
```bash
PORT=3000                          # Vite dev server port (required)
BASE_PATH=/                        # App base path (required)
API_URL=http://localhost:5000      # Backend URL for Vite proxy in dev
```

---

*Bug Finder Pro — Enterprise Security Operations Platform*  
*© 2026 — All rights reserved*
