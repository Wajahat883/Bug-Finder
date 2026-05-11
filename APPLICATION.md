# Bug Finder Pro — Complete Application Documentation

A professional-grade bug bounty and vulnerability management platform built with a React frontend, Node.js/Express API server, MongoDB database, OWASP ZAP scanner, and AI-powered analysis via the OpenCode API.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Technology Stack](#2-technology-stack)
3. [Infrastructure & Docker Setup](#3-infrastructure--docker-setup)
4. [Backend — API Server](#4-backend--api-server)
5. [Scan Engine — How Scans Work](#5-scan-engine--how-scans-work)
6. [All Scanner Modules](#6-all-scanner-modules)
7. [AI Integration — How It Works](#7-ai-integration--how-it-works)
8. [Frontend Application](#8-frontend-application)
9. [Authentication & Authorization](#9-authentication--authorization)
10. [Real-Time Features (SSE)](#10-real-time-features-sse)
11. [Database Schema & Collections](#11-database-schema--collections)
12. [Integrations](#12-integrations)
13. [Key Features Breakdown](#13-key-features-breakdown)
14. [Environment Variables Reference](#14-environment-variables-reference)
15. [Running the Application](#15-running-the-application)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          Browser                                │
│              React + Vite + TanStack Query + Wouter             │
│                     http://localhost:3000                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP / SSE
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Nginx (port 3000)                             │
│   Serves static SPA   │   /api/* → proxy → API Server :5000    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Node.js / Express API Server (port 5000)           │
│                                                                 │
│  • Session management (MongoDB-backed)                          │
│  • REST API routes                                              │
│  • SSE streaming (scan logs + AI tokens)                        │
│  • Scanner pipeline orchestration                               │
│  • Cron scheduler (SLA enforcement, scheduled scans)            │
└────────────┬──────────────────────┬────────────────────────────┘
             │                      │
             ▼                      ▼
┌────────────────────┐   ┌──────────────────────────┐
│   MongoDB (27017)  │   │  OWASP ZAP (port 8080)   │
│                    │   │  Active scanner engine    │
│  Collections:      │   │  REST API daemon mode     │
│  - users           │   └──────────────────────────┘
│  - scan_jobs       │
│  - findings        │             │
│  - targets         │             ▼
│  - remediations    │   ┌──────────────────────────┐
│  - fp_suppressions │   │   OpenCode AI API        │
│  - sessions        │   │  (nemotron-3-super-free) │
│  - audit_log       │   │  Streamed via SSE        │
│  - ...             │   └──────────────────────────┘
└────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────┐
│    Grafana + Loki  (observability stack)        │
│    Grafana: port 3001    Loki: port 3100        │
│    Structured JSON logs shipped via pino        │
└────────────────────────────────────────────────┘
```

Every component runs as a Docker container on a shared bridge network (`bug-finder-network`). Containers communicate by service name (e.g. `mongodb`, `zap`, `api-server`).

---

## 2. Technology Stack

### Frontend
| Layer | Technology |
|---|---|
| Framework | React 18 + TypeScript |
| Build tool | Vite |
| Routing | Wouter (lightweight client-side router) |
| State / Data fetching | TanStack Query v5 (React Query) |
| UI Components | shadcn/ui (Radix UI primitives + Tailwind CSS) |
| Charts | Recharts |
| PDF export | jsPDF + jspdf-autotable |
| Icons | Lucide React |
| Theme | next-themes (dark/light toggle) |
| Toast notifications | Custom useToast hook (shadcn/ui) |
| HTTP | Native fetch + TanStack Query |

### Backend
| Layer | Technology |
|---|---|
| Runtime | Node.js 20 (LTS) |
| Framework | Express.js 4 |
| Language | TypeScript (compiled via tsx/esbuild) |
| Database client | MongoDB Node.js driver v6 |
| Sessions | express-session + connect-mongo |
| Logging | Pino (structured JSON) + pino-http |
| Scheduler | node-cron |
| AI client | openai SDK (pointed at OpenCode API) |
| Password hashing | bcryptjs |
| Email | Nodemailer |
| Validation | Zod |

### Infrastructure
| Service | Purpose |
|---|---|
| MongoDB 7 | Primary database + session store |
| OWASP ZAP (stable) | Active vulnerability scanner |
| Nginx (Alpine) | Reverse proxy + static file server |
| Grafana 10.2 | Log visualization dashboard |
| Grafana Loki 2.9 | Log aggregation (backend for Grafana) |
| mongo-backup | Daily `mongodump` with 7-day retention |

---

## 3. Infrastructure & Docker Setup

### Docker Compose Services

The entire application is defined in `docker-compose.yml` at the project root. All services share one Docker bridge network so they resolve each other by container name.

```
docker-compose.yml
├── mongodb          → Primary database, healthcheck with mongosh ping
├── zap              → OWASP ZAP in API daemon mode (-daemon flag)
├── api-server       → Express backend, depends on mongodb (healthy)
├── frontend         → Nginx serving React SPA, proxies /api/*
├── mongo-backup     → Sleeps 24h, then mongodump to /backups volume
├── loki             → Log aggregation (Grafana data source)
└── grafana          → Log visualization, anonymous admin access
```

### Build Process

**Backend Dockerfile** (`artifacts/api-server/Dockerfile`)
- Multi-stage: `node:20-alpine` builder → `node:20-alpine` runner
- Compiles TypeScript with `tsc` or esbuild
- Only `node_modules` (production) + `dist/` copied to final image

**Frontend Dockerfile** (`artifacts/bug-bounty-pro/Dockerfile`)
- Multi-stage: `node:20-alpine` builder → `nginx:alpine` runner
- `npm run build` produces `dist/public/`
- Nginx config (`nginx.conf`) handles:
  - Static file serving from `/usr/share/nginx/html`
  - `location /api/` → `proxy_pass http://api-server:5000`
  - `try_files $uri $uri/ /index.html` for SPA routing

### Networking
- Frontend port: `3000` (Nginx)
- API port: `5000` (Express, also exposed for direct access)
- ZAP port: `8090` → `8080` inside container
- MongoDB port: `27017`
- Grafana: `3001`, Loki: `3100`

---

## 4. Backend — API Server

### Entry Points

```
artifacts/api-server/src/
├── index.ts          ← process entry: creates HTTP server, starts listening
├── app.ts            ← Express app setup: middleware stack, route mounting
├── routes/
│   ├── index.ts      ← Master router, imports and mounts all sub-routers
│   ├── auth.ts       ← Login, logout, register, me, forgot/reset password
│   ├── scans.ts      ← CRUD scan jobs, SSE stream, cancel, export, diff
│   ├── findings.ts   ← CRUD findings, FP suppression, CVE lookup, kill chains
│   ├── targets.ts    ← CRUD targets, bulk import, risk trend, attack surface
│   ├── dashboard.ts  ← Aggregated KPI statistics
│   ├── ai.ts         ← All AI streaming endpoints
│   ├── integrations.ts ← GitHub issues, Slack notifications, webhooks
│   ├── remediations.ts ← Remediation tracking and SLA
│   ├── compliance.ts ← Compliance framework mapping (OWASP, PCI, ISO)
│   ├── sla.ts        ← SLA status and breach queries
│   ├── analytics.ts  ← Chart data for executive/trend views
│   ├── stream.ts     ← SSE endpoint /api/stream/:jobId
│   ├── settings.ts   ← Platform config, API key regeneration
│   ├── webhooks.ts   ← Outbound webhook management
│   ├── auditlog.ts   ← Security audit trail
│   ├── scan-templates.ts ← Saved scan configurations
│   └── comparison.ts ← Side-by-side scan comparison
├── services/
│   ├── scheduler.ts  ← node-cron: scheduled scans + SLA enforcement
│   ├── email.ts      ← Nodemailer email service
│   └── scanner/      ← All 60+ scanner modules (see Section 6)
├── middlewares/
│   ├── rbac.ts       ← requireAuth, requireRole, requireAdmin
│   └── apikey.ts     ← API key authentication (X-API-Key header)
└── lib/
    ├── db.ts         ← MongoDB connection singleton + col() helper
    ├── logger.ts     ← Pino logger configuration
    ├── schema.ts     ← Zod schemas for request validation
    ├── audit.ts      ← logAuditEvent() helper
    └── seed.ts       ← Default admin user + platform settings seeding
```

### Middleware Stack (in order)

1. **pino-http** — logs every request with method, path, status code
2. **cors** — allows all origins with credentials (`origin: true, credentials: true`)
3. **express-session** — stores sessions in MongoDB (`sessions` collection), 7-day TTL
4. **express.json()** — parses JSON request bodies
5. **apiKeyAuth** — checks `X-API-Key` header, sets `req.session.userId` and `req.session.role` if valid
6. **Route handlers** — all under `/api` prefix

### Session Management

Sessions are stored in MongoDB using `connect-mongo`. When a user logs in (`POST /api/auth/login`), the server:
1. Looks up the user by email
2. Verifies password with `bcrypt.compare()`
3. Sets `req.session.userId`, `req.session.role`, `req.session.email`
4. Returns the user object to the client

The session cookie (`bbp.sid`) is `httpOnly`, `sameSite: lax`, valid for 7 days.

---

## 5. Scan Engine — How Scans Work

The scan pipeline is the core of the application. When a user clicks "New Scan":

### Step 1 — Job Creation

`POST /api/scan-jobs` creates a document in `scan_jobs` collection with:
- `status: "queued"`, `progress: 0`
- `target_url`, `scan_profile` (quick/standard/deep)
- Feature flags: `validation_enabled`, `fuzzing_enabled`, `bug_bounty_mode`
- Severity counts all zeroed

### Step 2 — Pipeline Trigger

`runScanPipeline()` in `services/scanner/index.ts` is called asynchronously. It:
1. Creates a `ScanContext` object containing target URL, job ID, profile, flags
2. Runs crawler first to discover endpoints
3. Iterates through the module pipeline for the selected profile
4. Emits SSE events at each step (engine start, finding discovered, progress, complete)
5. Saves each finding to the `findings` collection
6. Updates job status, progress, and severity counts in real time
7. Calls `updateTargetAfterScan()` when done

### Step 3 — Cancellation

A Node.js `EventEmitter` (`scanEvents`) allows cancellation. When the user clicks Stop:
- `POST /api/scan-jobs/:id/cancel` sets `status: "cancelled"` in DB
- Emits `cancel:{jobId}` event on `scanEvents`
- The pipeline loop checks a `cancelled` flag at the start of each module and exits cleanly

### Step 4 — Target Update

After a scan completes, `updateTargetAfterScan()`:
- Extracts technology stack from fingerprint finding descriptions (regex: nginx, react, node, apache, etc.)
- Extracts discovered subdomains
- Appends a `{score, date}` entry to `risk_history[]` (capped at 10 entries)
- Upserts the target document with latest scan date, total findings count, and risk score

### Pipeline Selection

| Profile | Modules | Description |
|---|---|---|
| Quick | ~15 modules | Fast recon, headers, TLS, DNS, passive checks |
| Standard | ~30 modules | Full web app scan, injection tests, auth checks |
| Deep | 60+ modules | All modules including GraphQL, gRPC, smuggling, cloud |

### False Positive Suppression

Before saving each finding, the scanner checks `fp_suppressions` collection for a matching key `domain + title + endpoint`. If found, the finding is saved with `validation_status: "false_positive"` automatically.

---

## 6. All Scanner Modules

Every module receives a `ScanContext` object (target URL, job ID, discovered endpoints, session) and returns `ScanFinding[]`.

| Module File | What It Tests |
|---|---|
| `crawl.ts` | Spider target, discover endpoints, extract forms/links |
| `tls.ts` | TLS version, cipher suites, certificate expiry, HSTS |
| `headers.ts` | Missing/misconfigured security headers (CSP, X-Frame, etc.) |
| `cookies.ts` | Missing Secure/HttpOnly/SameSite flags, insecure session cookies |
| `cors.ts` | CORS wildcard origins, credentialed CORS misconfigurations |
| `recon.ts` | Sensitive paths (/.git, /backup, /admin, /phpinfo, etc.) |
| `dns.ts` | SPF/DMARC/DNSSEC, DNS zone transfer, subdomain takeover hints |
| `ports.ts` | Open port scan (common ports: 21, 22, 23, 25, 80, 443, 3306, etc.) |
| `xss.ts` | Reflected XSS via parameter injection, DOM-based indicators |
| `sqli.ts` | SQL injection via error-based and boolean-based probes |
| `redirect.ts` | Open redirect via `?redirect=`, `?url=`, `?next=` parameters |
| `auth.ts` | Real credential testing — login endpoint discovery, rate limits, username enumeration, default creds |
| `idor.ts` | Insecure Direct Object Reference via sequential ID manipulation |
| `pathtraversal.ts` | Directory traversal (`../etc/passwd`) in file parameters |
| `subdomains.ts` | Subdomain enumeration via DNS + Wayback Machine |
| `js-secrets.ts` | API keys, tokens, passwords in JavaScript source files |
| `jwt.ts` | Weak JWT secrets, algorithm confusion (none/RS256→HS256) |
| `graphql.ts` | GraphQL introspection enabled, batching attacks, NoSQL injection |
| `injection-advanced.ts` | SSTI, CRLF injection, prototype pollution |
| `file-upload.ts` | Unrestricted file upload, dependency confusion |
| `cve-lookup.ts` | Match server banners against known CVEs |
| `smuggling.ts` | HTTP request smuggling (CL-TE, TE-CL), rate limit detection |
| `infrastructure.ts` | WAF detection, load balancer fingerprinting, cloud metadata |
| `fingerprint.ts` | Technology stack identification (frameworks, servers, CMSs) |
| `passive-recon.ts` | Wayback Machine history, leaked URLs, old endpoints |
| `csrf.ts` | Missing CSRF tokens on state-changing forms |
| `xxe.ts` | XML External Entity injection in XML endpoints |
| `oauth.ts` | OAuth flow issues (state parameter, implicit flow, token leaks) |
| `auth-advanced.ts` | Advanced authentication issues (account enumeration at scale, MFA bypass) |
| `grpc.ts` | gRPC endpoint detection and reflection abuse |
| `api-advanced.ts` | Mass assignment, API versioning issues, hidden parameters |
| `business-logic.ts` | Price manipulation, workflow bypass, privilege escalation |
| `cache-poisoning.ts` | Web cache poisoning via unkeyed headers |
| `cloud.ts` | Cloud metadata endpoints (AWS/GCP/Azure), S3 bucket exposure |
| `data-exposure.ts` | Sensitive data in responses (PII, keys, stack traces) |
| `zap.ts` | OWASP ZAP active scanner integration via REST API |

### OWASP ZAP Integration

`zap.ts` connects to the ZAP daemon (`http://zap:8080`) via its JSON REST API:
1. Starts a new ZAP scan session
2. Sends the target URL to `spider`
3. Triggers `ascan` (active scan)
4. Polls until complete, then fetches alerts
5. Maps ZAP alert risk levels → Bug Finder severity levels
6. Returns findings with ZAP's evidence and solution fields

---

## 7. AI Integration — How It Works

All AI features use the **OpenCode API** (OpenAI-compatible) with the `nemotron-3-super-free` model by default. The model can be changed at runtime from the Settings page.

### Connection

```typescript
const openai = new OpenAI({
  apiKey: process.env["OPENCODE_API_KEY"],
  baseURL: process.env["OPENCODE_API_BASE"] ?? "https://opencode.ai/zen/v1",
  timeout: 240000,
});
```

The `openai` Node.js SDK is used because the OpenCode API is OpenAI-compatible — it accepts the same request format and returns the same response format, just at a different `baseURL`.

### Streaming Architecture

All AI responses are streamed using **Server-Sent Events (SSE)**. This means:

1. The browser sends a `POST` request (e.g. `POST /api/ai/scan-summary/:id`)
2. The server sets `Content-Type: text/event-stream`
3. The AI model streams tokens back from OpenCode
4. Each token chunk is immediately forwarded to the browser as `data: {"content": "..."}` 
5. When done, the server sends `data: {"done": true}`
6. The browser accumulates tokens and displays them character-by-character (typewriter effect)

```
Browser          Express Route      OpenCode API
  │                   │                   │
  │ POST /api/ai/*    │                   │
  │──────────────────►│                   │
  │                   │ stream: true      │
  │                   │──────────────────►│
  │◄── data: token ───│◄── chunk ─────────│
  │◄── data: token ───│◄── chunk ─────────│
  │◄── data: {done} ──│◄── [DONE] ────────│
```

A 15-second SSE heartbeat (`: keep-alive`) prevents Nginx from closing idle connections.

### Retry Logic

`streamWithRetry()` retries on retriable errors (524 timeout, provider errors, ECONNRESET) with exponential backoff:
- Attempt 0: immediate
- Attempt 1: wait 2 seconds
- Attempt 2: wait 4 seconds
- Max 2 retries (3 total attempts)

### AI Endpoints

| Endpoint | Purpose | Prompt Context |
|---|---|---|
| `POST /api/ai/scan-summary/:id` | Executive scan summary | Target URL, risk score, top 8 critical/high findings with CVSS+CWE |
| `POST /api/ai/finding-advice/:id` | Remediation guidance | Finding title, severity, CWE, endpoint, description |
| `POST /api/ai/payloads/:id` | Attack payload generation | Vulnerability type, category, endpoint, evidence snippet |
| `POST /api/ai/patch/:id` | Code patch generation | Finding details, recommended fix, optional tech stack |
| `POST /api/ai/executive-narrative/:id` | CISO-level briefing | Risk score, finding counts by severity, top critical titles |
| `POST /api/ai/chat` | Free-form security chat | System prompt + conversation history (last 10 messages) |

### AI Triage Page (`/ai-triage`)

The AI Triage page gives analysts a chat interface where they can:
- Ask about specific findings by referencing their ID or title
- Get bulk triage recommendations
- The system prompt positions the AI as a senior security engineer

### Frontend Integration

In the React components, each AI panel:
1. Uses native `fetch()` (not React Query, since SSE needs streaming)
2. Reads the response body as a `ReadableStream`
3. Uses `TextDecoder` to decode chunks
4. Splits on `\n` to parse SSE lines
5. Strips `data: ` prefix and JSON-parses each line
6. Appends `d.content` to local state using `setText(p => p + d.content)`

```typescript
const reader = res.body!.getReader();
const decoder = new TextDecoder();
let buf = "";
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  buf += decoder.decode(value, { stream: true });
  const lines = buf.split("\n");
  buf = lines.pop() ?? "";
  for (const line of lines) {
    if (!line.startsWith("data: ")) continue;
    const d = JSON.parse(line.slice(6));
    if (d.content) setText(p => p + d.content);
  }
}
```

### Model Selection

The Settings page (`/settings`) allows changing the AI model at runtime. When saved, the backend updates `process.env["OPENCODE_MODEL"]` and the `settings` MongoDB collection. `getModel()` in `ai.ts` always reads the environment variable so the change takes effect immediately without restart.

---

## 8. Frontend Application

### Project Structure

```
artifacts/bug-bounty-pro/src/
├── App.tsx              ← Root component, router configuration
├── components/
│   ├── layout.tsx       ← App shell: sidebar, topbar, keyboard shortcuts, SSE notifications
│   ├── command-palette.tsx ← Cmd+K global search
│   └── ui/              ← shadcn/ui components (button, card, badge, dialog, etc.)
├── pages/
│   ├── dashboard.tsx    ← KPI cards, recent findings, risk trend charts
│   ├── scans.tsx        ← Scan list with filters, export, cancel, pagination
│   ├── scan-detail.tsx  ← Scan viewer: Findings, Diff, Kill Chains, AI Summary, Attack Surface
│   ├── new-scan.tsx     ← Scan launch form with profile, flags, auth options
│   ├── findings.tsx     ← Global findings list with FP workflow, export, pagination
│   ├── finding-detail.tsx ← Finding deep-dive: details, evidence, CVE, remediation, AI panels
│   ├── targets.tsx      ← Target management with bulk import, risk sparklines, tag editor
│   ├── target-detail.tsx ← Per-target findings history and details
│   ├── attack-surface.tsx ← 5-tab attack surface map (Overview, Endpoints, Heatmap, Subdomains, Ports)
│   ├── executive.tsx    ← Executive dashboard with Recharts, AI narrative
│   ├── remediations.tsx ← Remediation tracking and status management
│   ├── ai-triage.tsx    ← AI chat interface for bulk triage
│   ├── integrations.tsx ← GitHub, Slack, webhook configuration
│   ├── settings.tsx     ← Platform config, model selection, API key
│   ├── compliance-dashboard.tsx ← OWASP Top 10, PCI-DSS, ISO 27001 mapping
│   ├── sla-dashboard.tsx ← SLA breach tracking
│   ├── admin-users.tsx  ← User management (role editing, activate/deactivate)
│   ├── cvss.tsx         ← Interactive CVSS 3.1 calculator
│   ├── timeline.tsx     ← Chronological finding timeline
│   ├── audit-log.tsx    ← Security audit event viewer
│   ├── login.tsx        ← Authentication page
│   ├── forgot-password.tsx / reset-password.tsx ← Password recovery
│   └── landing.tsx      ← Public marketing/info page
├── hooks/
│   └── use-toast.ts     ← Toast notification hook
└── lib/
    ├── utils.ts         ← cn() helper (clsx + tailwind-merge)
    └── sla.ts           ← getSlaStatus() — compute SLA deadline from severity + date
```

### Routing

Wouter is used for client-side routing. All routes are wrapped in `AppLayout` (the sidebar/topbar shell) except `/`, `/login`, `/forgot-password`, `/reset-password` which render standalone.

### Data Fetching

TanStack Query manages all server state:
- **QueryClient** is configured with `retry: 1`, `staleTime: 30000`
- API calls use `useQuery` for GET requests and `useMutation` for POST/PATCH/DELETE
- Running scans auto-refetch every 3 seconds (`refetchInterval`)
- Cache is invalidated on mutations via `queryClient.invalidateQueries()`

### Command Palette (Cmd+K)

`command-palette.tsx` opens via `Cmd+K` (Mac) or `Ctrl+K` (Windows/Linux). It:
- Fires 3 parallel search queries (findings, scans, targets) when query length > 1
- Filters a static PAGES array (12 pages) by title/subtitle match
- Groups results by type with keyboard navigation (↑↓ arrows, Enter to navigate, Esc to close)
- Also triggered by pressing `/` anywhere in the app

### Global Keyboard Shortcuts

Registered in `layout.tsx`:

| Key | Action |
|---|---|
| `Cmd/Ctrl + K` | Open command palette |
| `/` | Open command palette |
| `N` | Navigate to New Scan |
| `F` | Navigate to Findings |

### Real-Time Notifications

`layout.tsx` runs a polling loop every 10 seconds that:
1. Fetches `GET /api/scan-jobs?status=running`
2. For each running scan, opens an `EventSource` to `/api/stream/:jobId`
3. When a `finding` event arrives with `severity === "critical"` or `"high"`:
   - Adds a notification to the dropdown (with unread count badge)
   - Shows a toast notification
4. On `complete` event, closes the `EventSource` and shows a completion toast
5. Cleans up `EventSource` connections when scans finish

---

## 9. Authentication & Authorization

### Authentication Flow

1. `POST /api/auth/login` — validates email/password with bcrypt, creates session
2. `GET /api/auth/me` — returns current user from session (used by frontend on load)
3. `POST /api/auth/logout` — destroys session
4. `POST /api/auth/register` — creates new user (admin-only in production)
5. `POST /api/auth/forgot-password` — generates reset token, sends email
6. `POST /api/auth/reset-password` — validates token, updates password

### RBAC (Role-Based Access Control)

Three roles, enforced by middleware in `middlewares/rbac.ts`:

| Role | Permissions |
|---|---|
| `admin` | Full access including user management, settings, all data |
| `analyst` | Create/run scans, manage findings, create remediations |
| `viewer` | Read-only access to all data |

Middleware functions:
- `requireAuth` — blocks unauthenticated requests (returns 401)
- `requireRole("admin", "analyst")` — blocks insufficient roles (returns 403)
- `requireAdmin` — shorthand for `requireRole("admin")`

### API Key Authentication

`middlewares/apikey.ts` checks the `X-API-Key` header on every `/api` request. If a valid key is found in the `settings` collection, it sets the session context (treating the request as the admin user). This allows programmatic API access without cookie-based sessions.

### Seed Data

`lib/seed.ts` runs on server startup and creates:
- Default admin user: `admin@bugfinder.io` / `Admin@123!`
- Default platform settings document

---

## 10. Real-Time Features (SSE)

### Scan Streaming

When a scan runs, it emits events via the `scanEvents` EventEmitter in `scanner/index.ts`. The SSE route in `stream.ts` subscribes to these events:

```
Browser                 SSE Route (/api/stream/:jobId)      Scanner Pipeline
   │                           │                                    │
   │  GET /api/stream/:jobId   │                                    │
   │──────────────────────────►│                                    │
   │                           │ scanEvents.on('log:jobId', ...)    │
   │                           │◄───────────────────────────────────│ emit log
   │◄── event: log ────────────│                                    │
   │◄── event: finding ────────│◄───────────────────────────────────│ emit finding
   │◄── event: engine ─────────│◄───────────────────────────────────│ emit engine
   │◄── event: complete ───────│◄───────────────────────────────────│ emit complete
```

### Event Types

| Event | Payload | Description |
|---|---|---|
| `log` | `{message: string}` | General scan log message |
| `engine` | `{engine, status, message}` | Scanner module start/complete |
| `finding` | `{title, severity, endpoint, cvss_score}` | New vulnerability found |
| `progress` | `{progress: number}` | Percentage complete (0-100) |
| `complete` | `{message, risk_score}` | Scan finished |
| `error` | `{message}` | Scan error |

### AI Streaming

AI responses also use SSE. The response events contain:

| Field | Description |
|---|---|
| `content` | Token chunk to append |
| `done` | Stream finished flag |
| `error` | Error message if generation failed |

---

## 11. Database Schema & Collections

### `scan_jobs`
```
_id, target_url, scan_profile, status, progress,
created_at, started_at, completed_at,
findings_count, critical_count, high_count, medium_count, low_count, info_count,
risk_score, ai_summary,
validation_enabled, fuzzing_enabled, bug_bounty_mode,
authorization_acknowledged, scanner_engines[],
error_message, scheduled_by
```

### `findings`
```
_id, scan_job_id, target_url, title, severity, category,
endpoint, description, evidence, recommended_fix,
cvss_score, cve_id, cwe_id, scanner_name,
validation_status, fp_reason,
references[], created_at, cve_enrichment{}
```

### `targets`
```
_id, domain, risk_score, total_findings, total_scans,
last_scanned, tags[], tech_stack[],
subdomains[], risk_history[{score, date}],
notes, created_at
```

### `remediations`
```
_id, finding_id, title, description, patch_snippet,
status (pending/in_progress/completed),
sla_severity, sla_breached, sla_breached_at,
created_at, updated_at, target_url
```

### `fp_suppressions`
```
_id, domain, title, endpoint, reason, created_at
(unique index on domain+title+endpoint)
```

### `users`
```
_id, email, name, password_hash, role, is_active,
api_key, reset_token, reset_token_expires,
created_at, last_login
```

### `settings`
```
_id: "platform_settings",
ai_model, api_key,
smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from,
slack_webhook_url, github_token
```

### `scheduled_scans`
```
_id, target_url, scan_profile, cron_expression, enabled,
last_run, next_run,
validation_enabled, fuzzing_enabled, bug_bounty_mode
```

### `audit_log`
```
_id, user_id, action, resource, resource_id,
details{}, ip_address, user_agent, created_at
```

### `sessions`
Managed automatically by `connect-mongo`. TTL: 7 days.

---

## 12. Integrations

### GitHub

Configured in `integrations.ts`. When enabled (GitHub token in settings):
- `POST /api/integrations/github/create-issue` — creates a GitHub issue from a finding
- The issue title is the finding title, body includes severity, CVSS, endpoint, description
- Returns `issue_url` to display as a link in the UI

### Slack

Two Slack integration points:
1. **SLA Breach Alerts** (`scheduler.ts`) — automated hourly alerts for critical/high remediations past SLA deadline
2. **Manual notifications** via webhooks — can be triggered from integration settings

Slack messages use the attachment format with color coding: `danger` for critical, `warning` for high.

### Email (SMTP)

`services/email.ts` uses Nodemailer. Used for:
- Password reset emails (token link)
- Configurable via Settings page or environment variables

### Outbound Webhooks

`routes/webhooks.ts` manages a list of webhook URLs. Events that trigger outbound webhooks:
- New critical/high finding discovered
- Scan completed
- SLA breach detected

### NVD (National Vulnerability Database)

`GET /api/findings/:id/cve` queries:
```
https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-{n}
```
Returns CVE records with CVSS scores, descriptions, and publication dates. Results are cached in the finding's `cve_enrichment` field.

### OWASP ZAP

ZAP runs as a separate Docker container. Integration in `services/scanner/zap.ts`:
- Communicates via ZAP's REST API at `http://zap:8080`
- Used as the active scanner for the deep profile
- Results are normalized into Bug Finder's finding format

---

## 13. Key Features Breakdown

### Scheduled Scans & SLA Enforcement

`services/scheduler.ts` has two cron jobs:

**Scheduled Scans** — loaded from `scheduled_scans` collection at startup. Each enabled scheduled scan gets a `node-cron` task that:
- Creates a new `scan_jobs` document
- Calls `runScanPipeline()` asynchronously
- Updates `last_run` timestamp

**SLA Enforcement** — runs hourly (`0 * * * *`):
- Checks `remediations` for `pending`/`in_progress` items past SLA deadline
- SLA deadlines: Critical=1 day, High=7 days, Medium=30 days, Low=90 days
- Marks breached remediations with `sla_breached: true`
- Sends Slack alert for critical/high breaches

### Scan Diff / Delta View

`GET /api/scan-jobs/:id/diff`:
1. Finds the current scan's domain
2. Queries for the previous scan on the same domain (`created_at < current`)
3. Builds a lookup map of findings by key = `title||endpoint`
4. Categorizes findings into: `new_findings`, `fixed_findings`, `recurring_findings`
5. Returns counts + finding details for each category

### Kill Chain Correlation

`GET /api/scan-jobs/:id/kill-chains` detects multi-step attack paths by pattern matching against finding titles/categories. Five built-in patterns:

| Pattern | Findings Required |
|---|---|
| SSRF + Metadata Access | SSRF + cloud metadata endpoint exposure |
| SQL Injection + Auth Bypass | SQLi + authentication weakness |
| XSS + Session Hijacking | XSS + insecure cookie |
| Open Redirect + Phishing | Open redirect vulnerability |
| Admin Exposure + Brute Force | Admin panel + no rate limiting |

### False Positive Suppression

When marking a finding as FP with "suppress globally":
1. A record is written to `fp_suppressions` with key `domain+title+endpoint`
2. On future scans, before saving each finding, the scanner checks this collection
3. Matching findings are automatically marked `validation_status: "false_positive"`

### Attack Surface Map (`/attack-surface`)

Five tabs backed by `GET /api/attack-surface`:
- **Overview** — RadarChart by vulnerability category, Treemap, exposure trend AreaChart
- **Endpoints** — filterable/sortable table of all discovered endpoints with severity
- **Risk Heatmap** — target × category grid with color-coded cell risk
- **Subdomains** — all discovered subdomains with Add & Scan actions
- **Open Ports** — aggregated open port findings across all targets

### Pagination

All list endpoints support `page` and `page_size` query parameters. The response format is:
```json
{ "items": [...], "total": 150, "page": 1, "page_size": 25 }
```

### PDF Report Generation

Using `jsPDF` + `jspdf-autotable` in `scan-detail.tsx`:
1. Cover page with target, status, risk score, date, severity counts
2. Findings table with Title, Severity, CVSS, CWE, Endpoint columns
3. Purple header row (`fillColor: [109, 40, 217]`)
4. Auto-pagination for large finding lists
5. Saved as `scan-{id}-report.pdf`

---

## 14. Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `OPENCODE_API_KEY` | _(required)_ | OpenCode API key for AI features |
| `OPENCODE_API_BASE` | `https://opencode.ai/zen/v1` | OpenCode API base URL |
| `OPENCODE_MODEL` | `nemotron-3-super-free` | AI model to use |
| `MONGODB_URI` | `mongodb://bugfinder:password123@mongodb:27017/bugfinder?authSource=admin` | MongoDB connection string |
| `MONGO_USER` | `bugfinder` | MongoDB username |
| `MONGO_PASSWORD` | `password123` | MongoDB password |
| `MONGO_DB` | `bugfinder` | MongoDB database name |
| `SESSION_SECRET` | `bug-finder-secret-change-in-prod` | Express session signing secret |
| `GITHUB_TOKEN` | _(optional)_ | GitHub Personal Access Token for issue creation |
| `SLACK_WEBHOOK_URL` | _(optional)_ | Slack incoming webhook URL for alerts |
| `SMTP_HOST` | _(optional)_ | SMTP server for email notifications |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | _(optional)_ | SMTP username |
| `SMTP_PASS` | _(optional)_ | SMTP password |
| `SMTP_FROM` | `noreply@bugfinder.io` | From address for emails |
| `NODE_ENV` | `development` | Node environment |
| `PORT` | `5000` | API server port |
| `ZAP_URL` | `http://zap:8080` | OWASP ZAP API URL |

Set these in a `.env` file at the project root. Docker Compose reads it automatically.

---

## 15. Running the Application

### Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine + Docker Compose (Linux)
- At minimum 4GB RAM available to Docker

### Quick Start

```bash
# 1. Clone / navigate to project directory
cd "Bug-Finder"

# 2. Create .env file
echo "OPENCODE_API_KEY=your_key_here" > .env

# 3. Build and start all services
docker-compose up -d --build

# 4. Wait ~30 seconds for services to initialize, then open:
#    App:     http://localhost:3000
#    API:     http://localhost:5000/api/health
#    Grafana: http://localhost:3001
```

### Default Credentials

| Field | Value |
|---|---|
| Email | `admin@bugfinder.io` |
| Password | `Admin@123!` |

### Rebuild After Code Changes

```bash
# Rebuild only changed services (faster)
docker-compose build --no-cache frontend api-server
docker-compose up -d frontend api-server

# Full rebuild of everything
docker-compose down
docker-compose up -d --build
```

### Viewing Logs

```bash
# All services
docker-compose logs -f

# Just the API
docker-compose logs -f api-server

# Just the frontend
docker-compose logs -f frontend
```

### Stopping

```bash
docker-compose down        # stops containers, keeps volumes
docker-compose down -v     # stops containers AND deletes all data
```

---

*Bug Finder Pro — Built with React, Express, MongoDB, OWASP ZAP, and OpenCode AI*
