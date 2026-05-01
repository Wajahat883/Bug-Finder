# Bug Finder Pro

**Bug Finder Pro** is a full-stack, enterprise-grade security scanning and vulnerability management platform. It combines real-time scanning, AI-powered analysis, OWASP Top 10 coverage, CVSS 3.1 scoring, SLA enforcement, GitHub integration, and executive-level dashboards — all in a single modern web application.

---

## Table of Contents

1. [Overview](#overview)
2. [Tech Stack](#tech-stack)
3. [Project Structure](#project-structure)
4. [Features](#features)
5. [How We Built It](#how-we-built-it)
   - [1. Monorepo Setup](#1-monorepo-setup)
   - [2. Database & Schema](#2-database--schema)
   - [3. Authentication System](#3-authentication-system)
   - [4. Scan Engine & SSE Streaming](#4-scan-engine--sse-streaming)
   - [5. AI Integration (Claude)](#5-ai-integration-claude)
   - [6. CVSS 3.1 Scoring](#6-cvss-31-scoring)
   - [7. OWASP Top 10 Classification](#7-owasp-top-10-classification)
   - [8. SLA Enforcement](#8-sla-enforcement)
   - [9. Audit Logging & Deduplication](#9-audit-logging--deduplication)
   - [10. GitHub & Slack Webhooks](#10-github--slack-webhooks)
   - [11. Executive Dashboard & Analytics](#11-executive-dashboard--analytics)
   - [12. Attack Surface Map](#12-attack-surface-map)
   - [13. PDF Report Generation](#13-pdf-report-generation)
   - [14. Landing Page & Auth UI](#14-landing-page--auth-ui)
   - [15. OpenAPI Contract & Code Generation](#15-openapi-contract--code-generation)
6. [Getting Started](#getting-started)
7. [Environment Variables](#environment-variables)
8. [API Reference](#api-reference)
9. [Screenshots](#screenshots)

---

## Overview

Bug Finder Pro allows security teams to:

- **Define targets** (domains, IPs, URLs) and launch comprehensive security scans
- **Stream findings live** as they are discovered using Server-Sent Events (SSE)
- **Classify vulnerabilities** against OWASP Top 10 with automatic CVSS 3.1 severity scoring
- **Get AI-generated remediation** for every finding via Anthropic Claude
- **Track SLA deadlines** — Critical (24h), High (72h), Medium (7d), Low (30d)
- **Create GitHub issues** directly from findings with one click
- **Send Slack alerts** and configure custom webhooks for any event
- **Export PDF reports** with executive summaries, risk posture graphs, and full finding lists
- **Visualize the attack surface** as an interactive node graph
- **Monitor audit logs**, deduplicate findings, and manage remediations

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Wouter (routing), TanStack Query |
| **Backend** | Node.js, Express, TypeScript, esbuild |
| **Database** | PostgreSQL (via `pg` pool) |
| **AI** | Anthropic Claude (via `@anthropic-ai/sdk`) with streaming |
| **API Contract** | OpenAPI 3.0 spec → Orval codegen (Zod schemas + React Query hooks) |
| **Auth** | Session-based (express-session + connect-pg-simple), bcrypt password hashing |
| **Streaming** | Server-Sent Events (SSE) for live scan progress and AI responses |
| **PDF** | `pdfkit` for server-side report generation |
| **Icons** | Lucide React |
| **Monorepo** | pnpm workspaces |

---

## Project Structure

```
Bug-Finder/
├── artifacts/
│   ├── api-server/               # Express backend
│   │   ├── src/
│   │   │   ├── app.ts            # Express app setup, session, middleware
│   │   │   ├── lib/
│   │   │   │   ├── pgDb.ts       # PostgreSQL pool singleton
│   │   │   │   ├── schema.ts     # DB table creation & migrations
│   │   │   │   ├── logger.ts     # Pino logger singleton
│   │   │   │   ├── audit.ts      # Audit log helper
│   │   │   │   └── seed.ts       # Demo data seeder
│   │   │   └── routes/
│   │   │       ├── auth.ts       # Login, register, demo, logout, /me
│   │   │       ├── scans.ts      # Scan CRUD + SSE streaming
│   │   │       ├── findings.ts   # Findings CRUD + CVSS + dedup
│   │   │       ├── targets.ts    # Target management
│   │   │       ├── remediations.ts
│   │   │       ├── analytics.ts  # Executive, attack surface, OWASP, timeline
│   │   │       ├── ai.ts         # Claude streaming routes
│   │   │       ├── pdf.ts        # PDF report export
│   │   │       ├── webhooks.ts   # GitHub & Slack integration
│   │   │       ├── audit-log.ts
│   │   │       └── system.ts     # Health check
│   │   ├── build.mjs             # esbuild production bundler
│   │   └── package.json
│   │
│   ├── bug-bounty-pro/           # React frontend (Vite)
│   │   ├── src/
│   │   │   ├── App.tsx           # Router (Wouter) — landing, login, app
│   │   │   ├── pages/
│   │   │   │   ├── landing.tsx   # Public landing page
│   │   │   │   ├── login.tsx     # Split-panel auth (login + register)
│   │   │   │   ├── dashboard.tsx # Main dashboard + stats
│   │   │   │   ├── scans.tsx     # Scan list
│   │   │   │   ├── scan-detail.tsx # Live SSE scan + findings
│   │   │   │   ├── new-scan.tsx  # Scan creation form
│   │   │   │   ├── findings.tsx  # Global findings list
│   │   │   │   ├── finding-detail.tsx # CVSS + AI advice + GitHub issue
│   │   │   │   ├── targets.tsx
│   │   │   │   ├── target-detail.tsx
│   │   │   │   ├── remediations.tsx
│   │   │   │   ├── executive.tsx # Executive dashboard
│   │   │   │   ├── attack-surface.tsx
│   │   │   │   ├── owasp.tsx
│   │   │   │   ├── timeline.tsx
│   │   │   │   ├── cvss.tsx      # Interactive CVSS calculator
│   │   │   │   ├── audit-log.tsx
│   │   │   │   ├── integrations.tsx
│   │   │   │   ├── settings.tsx
│   │   │   │   └── system.tsx
│   │   │   └── components/
│   │   │       └── layout.tsx    # App shell (sidebar nav + auth guard)
│   │   └── package.json
│   │
│   └── mockup-sandbox/           # Canvas component preview server (Vite)
│       └── src/components/mockups/
│           ├── landing/LandingPage.tsx
│           └── auth/AuthPage.tsx
│
├── lib/
│   ├── api-spec/                 # OpenAPI 3.0 YAML spec
│   ├── api-zod/                  # Generated Zod schemas (Orval)
│   └── api-client-react/         # Generated React Query hooks (Orval)
│
├── pnpm-workspace.yaml
└── README.md
```

---

## Features

### Core Security Scanning
- Launch scans against any target URL, domain, or IP
- Real-time finding stream via SSE — findings appear as discovered
- Authorization acknowledgment required before scanning (compliance)
- Scanner engine selection (passive, active, full)

### Vulnerability Management
- Full CRUD for findings with CVSS 3.1 vector and score
- Severity classification: Critical, High, Medium, Low, Informational
- Finding deduplication — prevents duplicate entries across scans
- Status workflow: Open → In Progress → Resolved → Accepted Risk

### AI-Powered Analysis (Claude)
- Streaming executive summary per scan (business-level language)
- Per-finding remediation advice streamed in real time
- Context-aware — understands the target, finding type, and severity

### OWASP Top 10
- Every finding is mapped to an OWASP category (A01–A10)
- OWASP dashboard shows coverage heatmap across all scans
- Breakdown charts per category with finding counts

### CVSS 3.1 Calculator
- Interactive calculator with all 8 Base metric groups
- Real-time score calculation (0.0–10.0) with severity label
- Vector string generation and storage per finding

### SLA Enforcement
- Automatic deadline assignment based on severity:
  - Critical → 24 hours
  - High → 72 hours
  - Medium → 7 days
  - Low → 30 days
- Color-coded urgency — overdue findings highlighted in red

### GitHub Integration
- One-click issue creation from any finding
- Issue body includes: severity, CVSS score, OWASP category, description, steps to reproduce, remediation
- Uses GitHub PAT stored as an environment secret

### Slack & Webhook Alerts
- Configure custom webhooks for events: scan started, finding created, scan completed
- Built-in Slack webhook template with rich message formatting
- Webhook delivery log with retry status

### Executive Dashboard
- Risk posture score (0–100) with trend over time
- Severity breakdown donut charts
- Top vulnerable targets ranked by risk
- Finding velocity graph (findings over time)

### Attack Surface Map
- Interactive node graph of targets, scans, and findings
- Nodes colored by severity — visual risk assessment at a glance
- Click any node to navigate to the detail page

### Audit Log
- Every action logged: login, scan created, finding updated, issue created, etc.
- Filterable by user, entity type, and date range

### PDF Export
- Full scan report generated server-side with `pdfkit`
- Includes: executive summary, risk score, CVSS breakdown, full finding list with details

### Authentication
- Session-based auth with secure httpOnly cookies
- Register with first name, last name, email, password
- Password hashing with bcrypt (10 rounds)
- Demo admin account for instant access
- Role system: admin, analyst

---

## How We Built It

### 1. Monorepo Setup

The project uses **pnpm workspaces** to manage three layers:

- `lib/` — shared packages (OpenAPI spec, generated Zod schemas, React Query hooks)
- `artifacts/` — deployable services (API server, React frontend, mockup sandbox)
- `scripts/` — utility scripts

We defined the workspace in `pnpm-workspace.yaml` and used a global reverse proxy to route traffic by path — `/api` goes to the Express server, `/` goes to the React app.

TypeScript is configured with a solution file at the root for composite `lib/` packages, and `tsc --noEmit` for artifact packages (no emit needed for Vite/esbuild apps).

### 2. Database & Schema

PostgreSQL is used as the primary database via the `pg` pool. The schema is created on server startup using `CREATE TABLE IF NOT EXISTS` statements in `schema.ts`, which also runs safe `ALTER TABLE ADD COLUMN IF NOT EXISTS` migrations for new columns.

**Tables:**
- `users` — id, username, email, password (bcrypt), role, first_name, last_name
- `sessions` — express-session persistence via `connect-pg-simple`
- `audit_log` — structured event log with user, entity, action, metadata
- `scan_jobs` — scan state machine (pending → running → complete/failed)
- `findings` — vulnerability records with CVSS, OWASP, SLA fields
- `targets` — scan targets with metadata
- `remediations` — remediation plans linked to findings
- `webhooks` — configured webhook endpoints
- `documents` — JSONB key-value store for flexible data

### 3. Authentication System

Authentication uses **express-session** with **connect-pg-simple** to persist sessions in PostgreSQL. Sessions are signed with a `SESSION_SECRET` environment variable.

- `POST /api/auth/register` — accepts firstName, lastName, email, password. Auto-generates a username from the name. Hashes password with bcrypt.
- `POST /api/auth/login` — validates credentials, sets session.
- `POST /api/auth/demo` — creates/upserts a demo admin account for instant access.
- `GET /api/auth/me` — returns current session user.
- `POST /api/auth/logout` — destroys session and clears cookie.

In production, cookies are set with `secure: true` and the Express app uses `trust proxy: 1` for correct TLS detection behind the reverse proxy.

### 4. Scan Engine & SSE Streaming

Scans are created via `POST /api/scans` and run asynchronously. The client opens an SSE connection to `GET /api/scans/:id/stream` which receives:

- `progress` events — percentage complete and current check name
- `finding` events — new vulnerability discovered (streamed as JSON)
- `complete` / `error` events — scan finished

The scan engine runs a series of security checks against the target (TLS, headers, CORS, injection patterns, etc.) and emits findings as they are discovered, giving users a real-time view of the scan as it progresses.

Authorization acknowledgment (`authorization_acknowledged: "authorized"`) is required in the scan creation payload as a compliance safeguard.

### 5. AI Integration (Claude)

Two AI streaming routes power the AI features:

- `GET /api/ai/scan-summary/:scanId` — streams an executive summary of the full scan
- `GET /api/ai/finding-advice/:findingId` — streams specific remediation advice for a finding

Both use Anthropic's Claude via `@anthropic-ai/sdk` with `stream: true`. The response is piped to the client via SSE, so text appears word-by-word in the UI. The prompts include the full scan context, target information, and all finding details for accurate, contextual output.

### 6. CVSS 3.1 Scoring

An interactive CVSS 3.1 calculator (`/cvss`) lets analysts score any vulnerability using all 8 Base metric groups:

- Attack Vector, Attack Complexity, Privileges Required, User Interaction
- Scope, Confidentiality, Integrity, Availability

Scores are calculated in real time using the CVSS 3.1 formula and displayed with the severity label (None / Low / Medium / High / Critical). The resulting score and vector string are stored with each finding.

### 7. OWASP Top 10 Classification

Every finding is assigned an OWASP Top 10 category (A01 through A10). The OWASP dashboard (`/owasp`) shows:

- A heatmap of categories by finding count and severity
- The `short` code, full `name`, and finding breakdown per category
- Coverage percentage across all scans

### 8. SLA Enforcement

SLA deadlines are automatically assigned when a finding is created based on its severity. The system tracks:

- Due date for each finding
- Whether the deadline has been breached
- Days remaining / days overdue

Findings approaching or past their SLA are highlighted with color-coded urgency indicators in the UI.

### 9. Audit Logging & Deduplication

**Audit Logging** — every significant action (login, scan created, finding updated, issue created, webhook triggered) is recorded in `audit_log` with:
- `user_id`, `action`, `entity_type`, `entity_id`, `metadata` (JSONB), `created_at`, `ip_address`

**Deduplication** — when a new finding is created, the system checks for existing findings with the same target + title + OWASP category combination. Duplicates are flagged rather than created, keeping the finding list clean.

### 10. GitHub & Slack Webhooks

**GitHub Integration** — from any finding detail page, clicking "Create GitHub Issue" calls `POST /api/webhooks/github/issue` which:
1. Reads the finding details
2. Formats a rich issue body with severity, CVSS score, OWASP category, description, and remediation steps
3. Uses the `GITHUB_PAT` to call the GitHub API and create the issue

**Slack Webhooks** — the webhook system allows configuring Slack incoming webhook URLs. Events (scan started, finding found, scan complete) trigger POST requests to the configured URL with a formatted Slack message payload.

### 11. Executive Dashboard & Analytics

Four analytics endpoints power the reporting layer:

- `GET /api/analytics/executive` — risk posture score, severity distribution, top targets, trend data
- `GET /api/analytics/attack-surface` — graph nodes and edges representing targets, scans, findings
- `GET /api/analytics/owasp` — per-category breakdown with short codes and finding counts
- `GET /api/analytics/timeline` — activity events over time (scans launched, findings discovered)

### 12. Attack Surface Map

The attack surface page (`/attack-surface`) visualizes the entire security posture as a force-directed node graph. Nodes represent:

- **Targets** (blue) — the assets being scanned
- **Scans** (purple) — scan jobs linked to targets
- **Findings** (red/orange/yellow by severity) — vulnerabilities linked to scans

Clicking any node navigates to the relevant detail page.

### 13. PDF Report Generation

`GET /api/scans/:id/pdf` generates a complete PDF scan report server-side using `pdfkit`. The report includes:

- Cover page with scan metadata, target, and overall risk score
- Executive summary (AI-generated)
- Severity breakdown table
- Full finding list with CVSS scores, OWASP categories, and descriptions
- SLA compliance status

### 14. Landing Page & Auth UI

The public-facing pages were designed as **canvas mockups** first — letting us iterate on the visual design in an isolated sandbox before integrating into the main app.

**Landing Page (`/`):**
- Dark cybersecurity theme with gradient hero headline
- Animated terminal preview showing a live scan in progress
- Stats, features grid, OWASP coverage badges, CTA sections
- Checks auth on load — redirects to `/dashboard` if already signed in

**Auth Page (`/login`):**
- Split-panel layout: dark branding panel (left) + form panel (right)
- Sign In and Create Account tabs
- Register form: First name, Last name, Email, Password (with strength meter), Confirm password (with live match indicator)
- "Continue as Demo Admin" for instant access

### 15. OpenAPI Contract & Code Generation

The entire API is defined in an **OpenAPI 3.0 YAML spec** (`lib/api-spec`). From this single source of truth, we generate:

- **Zod validation schemas** (`lib/api-zod`) — used by the Express server to validate request/response bodies
- **React Query hooks** (`lib/api-client-react`) — used by the frontend for all data fetching with built-in caching, loading states, and error handling

Codegen runs with:
```bash
pnpm --filter @workspace/api-spec run codegen
```

This contract-first approach ensures the frontend and backend stay in sync and breaks are caught at compile time.

---

## Getting Started

### Prerequisites

- Node.js 20+
- pnpm 9+
- PostgreSQL database (connection string via `DATABASE_URL`)

### Installation

```bash
# Clone the repository
git clone https://github.com/Wajahat883/Bug-Finder.git
cd Bug-Finder

# Install all dependencies
pnpm install

# Set up environment variables (see below)
cp .env.example .env
```

### Running in Development

```bash
# Start the API server
pnpm --filter @workspace/api-server run dev

# Start the React frontend (in another terminal)
pnpm --filter @workspace/bug-bounty-pro run dev
```

The API server runs on `PORT` (default 3001) and the frontend on `PORT` (default 5173). A reverse proxy routes `/api` to the backend and `/` to the frontend.

### Building for Production

```bash
# Build the API server
pnpm --filter @workspace/api-server run build

# Build the frontend
pnpm --filter @workspace/bug-bounty-pro run build
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SESSION_SECRET` | Yes | Secret for signing session cookies (min 32 chars) |
| `GITHUB_PAT` | Optional | GitHub Personal Access Token for issue creation |
| `ANTHROPIC_API_KEY` | Optional | Anthropic API key for AI features |
| `PORT` | No | Server port (default: auto-assigned) |
| `NODE_ENV` | No | `production` enables secure cookies |

---

## API Reference

### Authentication
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Register new account |
| POST | `/api/auth/login` | Sign in |
| POST | `/api/auth/logout` | Sign out |
| GET | `/api/auth/me` | Current user |
| POST | `/api/auth/demo` | Demo admin login |

### Scans
| Method | Path | Description |
|---|---|---|
| GET | `/api/scans` | List all scans |
| POST | `/api/scans` | Create new scan |
| GET | `/api/scans/:id` | Get scan details |
| DELETE | `/api/scans/:id` | Delete scan |
| GET | `/api/scans/:id/stream` | SSE — live scan progress |
| GET | `/api/scans/:id/pdf` | Export PDF report |

### Findings
| Method | Path | Description |
|---|---|---|
| GET | `/api/findings` | List findings (filterable) |
| POST | `/api/findings` | Create finding |
| GET | `/api/findings/:id` | Get finding |
| PATCH | `/api/findings/:id` | Update finding |
| DELETE | `/api/findings/:id` | Delete finding |

### Targets
| Method | Path | Description |
|---|---|---|
| GET | `/api/targets` | List targets |
| POST | `/api/targets` | Create target |
| GET | `/api/targets/:id` | Get target |
| PATCH | `/api/targets/:id` | Update target |

### Analytics
| Method | Path | Description |
|---|---|---|
| GET | `/api/analytics/executive` | Executive dashboard data |
| GET | `/api/analytics/attack-surface` | Attack surface graph |
| GET | `/api/analytics/owasp` | OWASP breakdown |
| GET | `/api/analytics/timeline` | Activity timeline |

### AI
| Method | Path | Description |
|---|---|---|
| GET | `/api/ai/scan-summary/:scanId` | Stream AI scan summary |
| GET | `/api/ai/finding-advice/:findingId` | Stream AI remediation advice |

### Integrations
| Method | Path | Description |
|---|---|---|
| GET | `/api/webhooks` | List webhooks |
| POST | `/api/webhooks` | Create webhook |
| POST | `/api/webhooks/github/issue` | Create GitHub issue from finding |

---

## Screenshots

### Landing Page
Dark cybersecurity-themed public homepage with animated terminal scan preview, OWASP coverage grid, and feature highlights.

### Login / Register
Split-panel auth UI — branding panel with live scan widget on the left, clean form with password strength indicator on the right.

### Dashboard
Real-time stats: total findings by severity, active scans, targets at risk, SLA compliance rate, and recent activity feed.

### Scan Detail
Live SSE-streamed scan view — findings appear in real time as vulnerabilities are discovered, with severity badges and CVSS scores.

### AI Analysis
Claude-powered streaming summaries and per-finding remediation advice rendered word-by-word in the UI.

### Executive Dashboard
Board-ready charts: risk posture score, severity donut, top vulnerable targets, finding velocity over time.

### Attack Surface Map
Interactive force-directed node graph showing targets, scans, and findings colored by severity.

### CVSS Calculator
Interactive CVSS 3.1 Base Score calculator with all metric groups and real-time score calculation.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with React, TypeScript, Express, PostgreSQL, and Anthropic Claude.*
