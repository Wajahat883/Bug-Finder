# Bug Finder Pro — Complete Design & Architecture Guide

> Your comprehensive visual handbook for understanding, navigating, and extending the Bug Finder Pro application.

---

## Quick Navigation

| Document | Purpose | Read If You... |
|----------|---------|----------------|
| [`DESIGN_SYSTEM.md`](design/DESIGN_SYSTEM.md) | Colors, typography, components, themes | Want to build new UI |
| [`FOLDER_ARCHITECTURE.md`](design/FOLDER_ARCHITECTURE.md) | Proposed clean folder structure | Are restructuring code |
| [`APPLICATION_STORYBOARD.md`](design/APPLICATION_STORYBOARD.md) | Frame-by-frame app walkthrough | Need to demo the product |
| [`UI_SCREEN_MAP.md`](design/UI_SCREEN_MAP.md) | Every screen and how they connect | Are adding new pages |
| [`DATA_FLOW.md`](design/DATA_FLOW.md) | How data moves through the system | Are debugging or extending backend |

**Visual Assets:**
- [`architecture-diagram.svg`](assets/architecture-diagram.svg) — System architecture overview
- [`scan-lifecycle.svg`](assets/scan-lifecycle.svg) — How a scan works from start to finish
- [`ui-showcase.svg`](assets/ui-showcase.svg) — Component library visual reference

---

## What Is Bug Finder Pro?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   Bug Finder Pro is a full-stack cybersecurity platform that lets teams:    │
│                                                                             │
│   🔍  Launch security scans against any target (URL, domain, IP)           │
│   ⚡  Watch findings appear in real time via Server-Sent Events            │
│   🤖  Get AI-powered analysis and remediation advice (Claude/OpenCode)     │
│   📊  Visualize risk posture with executive dashboards                     │
│   🐙  Create GitHub issues directly from findings                          │
│   ⏱️  Track SLA deadlines automatically                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Built With:** React 18 + TypeScript + Vite (frontend) · Express + MongoDB (backend) · OWASP ZAP (scanner) · Anthropic Claude / OpenCode AI

---

## The Big Picture

### Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: PRESENTATION                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  React SPA (Vite)                                       │    │
│  │  • Dark cybersecurity theme (default)                   │    │
│  │  • 30+ pages across 4 nav groups                        │    │
│  │  • Real-time SSE streaming UI                           │    │
│  │  • Interactive charts (Recharts) + node graphs          │    │
│  └─────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: API / BUSINESS LOGIC                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Express API Server (Node.js)                           │    │
│  │  • 22 route modules covering all domains                │    │
│  │  • Session-based auth with MongoDB store                │    │
│  │  • 60+ scanner modules (crawl, inject, recon, cloud)    │    │
│  │  • AI streaming with retry logic                        │    │
│  │  • PDF report generation (pdfkit)                       │    │
│  └─────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: DATA & INFRASTRUCTURE                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  MongoDB 7 (primary database + session store)           │    │
│  │  OWASP ZAP (active vulnerability scanner)               │    │
│  │  OpenCode AI (streaming analysis)                       │    │
│  │  Docker Compose (full stack orchestration)              │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## How It Looks: Visual Tour

### 1. The Landing Page
Dark, cyber-themed public homepage with an animated terminal preview showing a live scan.

```
Background: #0a0a0f (deep space black)
Hero text: Gradient purple → cyan → purple
Accent: Purple glow (#7c3aed) on buttons and logo
Feel: Professional, modern, security-focused
```

### 2. The Login Screen
Split-panel layout: branding on the left, clean form on the right.

```
Left:  Dark purple gradient with live scan widget
Right: White/light gray form panel
Fields: Email, Password, Password strength meter
Demo:  "Continue as Demo Admin" for instant access
```

### 3. The App Shell (Authenticated)
Sidebar + header + main content area.

```
Sidebar: 200px fixed, dark background (#08080c)
  ├─ Logo: Purple gradient "B" + "Bug Finder Pro"
  ├─ Core: Dashboard, Scans, Findings, Targets, Remediations
  ├─ Analytics: Executive, Attack Surface, OWASP, Timeline, Compliance, SLA
  ├─ AI & Tools: AI Triage, Scan Compare, Templates, CVSS Calc
  └─ Config: Integrations, Audit Log, System, Settings, User Mgmt

Header: Breadcrumb + Command Palette trigger (⌘K) + 🔔 + Theme + Profile
Main: Scrollable content area with 24px padding
```

### 4. The Dashboard
Your security operations command center.

```
┌────────────────────────────────────────────────────────────┐
│  [1,247 Findings] [42 Critical] [12 Active] [94% SLA OK]   │
│                                                            │
│  [ Risk Trend Line Chart ]    [ Severity Donut Chart ]     │
│                                                            │
│  [ Recent Activity Feed ]                                  │
│     • Scan #2842 completed — 8 findings                    │
│     • Critical: SQL Injection on /api/users                │
│     • High: Missing CSP header                             │
└────────────────────────────────────────────────────────────┘
```

### 5. Live Scan Streaming
The most visually impressive feature.

```
Target: https://api.target.com    Status: 🟢 RUNNING
Progress: [████████████████████░░░░] 78%

LIVE FINDINGS:
🔴 Missing CSP Header          /api/admin    High    7.5
🟡 CORS Wildcard Origin        /api/data     Medium  5.3
🔴 SQL Injection in 'id'       /api/users    Critical 9.8  ← Just appeared!
⚪ X-Frame-Options Missing     /login        Info    3.1

→ New findings slide in with a subtle animation
→ Critical findings flash red and trigger a toast + sound
```

### 6. AI Analysis Panel
Claude-powered streaming text that appears word-by-word.

```
┌────────────────────────────────────────┐
│  🤖 AI Analysis by Claude               │
│  ─────────────────────────────────────  │
│  This scan of api.target.com reveals    │
│  a critical SQL injection vulnerability │
│  in the user lookup endpoint...         │
│                    ▓▓▓▓▓▓▓▓▓▓▓▓        │
│  [Text streams in real time]            │
└────────────────────────────────────────┘
```

### 7. Executive Dashboard
Board-ready charts for stakeholder reporting.

```
┌────────────────────────────────────────┐
│  Risk Posture Score: 73/100  ↑ 8%      │
│                                        │
│  [🍩 Severity Donut]  [📊 Top Targets] │
│                                        │
│  [📈 Finding Velocity (30 days)]       │
└────────────────────────────────────────┘
```

---

## How It Works: Key Flows

### Flow 1: Creating and Running a Scan

```
User clicks "New Scan"
    ↓
Enters target URL + selects profile (Quick / Standard / Deep)
    ↓
Checks "Authorization acknowledged" (compliance)
    ↓
Clicks "Launch Scan"
    ↓
POST /api/scans → Creates scan_job document (status: "queued")
    ↓
API server triggers runScanPipeline() asynchronously
    ↓
Scanner runs modules based on profile:
    Quick:  ~15 modules (crawl, headers, TLS, DNS, passive)
    Standard: ~30 modules (+ injection tests, auth checks)
    Deep:   60+ modules (+ GraphQL, gRPC, cloud, ZAP)
    ↓
Each finding is:
    1. Checked against fp_suppressions (deduplication)
    2. Saved to MongoDB findings collection
    3. Emitted via SSE to connected clients
    4. Assigned SLA deadline based on severity
    ↓
Client receives SSE events:
    → progress: { percentage, current_module }
    → finding:  { title, severity, endpoint, cvss }
    → complete: { risk_score, summary }
    ↓
User sees findings appear in real time on scan detail page
```

### Flow 2: AI Analysis Request

```
User clicks "Analyze with AI" on a scan
    ↓
POST /api/ai/scan-summary/:scanId
    ↓
Server builds prompt with:
    - Target URL
    - All findings with severity and CVSS
    - OWASP categories
    ↓
Server calls OpenCode API with stream: true
    ↓
AI streams tokens back chunk-by-chunk
    ↓
Server forwards each chunk as SSE event:
    data: {"content": "This scan reveals..."}
    ↓
Client parses SSE with TextDecoder
    ↓
React app appends text character-by-character
    ↓
User sees AI response type out in real time
```

### Flow 3: Critical Finding Alert

```
Scanner discovers CRITICAL finding
    ↓
Server emits SSE finding event
    ↓
Client receives event:
    → Adds to notification dropdown
    → Shows toast popup with "View" button
    → Plays 880Hz audio ping (if not muted)
    ↓
Server checks webhook settings
    → If Slack configured: sends formatted alert
    → If custom webhook: POSTs JSON payload
    → Writes to audit_log collection
    ↓
SLA scheduler (hourly cron):
    → If past deadline: marks sla_breached: true
    → Sends additional Slack alert
```

---

## Design System At a Glance

### Colors

```
Primary:   #7c3aed (violet purple)
Critical:  #ef4444 (red)
High:      #f97316 (orange)
Medium:    #eab308 (yellow)
Low:       #22d3ee (cyan)
Info:      #34d399 (green)

Background (dark):  #0a0a0f
Card (dark):        #111118
Sidebar (dark):     #08080c
Text primary:       #e8e8ef
Text muted:         #6b6b80
```

### Typography

```
Sans-serif: Inter (headings, body, UI)
Monospace:  Space Mono / Fira Code (code, terminals, data)
Scale:      Hero 48px → H1 32px → H2 24px → Body 14px → Small 12px
```

### Themes

```
Dark (default):   Deep space blacks + neon severity colors
Light:            Clean white-gray + deep saturated colors
High Contrast:    Pure black/white + maximum contrast primary
Switch:           Press "T" anywhere or click theme icon
```

---

## Proposed Folder Restructure

The current structure works, but for long-term maintainability, we recommend migrating to a **domain-driven architecture**:

```
Bug-Finder/
├── apps/
│   ├── web/              ← React frontend (moved from artifacts/frontend)
│   └── api/              ← Express backend (moved from artifacts/backend)
├── packages/
│   ├── ui/               ← shadcn component library
│   ├── api-client/       ← Generated OpenAPI client
│   └── config/           ← Shared tooling configs
├── services/
│   └── scanner/          ← 60+ scan modules (moved from backend/src/services/scanner)
├── infrastructure/
│   └── docker/           ← Docker + compose files
└── docs/
    ├── design/           ← This documentation
    └── architecture/     ← ADRs and diagrams
```

**Benefits:**
- Each feature lives in one place — no more hunting across folders
- Teams can own domains without merge conflicts
- Shared packages enforce consistency
- Easier to add new apps (mobile, CLI) later

See [`FOLDER_ARCHITECTURE.md`](design/FOLDER_ARCHITECTURE.md) for full migration plan.

---

## Quick Reference: All Routes

### Public (no auth)
| Route | Page |
|-------|------|
| `/` | Landing page |
| `/login` | User login / register |
| `/admin` | Admin login |
| `/forgot-password` | Password reset request |
| `/reset-password` | Password reset confirm |

### Authenticated (inside AppLayout)
| Route | Page | Group |
|-------|------|-------|
| `/dashboard` | Dashboard | Core |
| `/scans` | Scan list | Core |
| `/scans/new` | New scan | Core |
| `/scans/:id` | Scan detail (live stream) | Core |
| `/scans/compare` | Side-by-side diff | Core |
| `/findings` | Global findings list | Core |
| `/findings/:id` | Finding detail + CVSS + AI | Core |
| `/targets` | Target management | Core |
| `/targets/:id` | Target detail | Core |
| `/remediations` | Fix tracking | Core |
| `/executive` | Executive dashboard | Analytics |
| `/attack-surface` | Interactive node graph | Analytics |
| `/owasp` | OWASP Top 10 heatmap | Analytics |
| `/timeline` | Activity timeline | Analytics |
| `/compliance` | PCI/ISO mapping | Analytics |
| `/sla` | SLA breach tracking | Analytics |
| `/ai-triage` | AI chat interface | AI & Tools |
| `/scan-templates` | Saved configurations | AI & Tools |
| `/cvss` | Interactive calculator | AI & Tools |
| `/settings` | Platform config | Config |
| `/system` | Health checks | Config |
| `/notifications` | Notification history | Config |

### Admin Only
| Route | Page |
|-------|------|
| `/audit-log` | Security audit trail |
| `/integrations` | GitHub/Slack/webhooks |
| `/admin/users` | User management |

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `⌘K` / `Ctrl+K` | Open command palette |
| `/` | Open command palette (when not in input) |
| `N` | Go to New Scan |
| `F` | Go to Findings |
| `R` | Go to Remediations |
| `T` | Cycle theme (Dark → Light → High Contrast) |
| `Esc` | Close modals / dropdowns |

---

## Running the Application

```bash
# 1. Install dependencies
pnpm install

# 2. Set up environment
cp .env.example .env
# Edit .env with your DATABASE_URL, SESSION_SECRET, etc.

# 3. Start everything with Docker
docker-compose up -d --build

# 4. Or start individually:
pnpm --filter @workspace/api-server run dev    # Backend
pnpm --filter @workspace/bug-bounty-pro run dev # Frontend

# App: http://localhost:3000
# API: http://localhost:5000
# Grafana: http://localhost:3001
```

**Default Login:**
- Email: `admin@bugfinder.io`
- Password: `Admin@123!`

---

## Visual Assets Included

| File | Description | Format |
|------|-------------|--------|
| `architecture-diagram.svg` | Full system architecture with all services | SVG |
| `scan-lifecycle.svg` | 10-step scan flow from creation to completion | SVG |
| `ui-showcase.svg` | Buttons, badges, cards, forms, nav components | SVG |

Open these in any browser or design tool (Figma, Illustrator) for high-resolution viewing.

---

## Contributing to Design

When adding new features:

1. **Check the Design System first** — use existing colors, spacing, and components
2. **Follow the domain folder pattern** — put pages in `domain/<feature>/pages/`
3. **Use severity colors consistently** — critical=#ef4444, high=#f97316, etc.
4. **Add to the storyboard** — update `APPLICATION_STORYBOARD.md` with new frames
5. **Update this guide** — keep `PROJECT_GUIDE.md` in sync with changes

---

*Complete Design Guide v1.0 — Bug Finder Pro*
*Generated for visual documentation and team onboarding*
