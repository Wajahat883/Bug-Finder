# Bug Finder Pro — Data Flow & Architecture

> How data moves through the system, from scan launch to AI analysis to notification.

---

## System Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Browser    │  │  React SPA  │  │ TanStack    │  │  SSE EventSource    │  │
│  │             │  │  (Vite)     │  │ Query v5    │  │  (Real-time)        │  │
│  │  User       │  │  Wouter     │  │ Caching     │  │  Notifications      │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                │                    │             │
│         └────────────────┴────────────────┴────────────────────┘             │
│                                   │                                          │
│                              HTTP / SSE                                      │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼───────────────────────────────────────────┐
│                         REVERSE PROXY (Nginx)                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │  /api/*    →  proxy_pass http://api-server:5000                         │  │
│  │  /         →  try_files $uri /index.html (SPA)                         │  │
│  │  /stream/* →  proxy_pass (SSE support with buffering off)              │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼───────────────────────────────────────────┐
│                      API SERVER (Node.js + Express)                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │  Middleware Stack:                                                      │  │
│  │  1. pino-http        → Request logging                                  │  │
│  │  2. cors             → Cross-origin with credentials                    │  │
│  │  3. express-session  → MongoDB-backed sessions                          │  │
│  │  4. express.json     → Body parsing                                     │  │
│  │  5. apiKeyAuth       → X-API-Key validation                             │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                          │
│  ┌─────────────────────────────────┼────────────────────────────────────────┐│
│  │         ROUTE HANDLERS          │                                       ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────┴─────┐ ┌─────────┐ ┌─────────┐        ││
│  │  │ /auth   │ │ /scans  │ │ /findings │ │/analytics│ │  /ai    │        ││
│  │  │ /auth/* │ │ /scans/*│ │/findings/*│ │/analytics│ │ /ai/*   │        ││
│  │  └────┬────┘ └────┬────┘ └─────┬─────┘ └────┬────┘ └────┬────┘        ││
│  │       │           │            │            │           │              ││
│  │  ┌────┴───────────┴────────────┴────────────┴───────────┴────────┐     ││
│  │  │                      SERVICES LAYER                             │     ││
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │     ││
│  │  │  │ Auth    │ │ Scanner │ │Finding  │ │Analytics│ │ AI      │  │     ││
│  │  │  │ Service │ │ Engine  │ │Service  │ │ Service │ │ Service │  │     ││
│  │  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘  │     ││
│  │  └───────┼───────────┼───────────┼───────────┼───────────┼───────┘     ││
│  │          └───────────┴─────┬─────┴───────────┴───────────┘             ││
│  │                            │                                            ││
│  │                     ┌──────┴──────┐                                     ││
│  │                     │  Database   │                                     ││
│  │                     │  (MongoDB)  │                                     ││
│  │                     └─────────────┘                                     ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Scan Lifecycle Data Flow

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1: SCAN CREATION                                                        │
│                                                                                │
│  User                    React                  API Server       MongoDB      │
│   │                       │                         │                │         │
│   │  Click "Launch"       │                         │                │         │
│   │──────────────────────→│                         │                │         │
│   │                       │  POST /api/scans        │                │         │
│   │                       │────────────────────────→│                │         │
│   │                       │                         │  Insert scan   │         │
│   │                       │                         │  document      │         │
│   │                       │                         │───────────────→│         │
│   │                       │   { id, status: "queued" }              │         │
│   │                       │←────────────────────────│                │         │
│   │   Redirect to /scans/:id                     │                │         │
│   │←──────────────────────│                         │                │         │
│   │                       │                         │                │         │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  PHASE 2: PIPELINE EXECUTION (Async)                                           │
│                                                                                │
│  API Server              Scanner              Modules            SSE Stream    │
│   │                         │                    │                   │         │
│   │  runScanPipeline()      │                    │                   │         │
│   │────────────────────────→│                    │                   │         │
│   │                         │  update status     │                   │         │
│   │                         │  "running"         │                   │         │
│   │                         │────────────────────────────────────────→│         │
│   │                         │                    │                   │         │
│   │                         │  for each module:  │                   │         │
│   │                         │───────────────────→│                   │         │
│   │                         │                    │  run checks       │         │
│   │                         │                    │  on target        │         │
│   │                         │←───────────────────│                   │         │
│   │                         │  [findings]        │                   │         │
│   │                         │                    │                   │         │
│   │                         │  for each finding: │                   │         │
│   │                         │  1. deduplicate    │                   │         │
│   │                         │  2. save to DB     │                   │         │
│   │                         │  3. emit SSE       │                   │         │
│   │                         │────────────────────────────────────────→│         │
│   │                         │                    │     data: {finding}│         │
│   │                         │                    │                   │         │
│   │                         │  update progress   │                   │         │
│   │                         │────────────────────────────────────────→│         │
│   │                         │     data: {progress: 45}               │         │
│   │                         │                    │                   │         │
│   │                         │  (all modules done)│                   │         │
│   │                         │────────────────────────────────────────→│         │
│   │                         │     data: {complete: true}             │         │
│   │                         │                    │                   │         │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  PHASE 3: CLIENT RECEIVES STREAM                                               │
│                                                                                │
│  Browser                 EventSource            React State       UI Update   │
│   │                         │                      │                  │         │
│   │  GET /api/stream/:id    │                      │                  │         │
│   │────────────────────────→│                      │                  │         │
│   │                         │                      │                  │         │
│   │←────────────────────────│  event: progress     │                  │         │
│   │   data: {"progress": 45}│                      │                  │         │
│   │                         │─────────────────────→│  progress = 45   │         │
│   │                         │                      │─────────────────→│         │
│   │                         │                      │    Update bar    │         │
│   │                         │                      │                  │         │
│   │←────────────────────────│  event: finding      │                  │         │
│   │   data: {"finding":...} │                      │                  │         │
│   │                         │─────────────────────→│  findings.unshift│         │
│   │                         │                      │─────────────────→│         │
│   │                         │                      │   Slide in card  │         │
│   │                         │                      │                  │         │
│   │                         │  event: complete     │                  │         │
│   │                         │─────────────────────→│  status = "done" │         │
│   │                         │                      │─────────────────→│         │
│   │                         │                      │   Show success   │         │
│   │                         │                      │                  │         │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## AI Streaming Data Flow

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  AI ANALYSIS REQUEST                                                           │
│                                                                                │
│  User              React UI              API Server           OpenCode AI      │
│   │                   │                       │                    │           │
│   │  Click "Analyze"  │                       │                    │           │
│   │──────────────────→│                       │                    │           │
│   │                   │  POST /api/ai/scan/:id│                    │           │
│   │                   │  stream: true         │                    │           │
│   │                   │──────────────────────→│                    │           │
│   │                   │                       │                    │           │
│   │                   │                       │  Build prompt:     │           │
│   │                   │                       │  - Target URL      │           │
│   │                   │                       │  - Findings list   │           │
│   │                   │                       │  - CVSS scores     │           │
│   │                   │                       │                    │           │
│   │                   │                       │  POST /completions │           │
│   │                   │                       │  stream: true      │           │
│   │                   │                       │───────────────────→│           │
│   │                   │                       │                    │           │
│   │                   │                       │←───────────────────│           │
│   │                   │                       │  chunk: "This"     │           │
│   │                   │                       │  chunk: " scan"    │           │
│   │                   │                       │  chunk: " shows"   │           │
│   │                   │                       │  ...               │           │
│   │                   │                       │                    │           │
│   │                   │                       │  Forward each      │           │
│   │                   │                       │  chunk as SSE      │           │
│   │                   │                       │                    │           │
│   │                   │←──────────────────────│  data: {"content":  │           │
│   │                   │  SSE stream           │         "This scan"}│           │
│   │                   │                       │                    │           │
│   │                   │  TextDecoder          │                    │           │
│   │                   │  parse chunks         │                    │           │
│   │                   │  accumulate text      │                    │           │
│   │                   │                       │                    │           │
│   │  Word-by-word     │                       │                    │           │
│   │  typewriter effect←│                       │                    │           │
│   │───────────────────│                       │                    │           │
│   │                   │                       │                    │           │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Notification System Data Flow

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  REAL-TIME NOTIFICATIONS                                                       │
│                                                                                │
│  Scanner              API Server             Browser             UI Toast      │
│   │                      │                      │                  │           │
│   │  finding discovered  │                      │                  │           │
│   │─────────────────────→│                      │                  │           │
│   │                      │  severity: critical  │                  │           │
│   │                      │  or high?            │                  │           │
│   │                      │                      │                  │           │
│   │                      │  YES ──→ Push to     │                  │           │
│   │                      │          notification│                  │           │
│   │                      │          queue       │                  │           │
│   │                      │                      │                  │           │
│   │                      │  Poll every 10s      │                  │           │
│   │                      │←─────────────────────│                  │           │
│   │                      │                      │                  │           │
│   │                      │  EventSource         │                  │           │
│   │                      │  /api/stream/:id     │                  │           │
│   │                      │─────────────────────→│                  │           │
│   │                      │                      │                  │           │
│   │                      │←─────────────────────│  finding event   │           │
│   │                      │                      │                  │           │
│   │                      │  Trigger toast       │                  │           │
│   │                      │─────────────────────→│                  │           │
│   │                      │                      │  🔔 Toast popup  │           │
│   │                      │                      │─────────────────→│           │
│   │                      │                      │                  │           │
│   │                      │  Audio ping          │                  │           │
│   │                      │  (if critical)       │                  │           │
│   │                      │─────────────────────→│  🔊 880Hz beep   │           │
│   │                      │                      │─────────────────→│           │
│   │                      │                      │                  │           │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Database Collections Relationship

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  MONGODB COLLECTIONS                                                           │
│                                                                                │
│  ┌─────────────┐                                                               │
│  │   users     │◄────────────────────────────────────────┐                    │
│  │  _id, email │                                         │                    │
│  │  role, name │                                         │                    │
│  └──────┬──────┘                                         │                    │
│         │                                                │                    │
│         │ 1:N                                            │                    │
│         ▼                                                │                    │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐│                    │
│  │  scan_jobs  │────→│  findings   │     │ audit_log   ││                    │
│  │  _id, target│ 1:N │  _id, title │     │ user_id     │┘                    │
│  │  status, %  │     │  severity   │     │ action      │                     │
│  └──────┬──────┘     │  cvss_score │     └─────────────┘                     │
│         │            └──────┬──────┘                                          │
│         │ 1:1               │ 1:1                                             │
│         ▼                   ▼                                                 │
│  ┌─────────────┐     ┌─────────────┐                                          │
│  │   targets   │     │ remediations│                                          │
│  │  domain,    │     │ status,     │                                          │
│  │  risk_score │     │ sla_breach  │                                          │
│  └─────────────┘     └─────────────┘                                          │
│                                                                                │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                      │
│  │webhooks     │     │settings     │     │scheduled    │                      │
│  │url, events  │     │ai_model     │     │_scans       │                      │
│  └─────────────┘     └─────────────┘     └─────────────┘                      │
│                                                                                │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Integration Data Flows

### GitHub Issue Creation

```
User clicks "Create GitHub Issue"
         │
         ▼
┌─────────────────┐
│ POST /api/integrations/github/issue  │
│  finding_id: "..."                   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  API Server     │────→│  GitHub API     │
│  Format issue   │     │  POST /repos/   │
│  body with:     │     │  .../issues     │
│  - Title        │     │                 │
│  - Severity     │     │  Headers:       │
│  - CVSS score   │     │  Authorization: │
│  - Description  │     │  token GITHUB_  │
│  - Remediation  │     │  TOKEN          │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  Save issue_url │     │  Issue created  │
│  to finding doc │     │  on GitHub      │
└─────────────────┘     └─────────────────┘
         │
         ▼
User sees link: "View on GitHub →"
```

### Slack Alert

```
Event: Critical finding found / SLA breach
         │
         ▼
┌─────────────────┐
│ Webhook Service │
│ Format Slack    │
│ attachment:     │
│ - Color: danger │
│ - Title, Fields │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ POST to Slack   │
│ webhook URL     │
└─────────────────┘
```

---

*Data Flow Version 1.0 — Bug Finder Pro*
