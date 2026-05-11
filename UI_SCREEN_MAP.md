# Bug Finder Pro — UI Screen Map

> A visual map of every screen in the application and how they connect.

---

## Navigation Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PUBLIC PAGES                                    │
│                                                                              │
│   ┌──────────┐     ┌──────────┐     ┌──────────────┐     ┌──────────────┐   │
│   │ Landing  │────→│  Login   │←───→│  Register    │     │ Admin Login  │   │
│   │    /     │     │  /login  │     │  (in /login) │     │   /admin     │   │
│   └────┬─────┘     └────┬─────┘     └──────────────┘     └──────────────┘   │
│        │                │                                                    │
│        │                ↓                                                    │
│        │           ┌──────────┐     ┌──────────────┐                        │
│        │           │Forgot Pwd│────→│ Reset Pwd    │                        │
│        │           │/forgot   │     │ /reset       │                        │
│        │           └──────────┘     └──────────────┘                        │
│        │                                                                     │
│        │                ↓ Authenticated                                     │
│        └────────────────┘                                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APP SHELL (Sidebar + Header)                         │
│                                                                              │
│  ┌─────────┐  ┌───────────────────────────────────────────────────────────┐  │
│  │ Sidebar │  │  Header: Breadcrumb + Search (⌘K) + 🔔 + Theme + Profile │  │
│  │  200px  │  ├───────────────────────────────────────────────────────────┤  │
│  │ fixed   │  │                                                           │  │
│  │         │  │                    [PAGE CONTENT]                         │  │
│  │ Core    │  │                                                           │  │
│  │Analytics│  │                                                           │  │
│  │AI&Tools │  │                                                           │  │
│  │ Config  │  │                                                           │  │
│  └─────────┘  └───────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Domain Pages

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CORE — Primary Security Operations                                          │
│                                                                              │
│  Dashboard (/dashboard)                                                      │
│  ├──→ New Scan (/scans/new)                                                  │
│  ├──→ Scans List (/scans) ──→ Scan Detail (/scans/:id)                      │
│  │                              ├──→ Finding Detail (/findings/:id)          │
│  │                              ├──→ Scan Compare (/scans/compare)           │
│  │                              └──→ PDF Export (download)                   │
│  ├──→ Findings List (/findings) ──→ Finding Detail (/findings/:id)          │
│  │                                    ├──→ AI Advice (inline)                │
│  │                                    ├──→ GitHub Issue (create)             │
│  │                                    └──→ CVSS Calculator (/cvss)           │
│  ├──→ Targets List (/targets) ──→ Target Detail (/targets/:id)              │
│  │                                  └──→ New Scan (pre-filled)               │
│  └──→ Remediations (/remediations)                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Analytics Domain Pages

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ANALYTICS — Reporting & Visualization                                       │
│                                                                              │
│  Executive Dashboard (/executive)                                            │
│  ├──→ Risk posture score + trend charts                                      │
│  ├──→ Severity distribution                                                  │
│  └──→ Top vulnerable targets                                                 │
│                                                                              │
│  Attack Surface Map (/attack-surface)                                        │
│  ├──→ Overview tab (RadarChart + Treemap)                                    │
│  ├──→ Endpoints tab (filterable table)                                       │
│  ├──→ Heatmap tab (target × category grid)                                   │
│  ├──→ Subdomains tab (+ Add & Scan)                                          │
│  └──→ Open Ports tab                                                         │
│                                                                              │
│  OWASP Top 10 (/owasp)                                                       │
│  ├──→ Category heatmap (A01–A10)                                             │
│  └──→ Per-category finding breakdown                                         │
│                                                                              │
│  Timeline (/timeline)                                                        │
│  └──→ Chronological finding events                                           │
│                                                                              │
│  Compliance Dashboard (/compliance)                                          │
│  ├──→ OWASP mapping                                                          │
│  ├──→ PCI-DSS mapping                                                        │
│  └──→ ISO 27001 mapping                                                      │
│                                                                              │
│  SLA Dashboard (/sla)                                                        │
│  └──→ Breach tracking + deadline countdown                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## AI & Tools Domain Pages

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  AI & TOOLS — Advanced Capabilities                                          │
│                                                                              │
│  AI Triage (/ai-triage)                                                      │
│  ├──→ Chat interface with security AI                                        │
│  ├──→ Ask about specific findings                                            │
│  └──→ Bulk triage recommendations                                            │
│                                                                              │
│  Scan Compare (/scans/compare)                                               │
│  ├──→ Side-by-side scan diff                                                 │
│  ├──→ New findings vs fixed findings                                         │
│  └──→ Recurring findings                                                     │
│                                                                              │
│  Scan Templates (/scan-templates)                                            │
│  └──→ Saved scan configurations                                              │
│                                                                              │
│  CVSS Calculator (/cvss)                                                     │
│  ├──→ Interactive 8-metric calculator                                        │
│  ├──→ Real-time score (0.0–10.0)                                             │
│  └──→ Vector string generation                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Config Domain Pages

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CONFIG — Administration & Settings                                          │
│                                                                              │
│  Integrations (/integrations) — ADMIN ONLY                                   │
│  ├──→ GitHub connection                                                      │
│  ├──→ Slack webhook                                                          │
│  ├──→ API key management                                                     │
│  └──→ Custom webhooks                                                        │
│                                                                              │
│  Audit Log (/audit-log) — ADMIN ONLY                                         │
│  ├──→ Filter by user, entity, date                                           │
│  └──→ Export audit trail                                                     │
│                                                                              │
│  System (/system)                                                            │
│  ├──→ Health checks                                                          │
│  ├──→ Environment status                                                     │
│  └──→ Resource usage                                                         │
│                                                                              │
│  Settings (/settings)                                                        │
│  ├──→ Platform configuration                                                 │
│  ├──→ AI model selection                                                     │
│  ├──→ SMTP configuration                                                     │
│  └──→ Theme preferences                                                      │
│                                                                              │
│  User Management (/admin/users) — ADMIN ONLY                                 │
│  ├──→ Role editing                                                           │
│  ├──→ Activate/deactivate users                                              │
│  └──→ Password reset                                                         │
│                                                                              │
│  Notifications (/notifications)                                              │
│  └──→ Notification history + read status                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Global Overlays

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  OVERLAYS — Available from Any Page                                          │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │  Command Palette (⌘K or /)                                            │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  Search findings, scans, targets, pages...                      │  │   │
│  │  │  ─────────────────────────────────────────────────────────────  │  │   │
│  │  │  Pages (12)          Findings          Scans          Targets  │  │   │
│  │  │  ▸ Dashboard         ▸ SQL Injection   ▸ #2842       ▸ api... │  │   │
│  │  │  ▸ Scans             ▸ XSS             ▸ #2841       ▸ blog.. │  │   │
│  │  │  ▸ Findings          ▸ CSP Missing     ▸ #2839       ▸ admin │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │  Notification Dropdown (🔔 Bell)                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  Notifications                                        [Mark all]│  │   │
│  │  │  ─────────────────────────────────────────────────────────────  │  │   │
│  │  │  ● 3 CRITICAL Findings Detected        2m ago                 │  │   │
│  │  │  ● Scan #2842 Completed               15m ago                 │  │   │
│  │  │  ● SLA Breach: Auth Bypass            1h ago                  │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │  Profile Dropdown (👤 Avatar)                                         │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │  │  WA                                  ADMIN                      │  │   │
│  │  │  Wajahat Ahmad                     [Edit Profile]               │  │   │
│  │  │  wajahat@company.com               [Settings]                   │  │   │
│  │  │                                    [Change Password]            │  │   │
│  │  │  ─────────────────────────────────────────────────────────────  │  │   │
│  │  │  Theme: dark (T to cycle)          [Sign Out]                   │  │   │
│  │  └─────────────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Keyboard Shortcuts Reference

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  GLOBAL SHORTCUTS                                                            │
│                                                                              │
│  ⌘K / Ctrl+K    → Open Command Palette                                       │
│  /              → Open Command Palette (when not in input)                   │
│  N              → Navigate to New Scan                                       │
│  F              → Navigate to Findings                                       │
│  R              → Navigate to Remediations                                   │
│  T              → Cycle Theme (Dark → Light → High Contrast)                 │
│  Esc            → Close modals / dropdowns / command palette                 │
│                                                                              │
│  SCAN DETAIL SHORTCUTS                                                       │
│  Space          → Pause/Resume stream (when viewing live scan)               │
│                                                                              │
│  FINDING DETAIL SHORTCUTS                                                    │
│  G              → Create GitHub Issue                                        │
│  C              → Copy CVSS vector                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

*UI Map Version 1.0 — Bug Finder Pro*
