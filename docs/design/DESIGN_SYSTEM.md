# Bug Finder Pro — Design System

> A comprehensive visual language for the cybersecurity operations platform.

---

## 1. Design Philosophy

**"Dark Command Center"**

Bug Finder Pro is designed to feel like a professional security operations center. The interface prioritizes:

- **Information density** — maximum data visible without clutter
- **Severity recognition** — color-coded urgency at a glance
- **Dark mode first** — reduces eye strain during long investigations
- **Cyberpunk accents** — purple/violet primary with neon severity indicators

---

## 2. Color System

### Primary Palette

```
┌─────────────────────────────────────────────────────────────┐
│  PRIMARY GRADIENT                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ #6d28d9  │→ │ #7c3aed  │→ │ #8b5cf6  │  Violet Purple   │
│  │  rgb(109,│  │ rgb(124, │  │ rgb(139, │                  │
│  │  40,217) │  │ 58, 237) │  │ 92, 246) │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│       ↓            ↓            ↓                          │
│   Deep Purple   Core Brand   Bright Accent                 │
│                                                             │
│  Usage: Logo, active nav items, primary buttons, charts    │
└─────────────────────────────────────────────────────────────┘
```

### Severity Colors (Neon Cybersecurity Scale)

```
┌──────────────────────────────────────────────────────────────┐
│  CRITICAL    HIGH       MEDIUM      LOW         INFO         │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │
│  │#ef4444 │ │#f97316 │ │#eab308 │ │#22d3ee │ │#34d399 │     │
│  │  Red   │ │ Orange │ │ Yellow │ │  Cyan  │ │ Green  │     │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘     │
│     ●──●      ●──●       ●──●       ●──●       ●──●         │
│                                                              │
│  Dark bg: Vibrant neon    Light bg: Deep saturated          │
└──────────────────────────────────────────────────────────────┘
```

### Theme Surfaces

#### Dark Theme (Default)
```
Background    #0a0a0f  ← Deep space black
Card          #111118  ← Slightly elevated
Sidebar       #08080c  ← Deepest layer
Border        #1e1e2e  ← Subtle separation
Text Primary  #e8e8ef  ← Soft white
Text Muted    #6b6b80  ← Dimmed for secondary info
```

#### Light Theme
```
Background    #f7f7f8  ← Clean white-gray
Card          #ffffff  ← Pure white
Sidebar       #fafafa  ← Off-white
Border        #e4e4e7  ← Light gray
Text Primary  #18181b  ← Near black
Text Muted    #71717a  ← Medium gray
```

#### High Contrast
```
Background    #000000  ← Pure black
Card          #0f0f0f  ← Almost black
Text          #ffffff  ← Pure white
Primary       #a855f7  ← Bright violet
```

---

## 3. Typography

```
┌─────────────────────────────────────────────────────────────┐
│  FONT STACK                                                 │
│                                                             │
│  Sans-serif:  'Inter', system-ui, -apple-system, sans-serif │
│  Monospace:   'Space Mono', 'Fira Code', monospace          │
│  Serif:       Georgia, 'Times New Roman', serif             │
│                                                             │
│  Inter → Clean, modern, excellent for data dashboards      │
│  Space Mono → Terminal/code aesthetics for security tools  │
└─────────────────────────────────────────────────────────────┘
```

### Type Scale

| Token | Size | Weight | Usage |
|-------|------|--------|-------|
| `hero` | 48–72px | 900 | Landing page headlines |
| `h1` | 32px | 700 | Page titles |
| `h2` | 24px | 600 | Section headers |
| `h3` | 18px | 600 | Card titles |
| `body` | 14px | 400 | Primary content |
| `small` | 12px | 500 | Labels, metadata |
| `micro` | 10px | 600 | Tags, badges, nav groups |

---

## 4. Spacing & Layout

### Grid System

```
┌──────────────────────────────────────────────────────────────┐
│                    VIEWPORT (100vw)                          │
│  ┌────────────┬──────────────────────────────┐               │
│  │            │                              │               │
│  │  SIDEBAR   │        MAIN CONTENT          │               │
│  │   200px    │       flex: 1                │               │
│  │  fixed     │                              │               │
│  │            │                              │               │
│  │  ──────────│────────────────────────────  │               │
│  │  User      │  Header: 48px                │               │
│  │  Profile   │  ──────────────────────────  │               │
│  │            │                              │               │
│  │  Core      │  Padding: 24px (p-6)         │               │
│  │  Analytics │                              │               │
│  │  AI & Tools│  Cards: 16px gap             │               │
│  │  Config    │                              │               │
│  │            │                              │               │
│  └────────────┴──────────────────────────────┘               │
└──────────────────────────────────────────────────────────────┘
```

### Spacing Tokens

| Token | Value | Usage |
|-------|-------|-------|
| `xs` | 4px | Tight internal padding |
| `sm` | 8px | Button padding, icon gaps |
| `md` | 16px | Card padding, section gaps |
| `lg` | 24px | Page padding, major separations |
| `xl` | 32px | Hero sections, large gaps |

---

## 5. Component Library

### Buttons

```
┌─────────────────────────────────────────────────────────────┐
│  PRIMARY BUTTON                                             │
│  ┌─────────────────────────┐                                │
│  │  🚀 Start New Scan      │  Background: #7c3aed          │
│  └─────────────────────────┘  Text: White                   │
│                               Shadow: 0 4px 15px rgba(      │
│                                      124,58,237,0.3)        │
│                                                             │
│  SECONDARY BUTTON                                           │
│  ┌─────────────────────────┐                                │
│  │  Configure Settings     │  Background: hsl(var(--muted))│
│  └─────────────────────────┘  Border: 1px solid border      │
│                                                             │
│  DESTRUCTIVE BUTTON                                         │
│  ┌─────────────────────────┐                                │
│  │  ⚠ Delete Finding       │  Background: #ef4444          │
│  └─────────────────────────┘  Hover: #dc2626                │
└─────────────────────────────────────────────────────────────┘
```

### Cards

```
┌─────────────────────────────────────────────────────────────┐
│  DATA CARD                                                  │
│  ┌─────────────────────────────────────────┐                │
│  │  ┌──────┐  Finding Title               │  Border: 1px   │
│  │  │ 🔴   │  /api/users/login            │  Radius: 6px   │
│  │  └──────┘                              │  Background:   │
│  │  Severity: Critical  CVSS: 9.8         │  card color    │
│  │  ───────────────────────────────────── │                │
│  │  Description text goes here...         │                │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  METRIC CARD                                                │
│  ┌─────────────────────────────────────────┐                │
│  │  Total Findings                         │                │
│  │  ┌──────┐                               │                │
│  │  │ 1,247│  ↑ 12% vs last week          │                │
│  │  └──────┘                               │                │
│  │  42 Critical  │  189 High  │  516 Med   │                │
│  └─────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

### Badges

| Type | Background | Text | Border |
|------|-----------|------|--------|
| Critical | `#ef444420` | `#ef4444` | `#ef444440` |
| High | `#f9731620` | `#f97316` | `#f9731640` |
| Medium | `#eab30820` | `#eab308` | `#eab30840` |
| Low | `#22d3ee20` | `#22d3ee` | `#22d3ee40` |
| Info | `#34d39920` | `#34d399` | `#34d39940` |

---

## 6. Icons

**Library:** Lucide React

```
┌──────────────────────────────────────────────────────────────┐
│  NAVIGATION ICONS                     │ ACTION ICONS         │
│  ─────────────────                    │ ─────────────        │
│  LayoutDashboard → Dashboard          │  ShieldAlert → Risk  │
│  Activity → Scans                     │  Search → Command Pal│
│  ShieldAlert → Findings               │  Bell → Notifications│
│  Target → Targets                     │  LogOut → Sign Out   │
│  CheckSquare → Remediations           │  Sparkles → AI       │
│  TrendingUp → Executive               │  GitCompare → Diff   │
│  Network → Attack Surface             │  Bookmark → Templates│
│  Shield → OWASP                       │  Calculator → CVSS   │
│  Clock → Timeline                     │  Settings → Config   │
└──────────────────────────────────────────────────────────────┘
```

All icons: **16px default**, **20px for emphasis**, stroke-width: 2px

---

## 7. Animations & Motion

### Transitions

```
Theme switch:    background-color 200ms ease, border-color 200ms ease
Hover states:    opacity 150ms, transform 150ms
Modal open:      opacity 0→1, scale 0.95→1, 200ms ease-out
Toast enter:     slide-in from right, 300ms spring
Finding stream:  fade-in + slide-down, 200ms per item
```

### Interactive Effects

```
┌─────────────────────────────────────────────────────────────┐
│  SCAN PROGRESS ANIMATION                                    │
│                                                             │
│  [████████████░░░░░░░░] 62%                                 │
│   ↑ Animated gradient shimmer across the bar               │
│                                                             │
│  LIVE FINDING APPEARANCE                                    │
│                                                             │
│  New finding slides in from top:                           │
│  translateY(-10px) → translateY(0)                         │
│  opacity: 0 → 1                                            │
│  Background flash: rgba(239,68,68,0.1) → transparent       │
│                                                             │
│  ATTACK SURFACE GRAPH                                       │
│                                                             │
│  Nodes pulse on hover:                                     │
│  scale: 1 → 1.15, shadow intensifies                       │
│  Edges draw with SVG stroke-dashoffset animation           │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Responsive Breakpoints

| Name | Width | Behavior |
|------|-------|----------|
| Mobile | < 640px | Stack layout, hide sidebar behind hamburger |
| Tablet | 640–1024px | Collapsed sidebar (icons only) |
| Desktop | > 1024px | Full sidebar, all features visible |

---

## 9. Z-Index Scale

| Layer | Z-Index | Element |
|-------|---------|---------|
| Background | 0 | Page content |
| Elevated | 10 | Cards, buttons |
| Sticky | 100 | Header, sidebar |
| Overlay | 500 | Backdrop, modals |
| Dropdown | 1000 | Menus, tooltips |
| Toast | 9999 | Notifications |
| Command | 10000 | Command palette |

---

## 10. Shadow & Glow System

```
Card shadow:        0 1px 3px rgba(0,0,0,0.3)
Elevated shadow:    0 8px 30px rgba(0,0,0,0.4)
Modal shadow:       0 25px 50px rgba(0,0,0,0.5)
Button glow:        0 4px 15px rgba(124,58,237,0.3)
Critical glow:      0 0 20px rgba(239,68,68,0.2)
AI streaming glow:  0 0 15px rgba(139,92,246,0.15)
```

---

*Design System Version 1.0 — Bug Finder Pro*
