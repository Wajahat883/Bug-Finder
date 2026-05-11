# Bug Finder Pro — Enterprise Improvement Implementation Plan

## Priority Matrix

| Priority | # | Feature | Effort | Files Affected |
|----------|---|---------|--------|---------------|
| CRITICAL | 1 | DB Indexing | 2h | `schema.ts` |
| CRITICAL | 2 | BullMQ Queue System | 3d | `queue.ts`, `worker.ts`, docker-compose, `scans.ts`, `ai.ts` |
| CRITICAL | 3 | Secure Admin Credentials | 1h | `auth.ts`, `seed.ts`, `.env.example` |
| HIGH | 4 | Playwright Browser Engine | 5d | `scanner/playwright.ts`, docker-compose |
| HIGH | 5 | Redis Rate Limiting | 1d | `rate-limit.ts`, docker-compose |
| HIGH | 6 | Virtualized Tables | 2d | `findings.tsx`, `scans.tsx`, `targets.tsx` |
| MEDIUM | 7 | Scanner Sandboxing | 2d | Dockerfile.scanner, docker-compose |
| MEDIUM | 8 | WebSocket Real-time | 2d | `ws-server.ts`, `layout.tsx` |
| MEDIUM | 9 | OSINT Integration | 2d | `scanner/osint.ts` |

---

## CRITICAL 1: Database Indexing

### Problem
Every list endpoint loads ALL documents then filters/paginates in memory:
```ts
const all = await col("findings").find(query).toArray(); // SCANS EVERY DOCUMENT
const items = all.slice((page-1)*pageSize, page*pageSize); // TRIMS IN JS
```
With 10K+ findings, this takes seconds and freezes.

### Solution
Add MongoDB indexes to `schema.ts`:
```ts
col("findings").createIndex({ scan_job_id: 1 });
col("findings").createIndex({ severity: 1, created_at: -1 });
col("findings").createIndex({ target_url: 1 });
col("findings").createIndex({ category: 1 });
col("scan_jobs").createIndex({ status: 1, created_at: -1 });
col("scan_jobs").createIndex({ target_url: 1 });
col("targets").createIndex({ domain: 1 }, { unique: true });
col("activity_events").createIndex({ timestamp: -1 });
col("remediations").createIndex({ created_at: -1 });
```
Then update queries to use `.skip()` and `.limit()`:
```ts
const items = await col("findings").find(query)
  .sort({ created_at: -1 })
  .skip((page - 1) * pageSize)
  .limit(pageSize)
  .toArray();
```

---

## CRITICAL 2: BullMQ Queue System

### Problem
- Scans run directly in Express process — blocks other requests
- AI streaming consumes memory and blocks the event loop
- No retry logic for failed scans
- Cannot scale horizontally

### Solution
**Infrastructure:**
```
API Server → queue.add("scan", { jobId, targetUrl, profile })
              │
         Redis Queue (BullMQ)
              │
    ┌─────────┼─────────┐
    │         │         │
 Worker1   Worker2   Worker3
    │         │         │
    └─────────┼─────────┘
              │
         MongoDB (results)
              │
         SSE to clients
```

**Queue Types:**
- `scan-queue` → Vulnerability scanning (concurrency: 3)
- `ai-queue` → AI analysis (concurrency: 5)
- `notification-queue` → Email/Slack (concurrency: 10)
- `report-queue` → PDF generation (concurrency: 2)

**New Files:**
- `backend/src/services/queue/manager.ts` — Queue configuration + connection
- `backend/src/services/queue/scan-worker.ts` — Scan execution worker
- `backend/src/services/queue/ai-worker.ts` — AI generation worker
- `backend/src/services/queue/notify-worker.ts` — Notification worker

**Benefits:**
- Scans run in isolated workers — API stays responsive
- Automatic retry with exponential backoff
- Job prioritization (critical scan before scheduled)
- Horizontal scaling: add more workers when needed
- Graceful shutdown: save progress before exit

---

## CRITICAL 3: Secure Admin Credentials

### Problem
Current code in `auth.ts`:
```ts
const DEFAULT_ADMIN_EMAIL = "Waji2156@gmail.com";
const DEFAULT_ADMIN_PASSWORD = "Waji2156..";
```
Anyone who reads the source code can login as admin.

### Solution
Create a first-run setup flow:
1. Remove hardcoded constants
2. On first startup, generate a random admin password
3. Write to `.env.admin` or log to console once
4. Add `POST /api/setup` endpoint for initial admin creation
5. After first admin is created, disable setup endpoint

```ts
// seed.ts
const adminPassword = crypto.randomBytes(16).toString("hex");
// Log once: "Initial admin password: a3f8c2..."
```

---

## HIGH 4: Playwright Browser Automation Engine

### Problem
39 scanner modules are HTTP-only. Cannot test:
- DOM-based XSS
- Client-side routing (React/Vue SPA)
- Auth flows (login → cookie → authenticated scan)
- CSRF token extraction
- WebSocket security
- Canvas fingerprinting
- Service Worker exploitation

### Solution
Add a new scanner module `scanner/playwright.ts`:
```ts
export async function runPlaywrightScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // 1. Navigate and wait for SPA to load
  await page.goto(ctx.targetUrl, { waitUntil: "networkidle" });

  // 2. Extract DOM content for analysis
  const domContent = await page.content();

  // 3. Check for DOM-based XSS sinks
  const domXss = await checkDomXss(page);

  // 4. Capture screenshot for evidence
  const screenshot = await page.screenshot();

  // 5. Extract client-side storage
  const localStorage = await page.evaluate(() =>
    JSON.stringify(window.localStorage)
  );

  await browser.close();
  return findings;
}
```

**Docker Change:**
```yaml
playwright:
  image: mcr.microsoft.com/playwright:latest
  container_name: bug-finder-playwright
```

---

## HIGH 5: Redis Rate Limiting

### Problem
- Login, AI endpoints, scan creation — no rate limits
- One attacker can exhaust AI API credits
- Brute force attacks unrestricted

### Solution
Extend existing auth rate limiter to all sensitive endpoints:
```ts
// New: backend/src/middlewares/rate-limit.ts
import Redis from "ioredis";
import { RateLimiterRedis } from "rate-limiter-flexible";

const redis = new Redis({ host: "redis", port: 6379 });

export const apiRateLimiter = new RateLimiterRedis({
  storeClient: redis,
  points: 100,  // requests
  duration: 60, // per minute
});

export const aiRateLimiter = new RateLimiterRedis({
  storeClient: redis,
  points: 10,   // requests
  duration: 60, // per minute
});
```

**Protected Endpoints:**
| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/auth/login` | 5 | 15 min (existing) |
| `/api/auth/register` | 3 | 1 hour |
| `/api/ai/*` | 10 | 1 min |
| `/api/scan-jobs` (POST) | 5 | 1 min |
| `/api/*` (global) | 100 | 1 min |

---

## HIGH 6: Virtualized Tables

### Problem
Findings list loads ALL records into DOM. 1000 findings = 1000 React components rendered = browser freeze.

### Solution
Add `@tanstack/react-virtual`:
```tsx
import { useVirtualizer } from "@tanstack/react-virtual";

function FindingsTable({ data }) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: data.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 56, // row height
    overscan: 10,
  });

  return (
    <div ref={parentRef} style={{ height: "600px", overflow: "auto" }}>
      <div style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((virtualRow) => (
          <div key={virtualRow.key} style={{ transform: `translateY(${virtualRow.start}px)` }}>
            {data[virtualRow.index].title}
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

## MEDIUM 7: Scanner Sandboxing

### Problem
All 39 scanner modules run in the same Node.js process as the API. A crash in any module kills the entire server.

### Solution
Docker-isolated scanner container:
```yaml
scanner-worker:
  build:
    context: .
    dockerfile: backend/Dockerfile.scanner
  environment:
    - NODE_ENV=production
  networks:
    - bug-finder-network
  deploy:
    replicas: 3
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  read_only: true
```

---

## MEDIUM 8: WebSocket Real-time

### Problem
SSE is one-directional (server → client only). Client cannot send commands (pause/resume/cancel) through the same connection.

### Solution
Add Socket.IO alongside existing SSE:
```ts
// backend/src/services/ws-server.ts
import { Server } from "socket.io";

export function initWebSocket(httpServer) {
  const io = new Server(httpServer);
  io.on("connection", (socket) => {
    socket.on("subscribe:scan", (scanId) => {
      socket.join(`scan:${scanId}`);
      // Forward scan events to this socket
    });
    socket.on("scan:pause", (scanId) => {
      // Handle pause command from client
    });
  });
}
```

---

## MEDIUM 9: OSINT Integration

### Problem
Recon modules only check the target URL itself. Missing external intelligence about the target.

### Solution
Add OSINT enrichment module:
```ts
// backend/src/services/scanner/osint.ts
export async function runOsintEnrichment(ctx: ScanContext): Promise<ScanFinding[]> {
  const domain = new URL(ctx.targetUrl).hostname;

  // 1. Shodan: exposed services, open ports, banners
  const shodanData = await fetch(`https://api.shodan.io/dns/domain/${domain}?key=${SHODAN_KEY}`);

  // 2. Censys: certificates, subdomains
  const censysData = await fetch(`https://search.censys.io/api/v2/hosts/search?q=${domain}`);

  // 3. CRT.sh: certificate transparency logs
  const crtData = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);

  // 4. SecurityTrails: DNS history
  const stData = await fetch(`https://api.securitytrails.com/v1/domain/${domain}`);

  return findings; // Exposed services, shadow IT, forgotten subdomains
}
```

---

## Implementation Order

```
Day 1-2:  DB Indexing (2h) + Secure Admin (1h) + Rate Limiting (1d)
Day 3-5:  BullMQ Queue System (3d)
Day 6-7:  Virtualized Tables (2d)
Day 8-12: Playwright Browser Engine (5d)
Day 13-14: Scanner Sandboxing (2d)
Day 15-16: WebSocket Migration (2d)
Day 17-18: OSINT Integration (2d)
```

## Files Created/Modified Summary

| File | Action | Feature |
|------|--------|---------|
| `backend/src/lib/schema.ts` | Modify | DB Indexing |
| `backend/src/services/queue/manager.ts` | New | Queue System |
| `backend/src/services/queue/scan-worker.ts` | New | Queue System |
| `backend/src/services/queue/ai-worker.ts` | New | Queue System |
| `backend/src/middlewares/rate-limit.ts` | Modify | Rate Limiting |
| `backend/src/services/scanner/playwright.ts` | New | Browser Engine |
| `backend/src/services/scanner/osint.ts` | New | OSINT Integration |
| `backend/src/services/ws-server.ts` | New | WebSocket |
| `backend/src/app.ts` | Modify | WebSocket + Queue init |
| `backend/src/routes/scans.ts` | Modify | Queue integration |
| `backend/package.json` | Modify | New dependencies |
| `docker-compose.yml` | Modify | Playwright + worker services |
| `frontend/package.json` | Modify | @tanstack/react-virtual |
| `frontend/src/pages/findings.tsx` | Modify | Virtualized table |
| `frontend/src/pages/scans.tsx` | Modify | Virtualized table |
