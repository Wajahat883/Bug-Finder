// POINT 13: k6 load test — run with: k6 run load-test.js
// Install k6: https://k6.io/docs/getting-started/installation/
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// Custom metrics
const scanCreations   = new Counter("scan_creations");
const findingsFetched = new Counter("findings_fetched");
const errorRate       = new Rate("error_rate");
const apiLatency      = new Trend("api_latency_ms");

const BASE_URL = __ENV.BASE_URL || "http://localhost:5000";

// ── Load profile ───────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    // Smoke test — verify basic functionality
    smoke: {
      executor: "constant-vus",
      vus: 1,
      duration: "30s",
      tags: { scenario: "smoke" },
    },
    // Load test — normal expected load
    load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "1m",  target: 20  },  // Ramp up
        { duration: "3m",  target: 50  },  // Sustain
        { duration: "1m",  target: 0   },  // Ramp down
      ],
      tags: { scenario: "load" },
      startTime: "30s",
    },
    // Stress test — find breaking point
    stress: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "2m",  target: 100 },
        { duration: "5m",  target: 100 },
        { duration: "2m",  target: 200 },
        { duration: "5m",  target: 200 },
        { duration: "2m",  target: 0   },
      ],
      tags: { scenario: "stress" },
      startTime: "5m",
    },
  },
  thresholds: {
    http_req_duration:          ["p(95)<500", "p(99)<1500"],  // 95% under 500ms
    http_req_failed:            ["rate<0.01"],                 // < 1% failures
    error_rate:                 ["rate<0.05"],                 // < 5% app errors
    "api_latency_ms{endpoint:healthz}": ["p(95)<100"],        // Health < 100ms
    "api_latency_ms{endpoint:findings}": ["p(95)<800"],       // Findings < 800ms
  },
};

// ── Auth helper ────────────────────────────────────────────────────────────
let sessionCookie = "";

export function setup() {
  const loginRes = http.post(
    `${BASE_URL}/api/auth/demo`,
    null,
    { headers: { "Content-Type": "application/json" } }
  );
  if (loginRes.status === 200) {
    const cookies = loginRes.headers["Set-Cookie"];
    if (cookies) sessionCookie = cookies.split(";")[0];
  }
  return { cookie: sessionCookie };
}

// ── Test scenarios ─────────────────────────────────────────────────────────
export default function (data) {
  const headers = {
    "Content-Type": "application/json",
    ...(data.cookie ? { Cookie: data.cookie } : {}),
  };

  const scenario = Math.random();

  if (scenario < 0.3) {
    // Health check (30%)
    const t0 = Date.now();
    const res = http.get(`${BASE_URL}/api/healthz`, { headers, tags: { endpoint: "healthz" } });
    apiLatency.add(Date.now() - t0, { endpoint: "healthz" });
    errorRate.add(res.status >= 500);
    check(res, {
      "healthz status 200": r => r.status === 200,
      "healthz has status field": r => JSON.parse(r.body)?.status !== undefined,
    });

  } else if (scenario < 0.6) {
    // List findings (30%)
    const t0 = Date.now();
    const res = http.get(
      `${BASE_URL}/api/findings?page=1&page_size=20&severity=high`,
      { headers, tags: { endpoint: "findings" } }
    );
    apiLatency.add(Date.now() - t0, { endpoint: "findings" });
    errorRate.add(res.status >= 500);
    findingsFetched.add(1);
    check(res, {
      "findings status ok": r => r.status === 200 || r.status === 401,
    });

  } else if (scenario < 0.8) {
    // Dashboard stats (20%)
    const t0 = Date.now();
    const res = http.get(`${BASE_URL}/api/dashboard/stats`, { headers, tags: { endpoint: "dashboard" } });
    apiLatency.add(Date.now() - t0, { endpoint: "dashboard" });
    errorRate.add(res.status >= 500);
    check(res, {
      "dashboard status ok": r => r.status === 200 || r.status === 401,
    });

  } else {
    // Scan list (20%)
    const t0 = Date.now();
    const res = http.get(`${BASE_URL}/api/scan-jobs?page=1&page_size=10`, { headers, tags: { endpoint: "scans" } });
    apiLatency.add(Date.now() - t0, { endpoint: "scans" });
    errorRate.add(res.status >= 500);
    check(res, {
      "scans status ok": r => r.status === 200 || r.status === 401,
    });
  }

  sleep(Math.random() * 2 + 0.5); // 0.5–2.5s think time
}

export function handleSummary(data) {
  return {
    "stdout": textSummary(data, { indent: " ", enableColors: true }),
    "performance-results.json": JSON.stringify(data, null, 2),
  };
}

function textSummary(data, _opts) {
  const dur = data.metrics?.http_req_duration;
  if (!dur) return "No metrics collected";
  return [
    "",
    "=== Bug Finder Pro — Load Test Results ===",
    `  Total requests:  ${data.metrics?.http_reqs?.values?.count ?? 0}`,
    `  Failed requests: ${data.metrics?.http_req_failed?.values?.passes ?? 0}`,
    `  p95 latency:     ${Math.round(dur.values?.["p(95)"] ?? 0)}ms`,
    `  p99 latency:     ${Math.round(dur.values?.["p(99)"] ?? 0)}ms`,
    `  Error rate:      ${((data.metrics?.error_rate?.values?.rate ?? 0) * 100).toFixed(2)}%`,
    "",
  ].join("\n");
}
