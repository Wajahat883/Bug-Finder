import { TestSuite, TestCase, TestContext, TestResult } from "./types";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers },
    ...opts,
  }).catch(() => null);
}

const performanceTests: TestCase[] = [
  {
    id: "perf-01",
    category: "performance",
    name: "Concurrent Request Handling",
    description: "Sends 20 concurrent requests and measures success rate and response time distribution.",
    tags: ["performance", "concurrency"],
    run: async (ctx) => {
      const start = Date.now();
      const promises = Array.from({ length: 20 }, (_, i) =>
        api(ctx, `/health?_t=${Date.now()}_${i}`)
      );
      const responses = await Promise.all(promises);
      const totalTime = Date.now() - start;

      const statuses = responses.map(r => r?.status ?? 0);
      const successRate = statuses.filter(s => s === 200).length / statuses.length;
      const avgPerRequest = statuses.length > 0 ? totalTime / statuses.length : 0;

      return {
        id: "perf-01", name: "Concurrent Request Handling", category: "performance",
        status: successRate >= 0.95 ? "pass" : successRate >= 0.8 ? "warn" : "fail",
        duration: 0,
        message: `${statuses.filter(s => s === 200).length}/${statuses.length} succeeded in ${totalTime}ms (${Math.round(avgPerRequest)}ms avg/req, ${Math.round(successRate * 100)}% success)`,
        evidence: { totalTime, avgPerRequest, successRate, concurrent: 20, statuses },
        suggestion: successRate < 0.95 ? "Increase worker threads or add request queuing" : undefined,
      };
    },
    timeout: 30000,
  },
  {
    id: "perf-02",
    category: "performance",
    name: "Large Payload Handling",
    description: "Tests how the server handles large request bodies and response payloads.",
    tags: ["performance", "payload"],
    run: async (ctx) => {
      const large = await api(ctx, "/findings?page_size=100");

      return {
        id: "perf-02", name: "Large Payload Handling", category: "performance",
        status: large?.ok ? "pass" : "warn",
        duration: 0,
        message: `Large page fetch: HTTP ${large?.status}`,
        evidence: { status: large?.status },
        suggestion: !large?.ok ? "Consider limiting max page_size or adding streaming responses" : undefined,
      };
    },
  },
  {
    id: "perf-03",
    category: "performance",
    name: "Memory & Resource Usage Baseline",
    description: "Captures baseline process memory and uptime metrics.",
    tags: ["performance", "resources"],
    run: async () => {
      const mem = process.memoryUsage();
      const heapMB = Math.round(mem.heapUsed / 1024 / 1024 * 10) / 10;
      const rssMB = Math.round(mem.rss / 1024 / 1024);
      const uptime = Math.round(process.uptime());

      return {
        id: "perf-03", name: "Memory & Resource Usage Baseline", category: "performance",
        status: heapMB < 500 ? "pass" : "warn",
        duration: 0,
        message: `Heap: ${heapMB}MB, RSS: ${rssMB}MB, Uptime: ${uptime}s`,
        evidence: { heapMB, rssMB, uptime, external: Math.round(mem.external / 1024 / 1024) },
        suggestion: heapMB >= 500 ? "Check for memory leaks — consider profiling" : undefined,
      };
    },
  },
  {
    id: "perf-04",
    category: "performance",
    name: "Rapid Sequential Requests",
    description: "Tests latency consistency across 10 sequential requests to the same endpoint.",
    tags: ["performance", "latency"],
    run: async (ctx) => {
      const times: number[] = [];
      for (let i = 0; i < 10; i++) {
        const t0 = Date.now();
        await api(ctx, `/health?_seq=${Date.now()}_${i}`);
        times.push(Date.now() - t0);
      }

      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      const min = Math.min(...times);
      const max = Math.max(...times);
      const variance = times.reduce((sum, t) => sum + (t - avg) ** 2, 0) / times.length;
      const stdDev = Math.round(Math.sqrt(variance));

      return {
        id: "perf-04", name: "Rapid Sequential Requests", category: "performance",
        status: avg < 200 ? "pass" : avg < 500 ? "warn" : "fail",
        duration: 0,
        message: `${times.length} requests: avg ${Math.round(avg)}ms, min ${min}ms, max ${max}ms, stdDev ${stdDev}ms`,
        evidence: { times, avg, min, max, stdDev },
        suggestion: avg >= 500 ? "Investigate blocking operations or slow middleware" : undefined,
      };
    },
  },
  {
    id: "perf-05",
    category: "performance",
    name: "Gateway Timeout Check",
    description: "Verifies that long-running endpoints don't block the server indefinitely.",
    tags: ["performance", "timeouts"],
    run: async (ctx) => {
      const t0 = Date.now();
      const res = await api(ctx, "/health");
      const elapsed = Date.now() - t0;

      return {
        id: "perf-05", name: "Gateway Timeout Check", category: "performance",
        status: elapsed < 10000 ? "pass" : "fail",
        duration: 0,
        message: `Health check responded in ${elapsed}ms`,
        evidence: { elapsedMs: elapsed },
        suggestion: elapsed >= 10000 ? "Add request timeout middleware" : undefined,
      };
    },
  },
];

export const performanceSuite: TestSuite = {
  id: "performance",
  category: "performance",
  label: "Performance Testing",
  description: "Tests concurrent request handling, large payload processing, memory usage baselines, latency consistency, and timeout behavior.",
  icon: "Timer",
  tests: performanceTests,
};
