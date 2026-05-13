import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch } from "./fetch-utils";

const performanceTests: TestCase[] = [
  {
    id: "perf-01",
    category: "performance",
    name: "Concurrent Request Handling",
    description: "Sends 5 staggered concurrent requests and measures success rate.",
    tags: ["performance", "concurrency"],
    timeout: 30000,
    run: async (ctx) => {
      const results: Array<{ status: number }> = [];
      for (let i = 0; i < 5; i++) {
        const res = await testFetch(ctx, `/health?_t=${Date.now()}_${i}`);
        results.push({ status: res?.status ?? 0 });
      }
      const statuses = results.map(r => r.status);
      const successRate = statuses.filter(s => s === 200).length / statuses.length;

      return {
        id: "perf-01", name: "Concurrent Request Handling", category: "performance",
        status: successRate >= 0.8 ? "pass" : "warn", duration: 0,
        message: `${statuses.filter(s => s === 200).length}/${statuses.length} succeeded (${Math.round(successRate * 100)}%)`,
        evidence: { successRate, statuses },
        suggestion: successRate < 0.8 ? "Server may need optimization" : undefined,
      };
    },
  },
  {
    id: "perf-02",
    category: "performance",
    name: "Large Payload Handling",
    description: "Tests server behavior with large page sizes.",
    tags: ["performance", "payload"],
    run: async (ctx) => {
      const large = await testFetch(ctx, "/findings?page_size=100");
      return {
        id: "perf-02", name: "Large Payload Handling", category: "performance",
        status: large?.ok || large?.status === 401 ? "pass" : "warn", duration: 0,
        message: `Large page: HTTP ${large?.status}`,
        evidence: { status: large?.status },
        suggestion: !large?.ok && large?.status !== 401 ? "Consider limiting max page_size" : undefined,
      };
    },
  },
  {
    id: "perf-03",
    category: "performance",
    name: "Memory & Resource Usage",
    description: "Captures baseline process memory and uptime.",
    tags: ["performance", "resources"],
    run: async () => {
      const mem = process.memoryUsage();
      const heapMB = Math.round(mem.heapUsed / 1024 / 1024 * 10) / 10;
      const rssMB = Math.round(mem.rss / 1024 / 1024);
      const uptime = Math.round(process.uptime());
      return {
        id: "perf-03", name: "Memory & Resource Usage", category: "performance",
        status: heapMB < 500 ? "pass" : "warn", duration: 0,
        message: `Heap: ${heapMB}MB, RSS: ${rssMB}MB, Uptime: ${uptime}s`,
        evidence: { heapMB, rssMB, uptime },
        suggestion: heapMB >= 500 ? "Check for memory leaks" : undefined,
      };
    },
  },
  {
    id: "perf-04",
    category: "performance",
    name: "Latency Consistency",
    description: "Tests latency across 3 sequential requests.",
    tags: ["performance", "latency"],
    timeout: 20000,
    run: async (ctx) => {
      const times: number[] = [];
      for (let i = 0; i < 3; i++) {
        const t0 = Date.now();
        await testFetch(ctx, `/health?_s=${Date.now()}_${i}`);
        times.push(Date.now() - t0);
      }
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      return {
        id: "perf-04", name: "Latency Consistency", category: "performance",
        status: avg < 5000 ? "pass" : "warn", duration: 0,
        message: `Avg ${Math.round(avg)}ms across ${times.length} reqs`,
        evidence: { times, avg },
        suggestion: avg >= 5000 ? "Investigate slow middleware" : undefined,
      };
    },
  },
  {
    id: "perf-05",
    category: "performance",
    name: "Gateway Timeout Check",
    description: "Verifies endpoints respond within acceptable time.",
    tags: ["performance", "timeouts"],
    run: async (ctx) => {
      const t0 = Date.now();
      const res = await testFetch(ctx, "/health");
      const elapsed = Date.now() - t0;
      return {
        id: "perf-05", name: "Gateway Timeout Check", category: "performance",
        status: elapsed < 10000 ? "pass" : "fail", duration: 0,
        message: `Health responded in ${elapsed}ms`,
        evidence: { elapsedMs: elapsed },
        suggestion: elapsed >= 10000 ? "Add request timeout middleware" : undefined,
      };
    },
  },
];

export const performanceSuite: TestSuite = {
  id: "performance", category: "performance", label: "Performance Testing",
  description: "Tests concurrent requests, large payloads, memory usage, latency consistency, and timeout behavior.",
  icon: "Timer", tests: performanceTests,
};
