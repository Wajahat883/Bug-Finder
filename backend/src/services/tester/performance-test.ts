import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch } from "./fetch-utils";

const performanceTests: TestCase[] = [
  {
    id: "perf-01",
    category: "performance",
    name: "Concurrent Request Handling",
    description: "Sends 20 concurrent requests and measures success rate and response time.",
    tags: ["performance", "concurrency"],
    timeout: 30000,
    run: async (ctx) => {
      const start = Date.now();
      const promises = Array.from({ length: 20 }, (_, i) => testFetch(ctx, `/health?_t=${Date.now()}_${i}`));
      const responses = await Promise.all(promises);
      const totalTime = Date.now() - start;
      const statuses = responses.map(r => r?.status ?? 0);
      const successRate = statuses.filter(s => s === 200).length / statuses.length;
      const avgPerRequest = totalTime / statuses.length;

      return {
        id: "perf-01", name: "Concurrent Request Handling", category: "performance",
        status: successRate >= 0.95 ? "pass" : successRate >= 0.8 ? "warn" : "fail", duration: 0,
        message: `${statuses.filter(s => s === 200).length}/${statuses.length} succeeded in ${totalTime}ms (${Math.round(avgPerRequest)}ms avg/req, ${Math.round(successRate * 100)}% success)`,
        evidence: { totalTime, avgPerRequest, successRate, concurrent: 20 },
        suggestion: successRate < 0.95 ? "Increase worker threads or add queuing" : undefined,
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
    description: "Tests latency across 10 sequential requests.",
    tags: ["performance", "latency"],
    run: async (ctx) => {
      const times: number[] = [];
      for (let i = 0; i < 10; i++) {
        const t0 = Date.now();
        await testFetch(ctx, `/health?_s=${Date.now()}_${i}`);
        times.push(Date.now() - t0);
      }
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      const min = Math.min(...times);
      const max = Math.max(...times);
      return {
        id: "perf-04", name: "Latency Consistency", category: "performance",
        status: avg < 200 ? "pass" : avg < 500 ? "warn" : "fail", duration: 0,
        message: `Avg ${Math.round(avg)}ms, min ${min}ms, max ${max}ms across ${times.length} reqs`,
        evidence: { times, avg, min, max },
        suggestion: avg >= 500 ? "Investigate blocking operations" : undefined,
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
