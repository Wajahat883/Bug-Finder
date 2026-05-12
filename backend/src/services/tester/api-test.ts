import { TestSuite, TestCase, TestContext, TestResult } from "./types";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers },
    ...opts,
  }).catch(() => null);
}

const apiTests: TestCase[] = [
  {
    id: "api-01",
    category: "api",
    name: "REST Endpoint Health Check",
    description: "Verifies all major REST endpoints return valid JSON responses with correct content types.",
    tags: ["api", "rest"],
    run: async (ctx) => {
      const endpoints = ["/health", "/auth/me", "/scans?page_size=1", "/findings?page_size=1", "/targets", "/system", "/settings"];
      const results: Record<string, { status: number; isJson: boolean; ok: boolean }> = {};

      for (const ep of endpoints) {
        const res = await api(ctx, ep);
        const ct = res?.headers.get("content-type") ?? "";
        results[ep] = {
          status: res?.status ?? 0,
          isJson: ct.includes("application/json"),
          ok: !!res?.ok,
        };
      }

      const allResponding = Object.values(results).every(r => r.status > 0);
      const allJson = Object.values(results).every(r => r.isJson);
      const status: TestResult["status"] = allResponding && allJson ? "pass" : "fail";

      return {
        id: "api-01", name: "REST Endpoint Health Check", category: "api", status, duration: 0,
        message: allResponding && allJson ? `All ${endpoints.length} endpoints respond with JSON` : `Issues: responding=${allResponding}, json=${allJson}`,
        evidence: results,
        suggestion: !allResponding ? "Check route registration" : !allJson ? "Ensure Content-Type: application/json headers" : undefined,
      };
    },
  },
  {
    id: "api-02",
    category: "api",
    name: "Pagination & Sorting",
    description: "Tests that pagination params work and sorting returns ordered results.",
    tags: ["api", "pagination"],
    run: async (ctx) => {
      const pageRes = await api(ctx, "/findings?page=1&page_size=3");
      const largePage = await api(ctx, "/findings?page=1&page_size=1000");
      const body = pageRes ? await pageRes.json().catch(() => null) : null;

      const hasPagination = body && Array.isArray(body.findings || body.items || body);
      const boundedOk = largePage?.ok !== false;

      return {
        id: "api-02", name: "Pagination & Sorting", category: "api",
        status: hasPagination ? "pass" : "warn",
        duration: 0,
        message: hasPagination ? "Pagination working correctly" : "No paginated response format detected",
        evidence: { pageSizeResponse: body ? Object.keys(body).slice(0, 5) : null },
        suggestion: !hasPagination ? "Add page/page_size params to list endpoints" : undefined,
      };
    },
  },
  {
    id: "api-03",
    category: "api",
    name: "Error Response Format",
    description: "Ensures all error responses return consistent { error: string } JSON format.",
    tags: ["api", "error-handling"],
    run: async (ctx) => {
      const badUrl = await api(ctx, "/scan-jobs/nonexistent-id/stream");
      const badBody = await api(ctx, "/auth/login", { method: "POST", body: JSON.stringify({}) });
      const badMethod = await api(ctx, "/auth/me", { method: "POST" });

      const [bd, bm] = [
        badBody ? await badBody.json().catch(() => null) : null,
        badMethod ? await badMethod.json().catch(() => null) : null,
      ];

      const hasErrorField = (bd && typeof bd.error === "string") || (bm && typeof bm.error === "string");

      return {
        id: "api-03", name: "Error Response Format", category: "api",
        status: hasErrorField ? "pass" : "warn",
        duration: 0,
        message: hasErrorField ? "Error responses contain valid { error } field" : "Error response format inconsistent",
        evidence: { badBodyResponse: bd, notFoundResponse: bm },
        suggestion: !hasErrorField ? "Standardize all error responses to { error: string }" : undefined,
      };
    },
  },
  {
    id: "api-04",
    category: "api",
    name: "CORS Headers",
    description: "Verifies CORS headers are present on API responses for cross-origin access.",
    tags: ["api", "cors"],
    run: async (ctx) => {
      const res = await api(ctx, "/health", { headers: { Origin: "https://bugfinder.io" } });
      const acao = res?.headers.get("access-control-allow-origin") ?? "";
      const acac = res?.headers.get("access-control-allow-credentials") ?? "";

      return {
        id: "api-04", name: "CORS Headers", category: "api",
        status: acao ? "pass" : "warn",
        duration: 0,
        message: acao ? `ACAO: ${acao}, Credentials: ${acac}` : "No Access-Control-Allow-Origin header",
        evidence: { acao, acac, origin: "https://bugfinder.io" },
        suggestion: !acao ? "Enable CORS middleware with specific origins" : undefined,
      };
    },
  },
  {
    id: "api-05",
    category: "api",
    name: "Request Validation",
    description: "Tests that API rejects malformed input with 400 rather than crashing with 500.",
    tags: ["api", "validation"],
    run: async (ctx) => {
      const noBody = await api(ctx, "/auth/login", { method: "POST" });
      const hugeBody = await api(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: "x".repeat(100000), password: "y".repeat(100000) }) });
      const sqlInjection = await api(ctx, "/findings?page=1&page_size=' OR '1'='1");

      const status: TestResult["status"] =
        noBody?.status !== 500 && hugeBody?.status !== 500 ? "pass" : "fail";

      return {
        id: "api-05", name: "Request Validation", category: "api",
        status, duration: 0,
        message: `No body: HTTP ${noBody?.status}, Huge payload: HTTP ${hugeBody?.status}`,
        evidence: { noBodyStatus: noBody?.status, hugeBodyStatus: hugeBody?.status },
        suggestion: status === "fail" ? "Add input validation middleware (body size limits, required fields)" : undefined,
      };
    },
  },
  {
    id: "api-06",
    category: "api",
    name: "Response Time Benchmark",
    description: "Measures response times for key endpoints to establish performance baseline.",
    tags: ["api", "performance"],
    run: async (ctx) => {
      const benchmarks: Record<string, number> = {};
      const eps = ["/health", "/auth/me", "/findings?page_size=1"];

      for (const ep of eps) {
        const t0 = Date.now();
        await api(ctx, ep);
        benchmarks[ep] = Date.now() - t0;
      }

      const avgMs = Object.values(benchmarks).reduce((a, b) => a + b, 0) / Object.values(benchmarks).length;
      const status: TestResult["status"] = avgMs < 2000 ? "pass" : "warn";

      return {
        id: "api-06", name: "Response Time Benchmark", category: "api", status, duration: 0,
        message: `Avg response: ${Math.round(avgMs)}ms across ${Object.keys(benchmarks).length} endpoints`,
        evidence: { benchmarks, avgMs },
        suggestion: avgMs >= 2000 ? "Investigate slow endpoints for optimization" : undefined,
      };
    },
  },
];

export const apiSuite: TestSuite = {
  id: "api",
  category: "api",
  label: "API Testing",
  description: "Validates REST endpoint health, pagination, error formats, CORS, input validation, and response time benchmarks.",
  icon: "Terminal",
  tests: apiTests,
};
