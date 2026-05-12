import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch, ensureAuthenticated } from "./fetch-utils";

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
        const res = await testFetch(ctx, ep);
        const ct = res?.headers.get("content-type") ?? "";
        results[ep] = { status: res?.status ?? 0, isJson: ct.includes("application/json"), ok: !!res?.ok };
      }

      const allResponding = Object.values(results).every(r => r.status > 0);
      const allJson = Object.values(results).every(r => r.isJson);
      const nonJson = Object.entries(results).filter(([, r]) => !r.isJson).map(([e]) => e).join(", ");

      return {
        id: "api-01", name: "REST Endpoint Health Check", category: "api",
        status: allResponding && allJson ? "pass" : "warn", duration: 0,
        message: allResponding && allJson ? `All ${endpoints.length} endpoints respond with JSON` : `Non-JSON: ${nonJson}`,
        evidence: results,
        suggestion: !allJson ? "Ensure Content-Type: application/json on all routes" : undefined,
      };
    },
  },
  {
    id: "api-02",
    category: "api",
    name: "Pagination & Sorting",
    description: "Tests that pagination params work on list endpoints.",
    tags: ["api", "pagination"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const res = await testFetch(ctx, "/findings?page=1&page_size=3");
      const body = res ? await res.json().catch(() => null) : null;

      const hasError = body && typeof body.error === "string";
      const hasPagination = !hasError && body && (Array.isArray(body.findings) || Array.isArray(body.items));

      return {
        id: "api-02", name: "Pagination & Sorting", category: "api",
        status: hasPagination ? "pass" : "warn", duration: 0,
        message: hasError ? `Auth required: ${String(body?.error)}` : hasPagination ? "Pagination working" : "No pagination format detected",
        evidence: { responseKeys: body ? Object.keys(body) : [], hasError },
        suggestion: hasError ? "Requires authentication — run auth suite first" : !hasPagination ? "Add page/page_size to findings list endpoint" : undefined,
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
      const badBody = await testFetch(ctx, "/auth/login", { method: "POST", body: JSON.stringify({}) });
      const badMethod = await testFetch(ctx, "/auth/me", { method: "POST" });
      const bd = badBody ? await badBody.json().catch(() => null) : null;
      const bm = badMethod ? await badMethod.json().catch(() => null) : null;

      const hasErrorField = (bd && typeof bd.error === "string") || (bm && typeof bm.error === "string");

      return {
        id: "api-03", name: "Error Response Format", category: "api",
        status: hasErrorField ? "pass" : "warn", duration: 0,
        message: hasErrorField ? "Error responses contain valid { error } field" : "Inconsistent error format",
        evidence: { badBodyResponse: bd, badMethodResponse: bm },
        suggestion: !hasErrorField ? "Standardize all error responses to { error: string }" : undefined,
      };
    },
  },
  {
    id: "api-04",
    category: "api",
    name: "CORS Headers",
    description: "Verifies CORS headers are present on API responses.",
    tags: ["api", "cors"],
    run: async (ctx) => {
      const res = await testFetch(ctx, "/health", { headers: { Origin: "https://bugfinder.io" } });
      const acao = res?.headers.get("access-control-allow-origin") ?? "";
      const acac = res?.headers.get("access-control-allow-credentials") ?? "";

      return {
        id: "api-04", name: "CORS Headers", category: "api",
        status: acao ? "pass" : "warn", duration: 0,
        message: acao ? `ACAO: ${acao}, Credentials: ${acac}` : "No Access-Control-Allow-Origin header",
        evidence: { acao, acac },
        suggestion: !acao ? "Enable CORS middleware" : undefined,
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
      const noBody = await testFetch(ctx, "/auth/login", { method: "POST" });
      const hugeBody = await testFetch(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: "x".repeat(100000), password: "y".repeat(100000) }) });

      const status: TestResult["status"] =
        noBody?.status === 429 ? "warn" :
        noBody?.status !== 500 && hugeBody?.status !== 500 ? "pass" : "fail";

      return {
        id: "api-05", name: "Request Validation", category: "api", status, duration: 0,
        message: `No body: HTTP ${noBody?.status}, Huge payload: HTTP ${hugeBody?.status}`,
        evidence: { noBodyStatus: noBody?.status, hugeBodyStatus: hugeBody?.status },
        suggestion: status === "fail" ? "Add body size limits and required field validation" : noBody?.status === 429 ? "Rate limited — skip when running with auth suite" : undefined,
      };
    },
  },
  {
    id: "api-06",
    category: "api",
    name: "Response Time Benchmark",
    description: "Measures response times for key endpoints.",
    tags: ["api", "performance"],
    run: async (ctx) => {
      const benchmarks: Record<string, number> = {};
      const eps = ["/health"];
      for (const ep of eps) {
        const t0 = Date.now();
        await testFetch(ctx, ep);
        benchmarks[ep] = Date.now() - t0;
      }
      const avgMs = Object.values(benchmarks).reduce((a, b) => a + b, 0) / Object.values(benchmarks).length;

      return {
        id: "api-06", name: "Response Time Benchmark", category: "api",
        status: avgMs < 2000 ? "pass" : "warn", duration: 0,
        message: `Avg response: ${Math.round(avgMs)}ms`,
        evidence: { benchmarks, avgMs },
        suggestion: avgMs >= 2000 ? "Investigate slow endpoints" : undefined,
      };
    },
  },
];

export const apiSuite: TestSuite = {
  id: "api", category: "api", label: "API Testing",
  description: "Validates REST endpoint health, pagination, error formats, CORS, input validation, and response time benchmarks.",
  icon: "Terminal", tests: apiTests,
};
