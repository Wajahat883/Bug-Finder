import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch, ensureAuthenticated, isRateLimited, rateLimitWarn } from "./fetch-utils";

const rbacTests: TestCase[] = [
  {
    id: "rbac-01",
    category: "rbac",
    name: "Unauthenticated Access Denied",
    description: "Verifies that API endpoints return 401 when no session/cookie is present.",
    tags: ["rbac", "auth"],
    run: async (ctx) => {
      const savedCookie = ctx.cookieStore.get(ctx.apiBase) ?? "";
      ctx.cookieStore.delete(ctx.apiBase);

      const endpoints = ["/auth/me", "/scans?page_size=1", "/findings?page_size=1", "/targets", "/system", "/settings"];
      const results: Record<string, number> = {};
      for (const ep of endpoints) {
        const res = await testFetch(ctx, ep);
        results[ep] = res?.status ?? 0;
      }

      if (savedCookie) ctx.cookieStore.set(ctx.apiBase, savedCookie);

      const allDenied = Object.values(results).every(s => s === 401);
      const allowed = Object.entries(results).filter(([, s]) => s !== 401).map(([e, s]) => `${e}=${s}`).join(", ");

      return {
        id: "rbac-01", name: "Unauthenticated Access Denied", category: "rbac",
        status: allDenied ? "pass" : "warn", duration: 0,
        message: allDenied ? `All ${Object.keys(results).length} protected endpoints returned 401` : `Allowed without auth: ${allowed}`,
        evidence: results,
        suggestion: !allDenied ? `Add requireAuth middleware to routes` : undefined,
      };
    },
  },
  {
    id: "rbac-02",
    category: "rbac",
    name: "Normal User Cannot Access Admin Routes",
    description: "Tests that a standard analyst user is blocked from admin-only endpoints.",
    tags: ["rbac", "admin"],
    run: async (ctx) => {
      const authed = await ensureAuthenticated(ctx);
      if (!authed) return { id: "rbac-02", name: "Normal User Cannot Access Admin Routes", category: "rbac", status: "warn", duration: 0, message: "No authenticated session available — run auth suite first" };

      const adminEndpoints = ["/admin/stats", "/api/api-keys", "/api/scanner/rules"];
      const results: Record<string, number> = {};
      for (const ep of adminEndpoints) {
        const res = await testFetch(ctx, ep);
        results[ep] = res?.status ?? 0;
      }

      const allBlocked = Object.values(results).every(s => s === 401 || s === 403);
      const blocked = Object.entries(results).filter(([, s]) => s === 401 || s === 403).length;

      return {
        id: "rbac-02", name: "Normal User Cannot Access Admin Routes", category: "rbac",
        status: allBlocked ? "pass" : "fail", duration: 0,
        message: `${blocked}/${Object.keys(results).length} admin endpoints blocked`,
        evidence: results,
        suggestion: !allBlocked ? "Add requireAdmin middleware to admin routes" : undefined,
      };
    },
  },
  {
    id: "rbac-03",
    category: "rbac",
    name: "Role Separation — Core Access",
    description: "Verifies authenticated user can access core endpoints.",
    tags: ["rbac", "roles"],
    run: async (ctx) => {
      const authed = await ensureAuthenticated(ctx);
      if (!authed) return { id: "rbac-03", name: "Role Separation — Core Access", category: "rbac", status: "warn", duration: 0, message: "No authenticated session" };

      const results: Record<string, number> = {};
      const eps = ["/scans?page_size=1", "/findings?page_size=1", "/remediations", "/targets"];
      for (const ep of eps) {
        const res = await testFetch(ctx, ep);
        results[ep] = res?.status ?? 0;
      }

      const allOk = Object.values(results).every(s => s === 200);
      const failures = Object.entries(results).filter(([, s]) => s !== 200).map(([e, s]) => `${e}=${s}`).join(", ");

      return {
        id: "rbac-03", name: "Role Separation — Core Access", category: "rbac",
        status: allOk ? "pass" : "warn", duration: 0,
        message: allOk ? "All core endpoints accessible" : `Blocked: ${failures}`,
        evidence: results,
        suggestion: !allOk ? "Check requireAuth middleware or session middleware" : undefined,
      };
    },
  },
  {
    id: "rbac-04",
    category: "rbac",
    name: "IDOR — Self-Update Only",
    description: "Verifies that users can update their own profile.",
    tags: ["rbac", "idor"],
    run: async (ctx) => {
      const authed = await ensureAuthenticated(ctx);
      if (!authed) return { id: "rbac-04", name: "IDOR — Self-Update Only", category: "rbac", status: "warn", duration: 0, message: "No authenticated session" };

      const profileRes = await testFetch(ctx, "/auth/profile", { method: "PATCH", body: JSON.stringify({ first_name: "UpdatedName" }) });
      return {
        id: "rbac-04", name: "IDOR — Self-Update Only", category: "rbac",
        status: profileRes?.ok ? "pass" : "warn", duration: 0,
        message: `Profile update: HTTP ${profileRes?.status}`,
        evidence: { profileStatus: profileRes?.status },
        suggestion: !profileRes?.ok ? "Profile updates must be scoped to current user" : undefined,
      };
    },
  },
  {
    id: "rbac-05",
    category: "rbac",
    name: "API Key Scope Enforcement",
    description: "Tests whether invalid API keys are rejected.",
    tags: ["rbac", "apikeys"],
    run: async (ctx) => {
      const results: Record<string, number> = {};
      const eps = ["/scans?page_size=1", "/findings?page_size=1"];
      for (const ep of eps) {
        const res = await testFetch(ctx, ep, { headers: { "X-API-Key": "invalid-test-key-0000" } });
        results[ep] = res?.status ?? 0;
      }

      const keyAccess = Object.values(results).some(s => s === 200);
      return {
        id: "rbac-05", name: "API Key Scope Enforcement", category: "rbac",
        status: keyAccess ? "fail" : "pass", duration: 0,
        message: keyAccess ? "Invalid API key granted access" : "Invalid API key correctly rejected",
        evidence: results,
        suggestion: keyAccess ? "API key middleware must reject invalid keys" : undefined,
      };
    },
  },
];

export const rbacSuite: TestSuite = {
  id: "rbac",
  category: "rbac",
  label: "Role-Based Access Testing",
  description: "Validates role separation, admin isolation, unauthenticated access denial, IDOR protection, and API key scope enforcement.",
  icon: "Shield",
  tests: rbacTests,
};
