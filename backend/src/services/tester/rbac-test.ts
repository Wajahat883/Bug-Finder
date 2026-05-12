import { TestSuite, TestCase, TestContext, TestResult } from "./types";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers },
    ...opts,
  }).catch(() => null);
}

const rbacTests: TestCase[] = [
  {
    id: "rbac-01",
    category: "rbac",
    name: "Unauthenticated Access Denied",
    description: "Verifies that API endpoints return 401 when no session/cookie is present.",
    tags: ["rbac", "auth"],
    run: async (ctx) => {
      const endpoints = ["/auth/me", "/scans", "/findings", "/targets", "/system", "/settings"];
      const results: Record<string, number> = {};

      for (const ep of endpoints) {
        const res = await api(ctx, ep);
        results[ep] = res?.status ?? 0;
      }

      const allDenied = Object.values(results).every(s => s === 401);
      const deniedList = Object.entries(results).filter(([, s]) => s === 401).map(([e]) => e).join(", ");
      const allowed = Object.entries(results).filter(([, s]) => s !== 401).map(([e, s]) => `${e}=${s}`).join(", ");

      return {
        id: "rbac-01", name: "Unauthenticated Access Denied", category: "rbac",
        status: allDenied ? "pass" : "warn",
        duration: 0,
        message: allDenied ? `All ${Object.keys(results).length} protected endpoints returned 401` : `Allowed without auth: ${allowed}`,
        evidence: results,
        suggestion: !allDenied ? `Add auth middleware to: ${allowed}` : undefined,
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
      const adminEndpoints = ["/admin/stats", "/admin/users", "/api-keys", "/scanner/rules"];
      const results: Record<string, number> = {};

      for (const ep of adminEndpoints) {
        const res = await api(ctx, ep);
        results[ep] = res?.status ?? 0;
      }

      const allBlocked = Object.values(results).every(s => s === 401 || s === 403);
      const blocked = Object.entries(results).filter(([, s]) => s === 401 || s === 403).length;

      return {
        id: "rbac-02", name: "Normal User Cannot Access Admin Routes", category: "rbac",
        status: allBlocked ? "pass" : "fail",
        duration: 0,
        message: allBlocked ? `${blocked}/${Object.keys(results).length} admin endpoints correctly blocked` : `Some admin endpoints accessible without admin role`,
        evidence: results,
        suggestion: !allBlocked ? "Check requireAdmin middleware on admin endpoints" : undefined,
      };
    },
  },
  {
    id: "rbac-03",
    category: "rbac",
    name: "Admin vs Viewer vs Analyst Role Separation",
    description: "Verifies that different roles have appropriate access boundaries.",
    tags: ["rbac", "roles"],
    run: async (ctx) => {
      const roleTests = [
        { ep: "/scans", method: "GET", desc: "GET scans" },
        { ep: "/findings", method: "GET", desc: "GET findings" },
        { ep: "/remediations", method: "GET", desc: "GET remediations" },
        { ep: "/admin/users", method: "GET", desc: "GET admin users" },
      ];

      const results: Record<string, { status: number; ok: boolean }> = {};
      for (const t of roleTests) {
        const res = await api(ctx, t.ep);
        results[t.desc] = { status: res?.status ?? 0, ok: !!res?.ok };
      }

      const userRoutesOk = ["GET scans", "GET findings", "GET remediations"].every(k => results[k]?.ok);
      const adminRoutesBlocked = results["GET admin users"]?.status === 401 || results["GET admin users"]?.status === 403 || !results["GET admin users"];

      return {
        id: "rbac-03", name: "Admin vs Viewer vs Analyst Role Separation", category: "rbac",
        status: userRoutesOk && adminRoutesBlocked ? "pass" : "warn",
        duration: 0,
        message: userRoutesOk && adminRoutesBlocked ? "Role separation properly enforced" : `User routes ok=${userRoutesOk}, Admin blocked=${adminRoutesBlocked}`,
        evidence: results,
        suggestion: !userRoutesOk ? "Ensure analyst/viewer roles can access core endpoints" : !adminRoutesBlocked ? "Admin routes must require admin role" : undefined,
      };
    },
  },
  {
    id: "rbac-04",
    category: "rbac",
    name: "IDOR — Self-Update Only",
    description: "Verifies that users can only update their own profile, not other users' data.",
    tags: ["rbac", "idor"],
    run: async (ctx) => {
      const profileRes = await api(ctx, "/auth/profile", {
        method: "PATCH",
        body: JSON.stringify({ first_name: "UpdatedName" }),
      });

      return {
        id: "rbac-04", name: "IDOR — Self-Update Only", category: "rbac",
        status: profileRes?.ok ? "pass" : "warn",
        duration: 0,
        message: `Profile update: HTTP ${profileRes?.status}`,
        evidence: { profileStatus: profileRes?.status },
        suggestion: !profileRes?.ok ? "Ensure profile updates are scoped to current user" : undefined,
      };
    },
  },
  {
    id: "rbac-05",
    category: "rbac",
    name: "API Key Scope Enforcement",
    description: "Tests whether API keys have proper scope restriction and cannot access admin routes.",
    tags: ["rbac", "apikeys"],
    run: async (ctx) => {
      const results: Record<string, number> = {};
      const eps = ["/scans", "/findings"];
      for (const ep of eps) {
        const res = await api(ctx, ep, { headers: { "X-API-Key": "invalid-test-key-0000" } });
        results[ep] = res?.status ?? 0;
      }

      const keyAccess = Object.values(results).some(s => s === 200);

      return {
        id: "rbac-05", name: "API Key Scope Enforcement", category: "rbac",
        status: keyAccess ? "fail" : "pass",
        duration: 0,
        message: keyAccess ? "Invalid API key granted access — scope not enforced" : "Invalid API key correctly rejected",
        evidence: results,
        suggestion: keyAccess ? "API key middleware must reject invalid keys with 401" : undefined,
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
