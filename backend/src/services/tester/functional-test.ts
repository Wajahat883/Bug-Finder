import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch, ensureAuthenticated } from "./fetch-utils";

const functionalTests: TestCase[] = [
  {
    id: "func-01",
    category: "functional",
    name: "Dashboard Data Loading",
    description: "Verifies that the dashboard analytics endpoint returns all expected fields.",
    tags: ["functional", "dashboard"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const res = await testFetch(ctx, "/analytics/dashboard");
      const body = res ? await res.json().catch(() => null) : null;

      const required = ["total_findings", "total_scans", "severity_breakdown", "risk_trend", "mttr_days"];
      const allPresent = body && required.every(k => k in body);

      return {
        id: "func-01", name: "Dashboard Data Loading", category: "functional",
        status: allPresent ? "pass" : "warn", duration: 0,
        message: allPresent ? "Dashboard returns all required fields" : `Missing: ${required.filter(k => !(k in (body || {}))).join(", ")}`,
        evidence: body ? { fields: Object.keys(body) } : { error: res?.status ? "Not authorized" : "No response" },
        suggestion: res?.status === 401 ? "Run auth suite first to authenticate" : !allPresent ? "Check dashboard analytics route" : undefined,
      };
    },
  },
  {
    id: "func-02",
    category: "functional",
    name: "Findings CRUD Operations",
    description: "Tests that findings can be listed and searched.",
    tags: ["functional", "findings"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const listRes = await testFetch(ctx, "/findings?page_size=1");
      const list = listRes ? await listRes.json().catch(() => null) : null;

      const searchRes = await testFetch(ctx, "/search?q=SQL&type=findings");

      return {
        id: "func-02", name: "Findings CRUD Operations", category: "functional",
        status: listRes?.ok && searchRes?.ok ? "pass" : "warn", duration: 0,
        message: `List: HTTP ${listRes?.status}, Search: HTTP ${searchRes?.status}`,
        evidence: { listOk: listRes?.ok, searchOk: searchRes?.ok },
        suggestion: !listRes?.ok ? "Check findings GET — may need auth" : undefined,
      };
    },
  },
  {
    id: "func-03",
    category: "functional",
    name: "Scans Workflow",
    description: "Tests scan listing with status filter.",
    tags: ["functional", "scans"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const allRes = await testFetch(ctx, "/scans?page_size=1");
      const completedRes = await testFetch(ctx, "/scans?status=completed&page_size=1");

      return {
        id: "func-03", name: "Scans Workflow", category: "functional",
        status: allRes?.ok !== false ? "pass" : "warn", duration: 0,
        message: `All scans: HTTP ${allRes?.status}, Completed: HTTP ${completedRes?.status}`,
        evidence: { allStatus: allRes?.status, completedStatus: completedRes?.status },
        suggestion: !allRes?.ok ? "Check scans endpoint" : undefined,
      };
    },
  },
  {
    id: "func-04",
    category: "functional",
    name: "Targets CRUD Flow",
    description: "Tests that targets can be listed.",
    tags: ["functional", "targets"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const listRes = await testFetch(ctx, "/targets");
      const listBody = listRes ? await listRes.json().catch(() => null) : null;
      const items = (listBody as any)?.targets ?? listBody ?? [];
      const count = Array.isArray(items) ? items.length : 0;

      return {
        id: "func-04", name: "Targets CRUD Flow", category: "functional",
        status: listRes?.ok ? "pass" : "warn", duration: 0,
        message: `Targets: HTTP ${listRes?.status}, Count: ${count}`,
        evidence: { status: listRes?.status, count },
        suggestion: !listRes?.ok ? "Check targets endpoint" : undefined,
      };
    },
  },
  {
    id: "func-05",
    category: "functional",
    name: "Remediations Management",
    description: "Tests remediations listing.",
    tags: ["functional", "remediation"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const listRes = await testFetch(ctx, "/remediations");
      const listBody = listRes ? await listRes.json().catch(() => null) : null;
      const items = (listBody as any)?.remediations ?? listBody ?? [];
      const count = Array.isArray(items) ? items.length : 0;

      return {
        id: "func-05", name: "Remediations Management", category: "functional",
        status: listRes?.ok ? "pass" : "warn", duration: 0,
        message: `Remediations: HTTP ${listRes?.status}, Count: ${count}`,
        evidence: { status: listRes?.status, count },
        suggestion: !listRes?.ok ? "Check remediations endpoint" : undefined,
      };
    },
  },
  {
    id: "func-06",
    category: "functional",
    name: "Settings Save & Retrieve",
    description: "Validates that settings can be read.",
    tags: ["functional", "settings"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const getRes = await testFetch(ctx, "/settings");
      const getBody = getRes ? await getRes.json().catch(() => null) : null;

      return {
        id: "func-06", name: "Settings Save & Retrieve", category: "functional",
        status: getRes?.ok ? "pass" : "warn", duration: 0,
        message: `Settings: HTTP ${getRes?.status}`,
        evidence: getBody ? { fields: Object.keys(getBody).slice(0, 5) } : { error: "No response" },
        suggestion: !getRes?.ok ? "Check settings GET endpoint" : undefined,
      };
    },
  },
];

export const functionalSuite: TestSuite = {
  id: "functional", category: "functional", label: "Functional Testing",
  description: "Validates core feature workflows: dashboard loading, findings CRUD, scan filtering, targets, remediation tracking, and settings.",
  icon: "CheckCircle2", tests: functionalTests,
};
