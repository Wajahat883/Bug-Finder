import crypto from "crypto";
import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { col } from "../../lib/db";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers },
    ...opts,
  }).catch(() => null);
}

interface SnapshotEntry {
  path: string;
  status: number;
  bodyHash: string;
  keyFields?: string[];
}

function hashContent(body: string): string {
  return crypto.createHash("md5").update(body).digest("hex");
}

async function takeSnapshot(ctx: TestContext): Promise<SnapshotEntry[]> {
  const endpoints = [
    "/health",
    "/analytics/dashboard",
    "/scans?page_size=1",
    "/findings?page_size=1",
    "/targets",
    "/system",
    "/settings",
  ];

  const snapshots: SnapshotEntry[] = [];
  for (const ep of endpoints) {
    const res = await api(ctx, ep);
    const body = res ? await res.text().catch(() => "") : "";
    snapshots.push({
      path: ep,
      status: res?.status ?? 0,
      bodyHash: hashContent(body),
      keyFields: res?.ok ? Object.keys(res ? (await res.clone().json().catch(() => ({}))) : {}) : [],
    });
  }
  return snapshots;
}

const regressionTests: TestCase[] = [
  {
    id: "reg-01",
    category: "regression",
    name: "API Snapshot Comparison",
    description: "Takes a snapshot of all major API endpoints and compares response structure with the previous run to detect regressions.",
    tags: ["regression", "api"],
    run: async (ctx) => {
      const current = await takeSnapshot(ctx);
      const prevRun = await col("test_snapshots").findOne({}).sort({ taken_at: -1 }) as Record<string, unknown> | null;

      if (!prevRun) {
        await col("test_snapshots").insertOne({ run_id: crypto.randomUUID(), snapshots: current, taken_at: new Date() });
        return {
          id: "reg-01", name: "API Snapshot Comparison", category: "regression",
          status: "pass",
          duration: 0,
          message: "First snapshot created — no previous baseline to compare",
          evidence: { snapshotCount: current.length, note: "Baseline established" },
        };
      }

      await col("test_snapshots").insertOne({ run_id: crypto.randomUUID(), snapshots: current, taken_at: new Date() });

      const prev = (prevRun["snapshots"] as SnapshotEntry[]) ?? [];
      const changes: string[] = [];
      const errors: string[] = [];

      for (const cur of current) {
        const prevEntry = prev.find(p => p.path === cur.path);

        if (!prevEntry) {
          changes.push(`NEW: ${cur.path} — HTTP ${cur.status}`);
          continue;
        }

        if (cur.status !== prevEntry.status && cur.status >= 500) {
          errors.push(`${cur.path}: HTTP ${prevEntry.status} → ${cur.status}`);
        } else if (cur.status >= 500 && prevEntry.status < 500) {
          errors.push(`${cur.path}: REGRESSION — now returning ${cur.status}`);
        }

        if (cur.bodyHash !== prevEntry.bodyHash) {
          changes.push(`${cur.path}: response body changed`);
        }
      }

      for (const p of prev) {
        if (!current.find(c => c.path === p.path)) {
          errors.push(`MISSING: ${p.path} — endpoint removed`);
        }
      }

      const allStable = changes.length === 0 && errors.length === 0;

      return {
        id: "reg-01", name: "API Snapshot Comparison", category: "regression",
        status: allStable ? "pass" : errors.length > 0 ? "fail" : "warn",
        duration: 0,
        message: allStable ? `${current.length} endpoints unchanged` : `${changes.length} changes, ${errors.length} errors`,
        evidence: { changes, errors, endpointCount: current.length },
        suggestion: errors.length > 0 ? `Fix regressions: ${errors.slice(0, 3).join("; ")}` : undefined,
      };
    },
  },
  {
    id: "reg-02",
    category: "regression",
    name: "Endpoint Availability Check",
    description: "Verifies all registered API endpoints are accessible and returning valid status codes.",
    tags: ["regression", "endpoints"],
    run: async (ctx) => {
      const eps = [
        { path: "/health", method: "GET" },
        { path: "/auth/me", method: "GET" },
        { path: "/scans?page_size=1", method: "GET" },
        { path: "/findings?page_size=1", method: "GET" },
        { path: "/targets", method: "GET" },
        { path: "/remediations", method: "GET" },
        { path: "/system", method: "GET" },
        { path: "/settings", method: "GET" },
        { path: "/analytics/dashboard", method: "GET" },
        { path: "/analytics/activity", method: "GET" },
      ];

      const results: Record<string, number> = {};
      for (const { path, method } of eps) {
        const res = await api(ctx, path, { method });
        results[path] = res?.status ?? 0;
      }

      const available = Object.entries(results).filter(([, s]) => s > 0 && s < 500).length;
      const broken = Object.entries(results).filter(([, s]) => s === 0).map(([p]) => p);
      const serverErrors = Object.entries(results).filter(([, s]) => s >= 500).map(([p, s]) => `${p}=${s}`);

      return {
        id: "reg-02", name: "Endpoint Availability Check", category: "regression",
        status: broken.length === 0 && serverErrors.length === 0 ? "pass" : "fail",
        duration: 0,
        message: `${available}/${eps.length} endpoints available. Broken: ${broken.join(", ") || "none"}. 5xx: ${serverErrors.join(", ") || "none"}`,
        evidence: { results, total: eps.length, available, broken, serverErrors },
        suggestion: broken.length > 0 ? "Check route registration" : serverErrors.length > 0 ? "Fix server errors on failed endpoints" : undefined,
      };
    },
  },
  {
    id: "reg-03",
    category: "regression",
    name: "Response Structure Versioning",
    description: "Checks that critical response fields haven't changed structure across deployments.",
    tags: ["regression", "schema"],
    run: async (ctx) => {
      const schemaChecks: [string, string[]][] = [
        ["/analytics/dashboard", ["total_findings", "total_scans", "severity_breakdown", "risk_trend", "mttr_days"]],
        ["/scans?page_size=1", ["items", "pagination"]],
        ["/system", ["status", "uptime", "version"]],
      ];

      const results: Record<string, { present: string[]; missing: string[] }> = {};
      for (const [ep, required] of schemaChecks) {
        const res = await api(ctx, ep);
        const body = res ? await res.json().catch(() => ({})) : {};
        const present = required.filter(f => f in (body as Record<string, unknown>));
        const missing = required.filter(f => !(f in (body as Record<string, unknown>)));
        results[ep] = { present, missing };
      }

      const allOk = Object.values(results).every(r => r.missing.length === 0);
      const issues = Object.entries(results).filter(([, r]) => r.missing.length > 0)
        .map(([ep, r]) => `${ep} missing: ${r.missing.join(", ")}`).join("; ");

      return {
        id: "reg-03", name: "Response Structure Versioning", category: "regression",
        status: allOk ? "pass" : "fail",
        duration: 0,
        message: allOk ? "All response schemas match expected structure" : `Schema regressions: ${issues}`,
        evidence: results,
        suggestion: !allOk ? "Restore missing fields in response schemas" : undefined,
      };
    },
  },
];

export const regressionSuite: TestSuite = {
  id: "regression",
  category: "regression",
  label: "Regression Testing",
  description: "Captures API snapshots, compares with previous runs to detect regressions, checks endpoint availability, and validates response schemas across deployments.",
  icon: "GitCompare",
  tests: regressionTests,
};
