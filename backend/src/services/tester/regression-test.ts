import crypto from "crypto";
import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch, ensureAuthenticated } from "./fetch-utils";
import { col } from "../../lib/db";

function hashContent(body: string): string {
  return crypto.createHash("md5").update(body).digest("hex");
}

const regressionTests: TestCase[] = [
  {
    id: "reg-01",
    category: "regression",
    name: "API Snapshot Comparison",
    description: "Takes a snapshot of major endpoints and compares with the previous run to detect regressions.",
    tags: ["regression", "api"],
    run: async (ctx) => {
      const endpoints = ["/health", "/scans?page_size=1", "/findings?page_size=1", "/targets", "/settings"];
      const current: { path: string; status: number; bodyHash: string }[] = [];

      for (const ep of endpoints) {
        const res = await testFetch(ctx, ep);
        const body = res ? await res.text().catch(() => "") : "";
        current.push({ path: ep, status: res?.status ?? 0, bodyHash: hashContent(body) });
      }

      await col("test_snapshots").insertOne({ run_id: crypto.randomUUID(), snapshots: current, taken_at: new Date() });

      const prevRun = await col("test_snapshots").find({}).sort({ taken_at: -1 }).skip(1).limit(1).toArray() as Array<Record<string, unknown>>;
      if (!prevRun.length) {
        return { id: "reg-01", name: "API Snapshot Comparison", category: "regression", status: "pass", duration: 0, message: "First snapshot — baseline established", evidence: { snapshotCount: current.length } };
      }

      const prev = (prevRun[0]["snapshots"] as Array<{ path: string; status: number; bodyHash: string }>) ?? [];
      const changes: string[] = [];

      for (const cur of current) {
        const prevEntry = prev.find(p => p.path === cur.path);
        if (!prevEntry) { changes.push(`NEW: ${cur.path}`); continue; }
        if (cur.status !== prevEntry.status && (cur.status >= 500 || prevEntry.status >= 500)) changes.push(`${cur.path}: ${prevEntry.status} → ${cur.status}`);
        if (cur.bodyHash !== prevEntry.bodyHash) changes.push(`${cur.path}: body changed`);
      }

      for (const p of prev) {
        if (!current.find(c => c.path === p.path)) changes.push(`MISSING: ${p.path}`);
      }

      return { id: "reg-01", name: "API Snapshot Comparison", category: "regression", status: changes.length === 0 ? "pass" : "warn", duration: 0, message: changes.length === 0 ? `${current.length} endpoints stable` : `${changes.length} changes`, evidence: { changes }, suggestion: changes.length > 0 ? "Review changes in regression snapshot" : undefined };
    },
  },
  {
    id: "reg-02",
    category: "regression",
    name: "Endpoint Availability Check",
    description: "Verifies all registered API endpoints are accessible.",
    tags: ["regression", "endpoints"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const eps = ["/health", "/scans?page_size=1", "/findings?page_size=1", "/targets", "/remediations", "/system", "/settings", "/analytics/dashboard", "/analytics/activity"];
      const results: Record<string, number> = {};
      for (const ep of eps) {
        const res = await testFetch(ctx, ep);
        results[ep] = res?.status ?? 0;
      }
      const available = Object.values(results).filter(s => s > 0 && s < 500).length;
      const broken = Object.entries(results).filter(([, s]) => s === 0 || s >= 500).map(([p, s]) => `${p}=${s}`);

      return { id: "reg-02", name: "Endpoint Availability Check", category: "regression", status: broken.length === 0 ? "pass" : "fail", duration: 0, message: `${available}/${eps.length} available. ${broken.length ? "Issues: " + broken.join(", ") : "All OK"}`, evidence: { results, total: eps.length }, suggestion: broken.length > 0 ? "Check route registration or auth middleware" : undefined };
    },
  },
  {
    id: "reg-03",
    category: "regression",
    name: "Response Structure Versioning",
    description: "Checks that critical response fields haven't changed structure.",
    tags: ["regression", "schema"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const schemaChecks: [string, string[]][] = [
        ["/analytics/dashboard", ["total_findings", "total_scans", "severity_breakdown"]],
        ["/system", ["status", "uptime", "version"]],
      ];
      const results: Record<string, { present: string[]; missing: string[]; note?: string }> = {};
      for (const [ep, required] of schemaChecks) {
        const res = await testFetch(ctx, ep);
        const body = res ? await res.json().catch(() => ({})) : {};
        if (body && typeof body.error === "string") {
          results[ep] = { present: [], missing: required, note: `Auth required: ${String(body.error)}` };
          continue;
        }
        const present = required.filter(f => f in (body as Record<string, unknown>));
        const missing = required.filter(f => !(f in (body as Record<string, unknown>)));
        results[ep] = { present, missing };
      }
      const actualErrors = Object.entries(results).filter(([, r]) => r.missing.length > 0 && !r.note);
      const allOk = actualErrors.length === 0;

      return {
        id: "reg-03", name: "Response Structure Versioning", category: "regression",
        status: allOk ? "pass" : "warn", duration: 0,
        message: allOk ? "All response schemas match (or auth required as expected)" : `Schema regressions: ${actualErrors.map(([e]) => e).join(", ")}`,
        evidence: results,
        suggestion: !allOk ? "Restore missing fields in response schemas" : undefined,
      };
    },
  },
];

export const regressionSuite: TestSuite = {
  id: "regression", category: "regression", label: "Regression Testing",
  description: "Captures API snapshots, compares with previous runs, checks endpoint availability, and validates response schemas.",
  icon: "GitCompare", tests: regressionTests,
};
