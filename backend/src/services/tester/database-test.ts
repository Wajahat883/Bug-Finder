import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { col, getDb } from "../../lib/db";
import { logger } from "../../lib/logger";

const databaseTests: TestCase[] = [
  {
    id: "db-01",
    category: "database",
    name: "Database Connectivity",
    description: "Verifies that the database connection is established and responsive.",
    tags: ["database", "connectivity"],
    run: async () => {
      try {
        const db = await getDb();
        const admin = await db.admin().ping();
        const ok = admin?.ok === 1;

        return {
          id: "db-01", name: "Database Connectivity", category: "database",
          status: ok ? "pass" : "fail",
          duration: 0,
          message: ok ? "Database ping successful" : "Database ping failed",
          evidence: { pingOk: admin?.ok, dbName: db.databaseName },
          suggestion: !ok ? "Check MONGODB_URI environment variable and network connectivity" : undefined,
        };
      } catch (err) {
        return {
          id: "db-01", name: "Database Connectivity", category: "database",
          status: "error", duration: 0,
          message: `Database connection failed: ${err instanceof Error ? err.message : String(err)}`,
          evidence: { error: String(err) },
          suggestion: "Verify MongoDB is running and MONGODB_URI is set correctly",
        };
      }
    },
    timeout: 10000,
  },
  {
    id: "db-02",
    category: "database",
    name: "Collection Read/Write Integrity",
    description: "Tests that documents can be inserted, read, and deleted atomically on all core collections.",
    tags: ["database", "crud"],
    run: async () => {
      const collections = ["users", "scan_jobs", "findings", "targets", "remediations"];
      const results: Record<string, { insert: boolean; find: boolean; delete: boolean }> = {};

      const { ObjectId } = await import("mongodb");
      for (const name of collections) {
        try {
          const testId = new ObjectId();
          await col(name).insertOne({ _id: testId, _test: true, created_at: new Date() });
          const found = await col(name).findOne({ _id: testId } as Record<string, unknown>);
          await col(name).deleteOne({ _id: testId } as Record<string, unknown>);
          results[name] = { insert: true, find: !!found, delete: true };
        } catch (err) {
          results[name] = { insert: false, find: false, delete: false };
          logger.warn({ err, collection: name }, "CRUD test failed on collection");
        }
      }

      const allOk = Object.values(results).every(r => r.insert && r.find && r.delete);
      const failed = Object.entries(results).filter(([, r]) => !r.insert || !r.find || !r.delete).map(([n]) => n);

      return {
        id: "db-02", name: "Collection Read/Write Integrity", category: "database",
        status: allOk ? "pass" : "fail",
        duration: 0,
        message: allOk ? `All ${collections.length} collections read/write OK` : `Failed: ${failed.join(", ")}`,
        evidence: { results, collections },
        suggestion: !allOk ? "Check collection permissions and indexes" : undefined,
      };
    },
  },
  {
    id: "db-03",
    category: "database",
    name: "Index Verification",
    description: "Verifies that required indexes exist on core collections for query performance.",
    tags: ["database", "indexes"],
    run: async () => {
      const requiredIndexes: Record<string, string[]> = {
        findings: ["scan_job_id", "severity", "target_url", "category"],
        scan_jobs: ["status", "target_url"],
        targets: ["domain"],
        users: ["email"],
        activity_events: ["timestamp"],
      };

      const results: Record<string, { expected: number; found: number; missing: string[] }> = {};
      try {
        for (const [colName, expectedFields] of Object.entries(requiredIndexes)) {
          try {
            const indexes = await col(colName).indexes();
            const indexFields: string[] = [];
            for (const idx of indexes) {
              const keys = (idx as Record<string, unknown>).key as Record<string, number> ?? {};
              indexFields.push(...Object.keys(keys));
            }
            const missing = expectedFields.filter(f => !indexFields.some(i => i === f));
            results[colName] = { expected: expectedFields.length, found: expectedFields.length - missing.length, missing };
          } catch {
            results[colName] = { expected: expectedFields.length, found: 0, missing: expectedFields };
          }
        }
      } catch {
        // In-memory DB won't have indexes — expected
      }

      const allIndexed = Object.values(results).every(r => r.missing.length === 0) || Object.keys(results).length === 0;

      return {
        id: "db-03", name: "Index Verification", category: "database",
        status: allIndexed ? "pass" : "warn",
        duration: 0,
        message: allIndexed ? "All required indexes present" : `Missing indexes: ${Object.entries(results).filter(([, r]) => r.missing.length > 0).map(([n, r]) => `${n}: ${r.missing.join(", ")}`).join("; ")}`,
        evidence: results,
        suggestion: !allIndexed ? "Run ensureIndexes() to create missing indexes" : undefined,
      };
    },
  },
  {
    id: "db-04",
    category: "database",
    name: "Query Performance",
    description: "Measures basic query performance to detect slow collections.",
    tags: ["database", "performance"],
    run: async () => {
      const benchmarks: Record<string, number> = {};
      const queries: [string, () => Promise<unknown>][] = [
        ["findings_count", async () => col("findings").countDocuments()],
        ["scan_jobs_recent", async () => col("scan_jobs").find({}).sort({ created_at: -1 }).limit(5).toArray()],
        ["users_one", async () => col("users").findOne({})],
        ["targets_all", async () => col("targets").find({}).limit(10).toArray()],
      ];

      for (const [name, fn] of queries) {
        try {
          const t0 = Date.now();
          await fn();
          benchmarks[name] = Date.now() - t0;
        } catch {
          benchmarks[name] = -1;
        }
      }

      const avgMs = Object.values(benchmarks).filter(v => v >= 0).reduce((a, b) => a + b, 0) /
        Object.values(benchmarks).filter(v => v >= 0).length;
      const slow = Object.entries(benchmarks).filter(([, ms]) => ms > 500).map(([n, ms]) => `${n}=${ms}ms`);

      return {
        id: "db-04", name: "Query Performance", category: "database",
        status: slow.length === 0 ? "pass" : "warn",
        duration: 0,
        message: `Avg query: ${Math.round(avgMs)}ms. ${slow.length ? `Slow queries: ${slow.join(", ")}` : "All queries fast"}`,
        evidence: { benchmarks, avgMs },
        suggestion: slow.length > 0 ? "Add indexes or optimize slow queries" : undefined,
      };
    },
  },
];

export const databaseSuite: TestSuite = {
  id: "database",
  category: "database",
  label: "Database Testing",
  description: "Validates database connectivity, collection read/write integrity, index coverage, and query performance benchmarks.",
  icon: "Database",
  tests: databaseTests,
};
