import crypto from "crypto";
import { EventEmitter } from "events";
import { logger } from "../../lib/logger";
import { col } from "../../lib/db";
import {
  TestSuite, TestCase, TestResult, TestRun, TestContext,
} from "./types";

export const testEvents = new EventEmitter();
testEvents.setMaxListeners(50);

const storedRuns: Map<string, TestRun> = new Map();
const MAX_STORED_RUNS = 20;

export function getCollectedData(ctx: TestContext, key: string): unknown {
  return ctx.runtime.collectedData.get(key);
}

export function setCollectedData(ctx: TestContext, key: string, value: unknown): void {
  ctx.runtime.collectedData.set(key, value);
}

function summarize(results: TestResult[]): TestRun["summary"] {
  const summary = { total: 0, pass: 0, fail: 0, warn: 0, error: 0, skipped: 0, duration: 0 };
  for (const r of results) {
    summary.total++;
    if (r.status === "pass") summary.pass++;
    else if (r.status === "fail") summary.fail++;
    else if (r.status === "warn") summary.warn++;
    else if (r.status === "error") summary.error++;
    else summary.skipped++;
    summary.duration += r.duration;
  }
  return summary;
}

async function executeTest(test: TestCase, ctx: TestContext): Promise<TestResult> {
  const t0 = Date.now();
  try {
    const timeout = test.timeout ?? 15000;
    const result = await Promise.race([
      test.run(ctx),
      new Promise<TestResult>((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout: ${timeout}ms`)), timeout)
      ),
    ]);
    return { ...result, id: test.id, name: test.name, category: test.category, duration: Date.now() - t0 };
  } catch (err) {
    return {
      id: test.id,
      name: test.name,
      category: test.category,
      status: "error",
      duration: Date.now() - t0,
      message: err instanceof Error ? err.message : "Test execution error",
      evidence: { error: String(err) },
      suggestion: "Check test configuration and connectivity",
    } as TestResult;
  }
}

export async function runTestSuites(
  suites: TestSuite[],
  options?: { baseUrl?: string; session?: TestContext["session"] }
): Promise<TestRun> {
  const runId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  const ctx: TestContext = {
    baseUrl: options?.baseUrl ?? "http://localhost:5000",
    apiBase: `${options?.baseUrl ?? "http://localhost:5000"}/api`,
    session: options?.session,
    runtime: { startTime: Date.now(), collectedData: new Map(), warnings: [] },
  };

  const run: TestRun = {
    id: runId,
    startedAt,
    suites: suites.map(s => s.id),
    results: [],
    summary: { total: 0, pass: 0, fail: 0, warn: 0, error: 0, skipped: 0, duration: 0 },
    status: "running",
  };

  storedRuns.set(runId, run);
  testEvents.emit(`test-run:${runId}`, { type: "start", runId, totalSuites: suites.length });

  for (const suite of suites) {
    testEvents.emit(`test-run:${runId}`, { type: "suite-start", suiteId: suite.id, suiteName: suite.label });
    logger.info({ suite: suite.label }, `Running test suite`);

    for (const test of suite.tests) {
      testEvents.emit(`test-run:${runId}`, { type: "test-start", testId: test.id, testName: test.name });
      const result = await executeTest(test, ctx);
      run.results.push(result);
      testEvents.emit(`test-run:${runId}`, { type: "test-result", result });
      logger.info({ test: test.name, status: result.status, duration: result.duration }, `Test completed`);
    }

    testEvents.emit(`test-run:${runId}`, { type: "suite-end", suiteId: suite.id });
  }

  run.summary = summarize(run.results);
  run.completedAt = new Date().toISOString();
  run.status = run.summary.error > 0 ? "failed" : "completed";

  testEvents.emit(`test-run:${runId}`, { type: "complete", run });

  // Persist to DB
  try {
    await col("test_runs").insertOne({
      run_id: runId,
      started_at: new Date(startedAt),
      completed_at: new Date(),
      suites: run.suites,
      summary: run.summary,
      results: run.results,
      status: run.status,
    });
  } catch (err) {
    logger.warn({ err }, "Failed to persist test run");
  }

  // Cleanup old stored runs
  if (storedRuns.size > MAX_STORED_RUNS) {
    const keys = [...storedRuns.keys()];
    for (let i = 0; i < keys.length - MAX_STORED_RUNS; i++) {
      storedRuns.delete(keys[i]);
    }
  }

  return run;
}

export function getTestRun(runId: string): TestRun | undefined {
  return storedRuns.get(runId);
}

export async function getTestRunHistory(limit = 10): Promise<TestRun[]> {
  try {
    const rows = await col("test_runs")
      .find({})
      .sort({ started_at: -1 })
      .limit(limit)
      .toArray() as Array<Record<string, unknown>>;
    return rows.map(r => ({
      id: String(r["run_id"]),
      startedAt: String(r["started_at"]),
      completedAt: String(r["completed_at"] ?? ""),
      suites: (r["suites"] as string[]) ?? [],
      results: (r["results"] as TestResult[]) ?? [],
      summary: r["summary"] as TestRun["summary"],
      status: String(r["status"] ?? "completed") as TestRun["status"],
    }));
  } catch {
    return [...storedRuns.values()].slice(-limit);
  }
}
