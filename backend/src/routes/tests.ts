import { Router } from "express";
import { logger } from "../lib/logger";
import { requireAuth, requireAdmin } from "../middlewares/rbac";
import {
  ALL_SUITES, getSuite, runTestSuites, getTestRun, getTestRunHistory,
} from "../services/tester";

const router = Router();
router.use(requireAuth);

// GET /tests/suites — List all available test suites with metadata
router.get("/tests/suites", (_req, res) => {
  try {
    res.json(ALL_SUITES.map(s => ({
      id: s.id,
      category: s.category,
      label: s.label,
      description: s.description,
      icon: s.icon,
      testCount: s.tests.length,
      tests: s.tests.map(t => ({ id: t.id, name: t.name, description: t.description, tags: t.tags })),
    })));
  } catch (err) {
    logger.error({ err }, "List test suites error");
    res.status(500).json({ error: "Failed to list test suites" });
  }
});

// GET /tests/suites/:id — Get single suite with all tests
router.get("/tests/suites/:id", (req, res) => {
  try {
    const suite = getSuite(req.params.id);
    if (!suite) return res.status(404).json({ error: "Suite not found" });
    res.json({
      id: suite.id,
      category: suite.category,
      label: suite.label,
      description: suite.description,
      icon: suite.icon,
      testCount: suite.tests.length,
      tests: suite.tests.map(t => ({
        id: t.id, name: t.name, description: t.description, tags: t.tags, timeout: t.timeout,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to retrieve suite" });
  }
});

// POST /tests/run — Run specified test suites
router.post("/tests/run", async (req, res) => {
  try {
    const { suiteIds, baseUrl } = req.body as { suiteIds?: string[]; baseUrl?: string };

    const suites = (suiteIds?.length
      ? suiteIds.map(id => getSuite(id)).filter(Boolean)
      : ALL_SUITES) as typeof ALL_SUITES;

    if (!suites.length) return res.status(400).json({ error: "No valid suites to run" });

    const session = (req as unknown as { session: { userId?: string; username?: string; role?: string } }).session;
    const run = await runTestSuites(suites, {
      baseUrl: baseUrl ?? `http://localhost:${process.env["PORT"] ?? 5000}`,
      session: session.userId ? { userId: session.userId, username: session.username ?? "", role: session.role ?? "" } : undefined,
    });

    res.json({
      runId: run.id,
      status: run.status,
      summary: run.summary,
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      suites: run.suites,
      results: run.results,
    });
  } catch (err) {
    logger.error({ err }, "Run tests error");
    res.status(500).json({ error: "Test execution failed" });
  }
});

// GET /tests/runs/:id — Get a specific test run result
router.get("/tests/runs/:id", (req, res) => {
  const run = getTestRun(req.params.id);
  if (!run) return res.status(404).json({ error: "Test run not found" });
  res.json(run);
});

// GET /tests/runs — Get test run history
router.get("/tests/runs", async (req, res) => {
  try {
    const limit = parseInt(String(req.query["limit"] ?? "10"));
    const history = await getTestRunHistory(limit);
    res.json(history.map(r => ({
      id: r.id,
      startedAt: r.startedAt,
      completedAt: r.completedAt,
      status: r.status,
      summary: r.summary,
      suites: r.suites,
    })));
  } catch (err) {
    res.status(500).json({ error: "Failed to load test history" });
  }
});

// GET /tests/runs/:id/stream — SSE stream for real-time test progress
router.get("/tests/runs/:id/stream", (req, res) => {
  const { id } = req.params;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = (event: string, data: unknown) => {
    try { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); } catch { /* client disconnected */ }
  };

  const heartbeat = setInterval(() => {
    try { res.write(": heartbeat\n\n"); } catch { clearInterval(heartbeat); }
  }, 15000);

  const { testEvents } = require("../services/tester");

  const handler = (event: Record<string, unknown>) => {
    send("test-event", event);
    if (event.type === "complete" || event.type === "error") {
      cleanup();
    }
  };

  const cleanup = () => {
    clearInterval(heartbeat);
    testEvents.off(`test-run:${id}`, handler);
    try { res.end(); } catch { /* ignore */ }
  };

  testEvents.on(`test-run:${id}`, handler);
  req.on("close", cleanup);

  const existing = getTestRun(id);
  if (existing && existing.status !== "running") {
    send("complete", existing);
    cleanup();
  }
});

export default router;
