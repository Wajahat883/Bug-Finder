import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { scanEvents } from "../services/scanner/index";
import { ScannerEvent } from "../services/scanner/types";
import { requireAuth } from "../middlewares/rbac";
import { errorResponse } from "../lib/response";

const router = Router();

// ── SSE connection rate limiter (max 5 concurrent per user, tracked in memory) ─
// In production, use Redis with ioredis for cross-instance tracking.
const sseConnections = new Map<string, number>();
const MAX_SSE_PER_USER = 5;

// Both paths serve SSE streams — frontend uses /api/stream/:id
router.get(["/stream/:id", "/scan-jobs/:id/stream"], requireAuth, async (req, res) => {
  const session = (req as unknown as { session: { userId?: string } }).session;
  const userId = session?.userId ?? "anon";
  const current = sseConnections.get(userId) ?? 0;
  if (current >= MAX_SSE_PER_USER) {
    return errorResponse(res, 429, "Too Many Connections", `Max ${MAX_SSE_PER_USER} concurrent SSE streams per user`);
  }
  sseConnections.set(userId, current + 1);
  const { id } = req.params;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  const send = (event: string, data: unknown) => {
    try {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    } catch {
      // client disconnected
    }
  };

  // Send keep-alive heartbeat
  const heartbeat = setInterval(() => {
    try {
      res.write(": heartbeat\n\n");
    } catch {
      clearInterval(heartbeat);
    }
  }, 15000);

  // Check if scan already completed
  try {
    if (ObjectId.isValid(id)) {
      const job = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
      if (job) {
        if (job["status"] === "completed") {
          send("progress", { progress: 100, status: "completed" });
          send("complete", { progress: 100, status: "completed", findings_count: job["findings_count"] ?? 0 });
          clearInterval(heartbeat);
          res.end();
          return;
        }
        if (job["status"] === "failed") {
          send("error", { message: job["error_message"] ?? "Scan failed" });
          clearInterval(heartbeat);
          res.end();
          return;
        }
      }
    }
  } catch (err) {
    logger.error({ err }, "Stream initial status check error");
  }

  // Listen to real scanner events
  const eventName = `scan:${id}`;

  const handler = (event: ScannerEvent) => {
    switch (event.type) {
      case "log":
        send("log", { message: event.message, timestamp: new Date().toISOString() });
        break;
      case "engine_start":
        send("engine", { engine: event.engine, status: "scanning", message: event.message });
        break;
      case "engine_done":
        send("engine", { engine: event.engine, status: "done", message: event.message });
        break;
      case "finding":
        if (event.finding) {
          send("finding", {
            title: event.finding.title,
            severity: event.finding.severity,
            category: event.finding.category,
            endpoint: event.finding.endpoint,
            scanner_name: event.finding.scanner_name,
            timestamp: new Date().toISOString(),
          });
        }
        break;
      case "progress":
        send("progress", { progress: event.progress, status: "running" });
        break;
      case "complete":
        send("progress", { progress: 100, status: "completed" });
        send("complete", { progress: 100, status: "completed", message: event.message });
        cleanup();
        break;
      case "error":
        send("error", { message: event.message });
        cleanup();
        break;
    }
  };

  const cleanup = () => {
    clearInterval(heartbeat);
    scanEvents.off(eventName, handler);
    // Decrement SSE connection counter
    const cnt = sseConnections.get(userId) ?? 1;
    if (cnt <= 1) sseConnections.delete(userId);
    else sseConnections.set(userId, cnt - 1);
    try { res.end(); } catch { /* ignore */ }
  };

  scanEvents.on(eventName, handler);

  req.on("close", () => {
    cleanup();
  });
});

router.post("/scan-jobs/:id/start-simulation", requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Scan job not found" });
    const job = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!job) return res.status(404).json({ error: "Scan job not found" });

    res.json({ ok: true, message: "Scan queued" });

    const { enqueueScan } = await import("../services/queue/manager");
    await enqueueScan({
      jobId: id,
      targetUrl: String(job["target_url"] ?? ""),
      profile: (job["scan_profile"] as "quick" | "standard" | "deep") ?? "standard",
      validationEnabled: Boolean(job["validation_enabled"]),
      fuzzingEnabled: Boolean(job["fuzzing_enabled"]),
      bugBountyMode: Boolean(job["bug_bounty_mode"]),
    });
  } catch (err) {
    logger.error({ err }, "Start scan error");
  }
});

export default router;
