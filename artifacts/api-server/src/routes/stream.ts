import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { scanEvents } from "../services/scanner/index";
import { ScannerEvent } from "../services/scanner/types";

const router = Router();

router.get("/scan-jobs/:id/stream", async (req, res) => {
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
    try { res.end(); } catch { /* ignore */ }
  };

  scanEvents.on(eventName, handler);

  req.on("close", () => {
    cleanup();
  });
});

router.post("/scan-jobs/:id/start-simulation", async (req, res) => {
  const { id } = req.params;
  try {
    const job = await col("scan_jobs").findOne({ _id: id } as never);
    if (!job) return res.status(404).json({ error: "Scan job not found" });
    await col("scan_jobs").updateOne({ _id: id } as never, {
      $set: { status: "running", progress: 0, started_at: new Date() },
    });
    res.json({ ok: true, message: "Scan started" });
  } catch (err) {
    logger.error({ err }, "Start scan error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
