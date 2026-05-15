import { Router } from "express";
import { col } from "../lib/db";
import { getRedis } from "../lib/redis";

const router = Router();

router.get("/status", async (_req, res) => {
  const checks: Record<string, { status: string; latency_ms?: number; error?: string; active_scans?: number }> = {};
  const start = Date.now();

  try {
    const t = Date.now();
    await col("users").countDocuments({});
    checks["mongodb"] = { status: "healthy", latency_ms: Date.now() - t };
  } catch (err) {
    checks["mongodb"] = { status: "degraded", error: String((err as Error).message).slice(0, 100) };
  }

  try {
    const t = Date.now();
    const redis = getRedis();
    await redis.ping();
    checks["redis"] = { status: "healthy", latency_ms: Date.now() - t };
  } catch {
    checks["redis"] = { status: "degraded", error: "Redis unavailable" };
  }

  try {
    const running = await col("scan_jobs").countDocuments({ status: "running" } as Record<string, unknown>);
    checks["scanner"] = { status: "healthy", latency_ms: 0, active_scans: running };
  } catch {
    checks["scanner"] = { status: "unknown" };
  }

  const allHealthy = Object.values(checks).every(c => c.status === "healthy");
  const anyDegraded = Object.values(checks).some(c => c.status === "degraded");

  res.json({
    status: allHealthy ? "operational" : anyDegraded ? "degraded" : "partial_outage",
    version: process.env["APP_VERSION"] ?? "1.0.0",
    uptime_seconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    components: checks,
    total_latency_ms: Date.now() - start,
  });
});

router.get("/status/incidents", async (_req, res) => {
  try {
    const incidents = await col("incidents").find({}).sort({ created_at: -1 }).limit(10).toArray() as Array<Record<string, unknown>>;
    res.json(incidents.map(i => ({ id: String(i["_id"]), title: i["title"], severity: i["severity"], status: i["status"], created_at: i["created_at"], resolved_at: i["resolved_at"] ?? null })));
  } catch {
    res.json([]);
  }
});

export default router;
