import { Router } from "express";
import { col } from "../lib/db";
import { getQueueStats } from "../services/queue/manager";

const router = Router();
const startTime = Date.now();

router.get("/healthz", async (_req, res) => {
  const uptimeMs = Date.now() - startTime;
  let dbStatus = "healthy";
  let redisStatus: string = "unavailable";
  let zapStatus: string = "unknown";
  let playwrightStatus: string = "unavailable";
  const queueStats = getQueueStats();

  try { await col("settings").findOne({}); } catch { dbStatus = "unhealthy"; }

  try { const resp = await fetch((process.env["ZAP_URL"] ?? "http://zap:8080") + "/JSON/core/view/version/", { signal: AbortSignal.timeout(3000) }); zapStatus = resp.ok ? "healthy" : "unhealthy"; } catch { zapStatus = "unavailable"; }

  try { const resp = await fetch((process.env["PLAYWRIGHT_URL"] ?? "http://localhost:3005") + "/health", { signal: AbortSignal.timeout(3000) }); playwrightStatus = resp.ok ? "healthy" : "unavailable"; } catch { playwrightStatus = "unavailable"; }

  try { const r = await fetch((process.env["REDIS_URL"] ?? "redis://localhost:6379").replace("redis://", "http://").split(":")[0] + ":9121/health", { signal: AbortSignal.timeout(2000) }); redisStatus = r.ok ? "healthy" : "unavailable"; } catch { redisStatus = "unavailable"; }

  const mem = process.memoryUsage();
  const memMB = Math.round(mem.heapUsed / 1024 / 1024);
  const memTotal = Math.round(mem.heapTotal / 1024 / 1024);

  const [activeScans, totalScans, totalFindings, totalTargets] = await Promise.all([
    col("scan_jobs").countDocuments({ status: "running" }),
    col("scan_jobs").countDocuments(),
    col("findings").countDocuments(),
    col("targets").countDocuments(),
  ]);

  const components = { database: dbStatus, redis: redisStatus, zap: zapStatus, playwright: playwrightStatus, api: "healthy" };
  const allHealthy = dbStatus === "healthy";

  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? "healthy" : "degraded",
    uptime_seconds: Math.floor(uptimeMs / 1000),
    uptime_display: `${Math.floor(uptimeMs / 3600000)}h ${Math.floor((uptimeMs % 3600000) / 60000)}m`,
    timestamp: new Date().toISOString(),
    memory: { used_mb: memMB, total_mb: memTotal, usage_pct: Math.round((memMB / memTotal) * 100) },
    components,
    queue: queueStats,
    stats: { active_scans: activeScans, total_scans: totalScans, total_findings: totalFindings, total_targets: totalTargets },
  });
});

export default router;
