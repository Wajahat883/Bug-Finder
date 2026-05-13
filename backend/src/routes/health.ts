import { Router } from "express";
import OpenAI from "openai";
import { col } from "../lib/db";
import { getQueueStats } from "../services/queue/manager";


const router = Router();
const startTime = Date.now();

async function checkAiHealth(): Promise<{ status: string; latency_ms: number; model: string }> {
  const model = process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free";
  const apiKey = process.env["OPENCODE_API_KEY"] ?? "";
  if (!apiKey) return { status: "not_configured", latency_ms: 0, model };
  const t0 = Date.now();
  try {
    const client = new OpenAI({
      apiKey,
      baseURL: process.env["OPENCODE_API_BASE"] ?? "https://opencode.ai/zen/v1",
      timeout: 8000,
    });
    await client.chat.completions.create({
      model,
      max_tokens: 5,
      messages: [{ role: "user", content: "ping" }],
      stream: false,
    });
    return { status: "healthy", latency_ms: Date.now() - t0, model };
  } catch {
    return { status: "unhealthy", latency_ms: Date.now() - t0, model };
  }
}

router.get(["/health", "/healthz"], async (_req, res) => {
  const uptimeMs = Date.now() - startTime;
  let dbStatus = "healthy";
  let redisStatus: string = "unavailable";
  let zapStatus: string = "unknown";
  let playwrightStatus: string = "unavailable";
  const queueStats = await getQueueStats();

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

// Dedicated AI health check — tests actual API connectivity and latency
router.get("/healthz/ai", async (_req, res) => {
  const result = await checkAiHealth();
  const statusCode = result.status === "healthy" ? 200 : result.status === "not_configured" ? 200 : 503;
  res.status(statusCode).json({ ...result, timestamp: new Date().toISOString() });
});

export default router;
