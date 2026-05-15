import { Router } from "express";
import OpenAI from "openai";
import { col } from "../lib/db";
import { getQueueStats } from "../services/queue/manager";
import { requireAuth } from "../middlewares/rbac";

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
      timeout: 3000,
    });
    await client.chat.completions.create({
      model, max_tokens: 5,
      messages: [{ role: "user", content: "ping" }],
      stream: false,
    });
    return { status: "healthy", latency_ms: Date.now() - t0, model };
  } catch {
    return { status: "unhealthy", latency_ms: Date.now() - t0, model };
  }
}

// Public liveness probe — safe for load balancers / uptime monitors
router.get(["/health", "/healthz"], async (_req, res) => {
  let dbStatus = "healthy";
  try { await col("settings").findOne({}); } catch { dbStatus = "unhealthy"; }
  const ok = dbStatus === "healthy";
  res.status(ok ? 200 : 503).json({ status: ok ? "ok" : "degraded", timestamp: new Date().toISOString() });
});

// Detailed system health — requires authentication (info-disclosure protection)
router.get(["/health/details", "/healthz/details"], requireAuth, async (_req, res) => {
  const uptimeMs = Date.now() - startTime;
  let dbStatus = "healthy";
  let redisStatus = "unavailable";
  let zapStatus = "unavailable";
  let playwrightStatus = "unavailable";
  const queueStats = await getQueueStats();

  try { await col("settings").findOne({}); } catch { dbStatus = "unhealthy"; }

  try {
    const resp = await fetch((process.env["ZAP_URL"] ?? "http://zap:8080") + "/JSON/core/view/version/", { signal: AbortSignal.timeout(1500) });
    zapStatus = resp.ok ? "healthy" : "unhealthy";
  } catch { zapStatus = "unavailable"; }

  try {
    const resp = await fetch((process.env["PLAYWRIGHT_URL"] ?? "http://localhost:3005") + "/health", { signal: AbortSignal.timeout(1500) });
    playwrightStatus = resp.ok ? "healthy" : "unavailable";
  } catch { playwrightStatus = "unavailable"; }

  try {
    const redisHost = (process.env["REDIS_URL"] ?? "redis://localhost:6379").replace("redis://", "").split(":")[0];
    const resp = await fetch(`http://${redisHost}:9121/health`, { signal: AbortSignal.timeout(1000) });
    redisStatus = resp.ok ? "healthy" : "unavailable";
  } catch { redisStatus = "unavailable"; }

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
    status: allHealthy ? "ok" : "degraded",
    uptime_seconds: Math.floor(uptimeMs / 1000),
    uptime: `${Math.floor(uptimeMs / 3600000)}h ${Math.floor((uptimeMs % 3600000) / 60000)}m`,
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    memory: { used_mb: memMB, total_mb: memTotal, usage_pct: Math.round((memMB / Math.max(memTotal, 1)) * 100) },
    components,
    queue: queueStats,
    stats: { active_scans: activeScans, total_scans: totalScans, total_findings: totalFindings, total_targets: totalTargets },
  });
});

// AI health — requires authentication
router.get("/healthz/ai", requireAuth, async (_req, res) => {
  const result = await checkAiHealth();
  res.status(200).json({ ...result, timestamp: new Date().toISOString() });
});

export default router;
