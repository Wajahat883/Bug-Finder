import { Router, type IRouter } from "express";
import { col } from "../lib/db";

const router: IRouter = Router();
const startTime = Date.now();

router.get("/healthz", async (_req, res) => {
  const uptimeMs = Date.now() - startTime;
  let dbStatus = "healthy";
  let zapStatus = "unknown";

  try {
    await col("settings").findOne({});
  } catch {
    dbStatus = "unhealthy";
  }

  try {
    const zapUrl = process.env["ZAP_URL"] ?? "http://zap:8080";
    const resp = await fetch(`${zapUrl}/JSON/core/view/version/`, { signal: AbortSignal.timeout(3000) });
    zapStatus = resp.ok ? "healthy" : "unhealthy";
  } catch {
    zapStatus = "unavailable";
  }

  const allHealthy = dbStatus === "healthy";
  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? "healthy" : "degraded",
    uptime: Math.floor(uptimeMs / 1000),
    timestamp: new Date().toISOString(),
    components: {
      database: dbStatus,
      zap: zapStatus,
      api: "healthy",
    },
  });
});

export default router;
