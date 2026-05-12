import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

router.get("/analytics/risk-trend", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = session?.role !== "admin" ? { user_id: session?.userId ?? null } : {};
    const findings = await col("findings").find(userFilter).sort({ created_at: 1 }).toArray() as Array<Record<string,unknown>>;
    const SEV_WEIGHT: Record<string,number> = { critical: 40, high: 20, medium: 8, low: 2, info: 0 };
    const now = Date.now();
    const weeks: Array<{ week: string; risk_score: number; critical: number; high: number; medium: number; low: number; total: number }> = [];

    for (let i = 11; i >= 0; i--) {
      const cutoff = new Date(now - i * 7 * 24 * 60 * 60 * 1000);
      const subset = findings.filter(f => {
        const d = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
        return d <= cutoff;
      });
      const score = Math.min(100, subset.reduce((acc, f) => acc + (SEV_WEIGHT[String(f["severity"] ?? "info")] ?? 0), 0));
      weeks.push({
        week: `W${12 - i}`,
        risk_score: score,
        critical: subset.filter(f => f["severity"] === "critical").length,
        high: subset.filter(f => f["severity"] === "high").length,
        medium: subset.filter(f => f["severity"] === "medium").length,
        low: subset.filter(f => f["severity"] === "low").length,
        total: subset.length,
      });
    }
    res.json(weeks);
  } catch(err) { logger.error({err},"risk-trend error"); res.status(500).json({ error: "Internal server error" }); }
});

export default router;
