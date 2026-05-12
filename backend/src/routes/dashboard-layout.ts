import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

const DEFAULT_LAYOUT = {
  widgets: [
    { id: "stats", type: "stats", x: 0, y: 0, w: 4, h: 1, enabled: true },
    { id: "severity-pie", type: "severity-pie", x: 0, y: 1, w: 2, h: 2, enabled: true },
    { id: "risk-trend", type: "risk-trend", x: 2, y: 1, w: 2, h: 2, enabled: true },
    { id: "top-targets", type: "top-targets", x: 0, y: 3, w: 2, h: 2, enabled: true },
    { id: "recent-activity", type: "activity-feed", x: 2, y: 3, w: 2, h: 2, enabled: true },
    { id: "sla-status", type: "sla-status", x: 0, y: 5, w: 2, h: 1, enabled: true },
    { id: "scan-velocity", type: "scan-velocity", x: 2, y: 5, w: 2, h: 1, enabled: true },
  ],
};

// GET /dashboard/layout — Get user's dashboard layout
router.get("/dashboard/layout", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string } }).session;
    const userId = session.userId ?? "anonymous";
    const doc = await col("dashboard_layouts").findOne({ user_id: userId } as Record<string, unknown>) as Record<string, unknown> | null;
    res.json(doc?.["layout"] ?? DEFAULT_LAYOUT);
  } catch (err) {
    logger.error({ err }, "Get layout error");
    res.json(DEFAULT_LAYOUT);
  }
});

// PUT /dashboard/layout — Save user's dashboard layout
router.put("/dashboard/layout", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string } }).session;
    const userId = session.userId ?? "anonymous";
    const layout = req.body;
    await col("dashboard_layouts").updateOne(
      { user_id: userId } as Record<string, unknown>,
      { $set: { layout, updated_at: new Date() }, $setOnInsert: { created_at: new Date() } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Save layout error");
    res.status(500).json({ error: "Failed to save layout" });
  }
});

export default router;
