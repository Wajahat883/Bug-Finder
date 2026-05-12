import { Router } from "express";
import { requireRole } from "../middlewares/rbac";
import { logger } from "../lib/logger";

const router = Router();

// POST /admin/demo-seed — seed demo data (admin only)
router.post("/admin/demo-seed", requireRole("admin"), async (_req, res) => {
  try {
    const { seedDemoData } = await import("../lib/seed");
    await seedDemoData();
    res.json({ ok: true, message: "Demo data seeded successfully" });
  } catch (err) {
    logger.error({ err }, "Admin demo seed error");
    res.status(500).json({ error: "Failed to seed demo data" });
  }
});

// GET /admin/queue-stats — queue health (admin only)
router.get("/admin/queue-stats", requireRole("admin"), async (_req, res) => {
  try {
    const { getQueueStats } = await import("../services/queue/manager");
    const stats = await getQueueStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
