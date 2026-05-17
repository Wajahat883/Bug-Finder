import { Router } from "express";
import { requireRole, requireApiKeyScope } from "../middlewares/rbac";
import { logger } from "../lib/logger";
import { col } from "../lib/db";

const router = Router();
const requireAdmin = requireRole("admin");

// POST /admin/demo-seed — seed demo data (admin only)
router.post("/admin/demo-seed", requireRole("admin"), requireApiKeyScope("admin"), async (_req, res) => {
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
router.get("/admin/queue-stats", requireRole("admin"), requireApiKeyScope("admin"), async (_req, res) => {
  try {
    const { getQueueStats } = await import("../services/queue/manager");
    const stats = await getQueueStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/admin/rate-limit-events", requireAdmin, requireApiKeyScope("admin"), async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query["limit"] ?? "100")), 500);
    const events = await col("rate_limit_events").find({} as Record<string, unknown>).sort({ window_start: -1 }).limit(limit).toArray() as Array<Record<string, unknown>>;
    res.json(events.map(e => ({ ip: e["ip"], endpoint: e["endpoint"], count: e["count"], window_start: e["window_start"], blocked: e["blocked"] ?? false })));
  } catch { res.status(500).json({ error: "Internal server error" }); }
});

router.post("/admin/block-ip", requireAdmin, requireApiKeyScope("admin"), async (req, res) => {
  const { ip } = req.body as { ip: string };
  if (!ip) return res.status(400).json({ error: "ip required" });
  await col("blocked_ips").updateOne({ ip } as Record<string, unknown>, { $set: { ip, blocked_at: new Date() } }, { upsert: true });
  res.json({ ok: true });
});

router.post("/admin/whitelist-ip", requireAdmin, requireApiKeyScope("admin"), async (req, res) => {
  const { ip } = req.body as { ip: string };
  if (!ip) return res.status(400).json({ error: "ip required" });
  await col("ip_allowlist").updateOne({ ip } as Record<string, unknown>, { $set: { ip, added_at: new Date() } }, { upsert: true });
  res.json({ ok: true });
});

export default router;
