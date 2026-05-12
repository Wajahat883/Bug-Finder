import { Router } from "express";
import { ObjectId } from "mongodb";
import cron from "node-cron";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { scheduleJob, unscheduleJob } from "../services/scheduler";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

router.use(requireAuth);

// GET /scheduled-scans — List all scheduled scans
router.get("/scheduled-scans", async (_req, res) => {
  try {
    const scans = await col("scheduled_scans").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(scans.map((s) => ({
      id: String(s["_id"]),
      target_url: s["target_url"],
      scan_profile: s["scan_profile"],
      cron_expression: s["cron_expression"],
      cron_description: describeCron(String(s["cron_expression"] ?? "")),
      enabled: s["enabled"],
      last_run: s["last_run"] ?? null,
      validation_enabled: s["validation_enabled"] ?? false,
      fuzzing_enabled: s["fuzzing_enabled"] ?? false,
      bug_bounty_mode: s["bug_bounty_mode"] ?? false,
      created_at: s["created_at"],
    })));
  } catch (err) { logger.error({ err }, "List scheduled scans error"); res.status(500).json({ error: "Failed" }); }
});

// POST /scheduled-scans — Create scheduled scan
router.post("/scheduled-scans", async (req, res) => {
  try {
    const { target_url, scan_profile, cron_expression, validation_enabled, fuzzing_enabled, bug_bounty_mode } = req.body as Record<string, unknown>;
    if (!target_url || !scan_profile || !cron_expression) return res.status(400).json({ error: "target_url, scan_profile, and cron_expression required" });
    if (!cron.validate(String(cron_expression))) return res.status(400).json({ error: "Invalid cron expression. Use: */30 * * * * (every 30 min), 0 */6 * * * (every 6 hours), 0 0 * * * (daily)" });
    const insert = await col("scheduled_scans").insertOne({
      target_url: String(target_url),
      scan_profile: String(scan_profile),
      cron_expression: String(cron_expression),
      enabled: true,
      validation_enabled: !!validation_enabled,
      fuzzing_enabled: !!fuzzing_enabled,
      bug_bounty_mode: !!bug_bounty_mode,
      last_run: null,
      created_at: new Date(),
      updated_at: new Date(),
    });
    const saved = await col("scheduled_scans").findOne({ _id: insert.insertedId }) as Record<string, unknown>;
    scheduleJob(saved as any);
    res.status(201).json({ id: String(insert.insertedId), message: "Scheduled scan created" });
  } catch (err) { logger.error({ err }, "Create scheduled scan error"); res.status(500).json({ error: "Failed" }); }
});

// PATCH /scheduled-scans/:id — Toggle enable/disable
router.patch("/scheduled-scans/:id", async (req, res) => {
  try {
    const { enabled } = req.body as { enabled?: boolean };
    await col("scheduled_scans").updateOne({ _id: new ObjectId(req.params.id) } as Record<string, unknown>, { $set: { enabled: !!enabled, updated_at: new Date() } });
    if (enabled) {
      const scan = await col("scheduled_scans").findOne({ _id: new ObjectId(req.params.id) }) as Record<string, unknown>;
      if (scan) scheduleJob(scan as any);
    } else {
      unscheduleJob(req.params.id);
    }
    res.json({ ok: true });
  } catch (err) { logger.error({ err }, "Toggle scheduled scan error"); res.status(500).json({ error: "Failed" }); }
});

// DELETE /scheduled-scans/:id — Remove scheduled scan
router.delete("/scheduled-scans/:id", async (req, res) => {
  try {
    unscheduleJob(req.params.id);
    await col("scheduled_scans").deleteOne({ _id: new ObjectId(req.params.id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) { logger.error({ err }, "Delete scheduled scan error"); res.status(500).json({ error: "Failed" }); }
});

function describeCron(expr: string): string {
  const parts = expr.trim().split(/\s+/);
  if (parts.length < 5) return "Invalid";
  const [min, hour, day, ,] = parts;
  if (hour === "*" && min !== "*") return `Every ${min} minutes`;
  if (day === "*" && hour !== "*") return `Every ${hour} hours`;
  if (hour === "0" && min === "0") return "Daily at midnight";
  if (hour === "9" && min === "0") return "Daily at 9 AM";
  if (hour === "*" && min === "0") return "Every hour";
  if (min === "0" && day === "1") return "Monthly on 1st";
  if (min === "0" && day === "*" && hour === "0") return "Daily at midnight";
  return expr;
}

export default router;
