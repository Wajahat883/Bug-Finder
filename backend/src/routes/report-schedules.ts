import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

router.get("/report-schedules", requireAuth, async (_req, res) => {
  try {
    const schedules = await col("report_schedules").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(schedules.map((s) => ({ ...s, id: String(s["_id"]) })));
  } catch (err) {
    logger.error({ err }, "List report schedules error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/report-schedules", requireAuth, async (req, res) => {
  try {
    const { name, recipients, cron_expression, target_url } = req.body as {
      name?: string; recipients?: string[]; cron_expression?: string; target_url?: string;
    };

    if (!name || !recipients?.length || !cron_expression) {
      return res.status(400).json({ error: "name, recipients[], and cron_expression are required" });
    }

    const { scheduleReport } = await import("../services/scheduler");
    const insert = await col("report_schedules").insertOne({
      name, recipients, cron_expression,
      target_url: target_url ?? null,
      enabled: true,
      created_at: new Date(),
      last_sent: null,
    });

    const saved = await col("report_schedules").findOne({ _id: insert.insertedId }) as Record<string, unknown>;
    scheduleReport(saved as any);
    res.status(201).json({ ...saved, id: String(saved["_id"]) });
  } catch (err) {
    logger.error({ err }, "Create report schedule error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/report-schedules/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { enabled } = req.body as { enabled?: boolean };

    await col("report_schedules").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { enabled, updated_at: new Date() } }
    );

    if (enabled === false) {
      const { unscheduleReport } = await import("../services/scheduler");
      unscheduleReport(id);
    } else if (enabled === true) {
      const schedule = await col("report_schedules").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
      if (schedule) {
        const { scheduleReport } = await import("../services/scheduler");
        scheduleReport(schedule as any);
      }
    }

    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Patch report schedule error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/report-schedules/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { unscheduleReport } = await import("../services/scheduler");
    unscheduleReport(id);
    await col("report_schedules").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete report schedule error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// Send a test/manual report immediately
router.post("/report-schedules/:id/send-now", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const schedule = await col("report_schedules").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!schedule) return res.status(404).json({ error: "Schedule not found" });

    const { sendReportEmail } = await import("../services/email");
    const { col: getCol } = await import("../lib/db");

    const filter: Record<string, unknown> = schedule["target_url"] ? { target_url: schedule["target_url"] } : {};
    const findings = await getCol("findings").find(filter).toArray() as Array<Record<string, unknown>>;
    const remediations = await getCol("remediations").find(filter).toArray() as Array<Record<string, unknown>>;
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const ok = await sendReportEmail(schedule["recipients"] as string[], {
      title: String(schedule["name"]),
      generatedAt: new Date(),
      targetUrl: schedule["target_url"] as string | undefined,
      totalFindings: findings.length,
      critical: findings.filter((f) => f["severity"] === "critical").length,
      high: findings.filter((f) => f["severity"] === "high").length,
      medium: findings.filter((f) => f["severity"] === "medium").length,
      low: findings.filter((f) => f["severity"] === "low").length,
      topFindings: findings
        .sort((a, b) => ["critical","high","medium","low","info"].indexOf(String(a["severity"])) - ["critical","high","medium","low","info"].indexOf(String(b["severity"])))
        .slice(0, 10)
        .map((f) => ({ title: String(f["title"] ?? ""), severity: String(f["severity"] ?? "medium"), endpoint: String(f["endpoint"] ?? "") })),
      openRemediations: remediations.filter((r) => r["status"] !== "resolved").length,
      resolvedLastPeriod: remediations.filter((r) => r["status"] === "resolved" && new Date(r["updated_at"] as string) > sevenDaysAgo).length,
    });

    if (ok) {
      await col("report_schedules").updateOne(
        { _id: new ObjectId(id) } as Record<string, unknown>,
        { $set: { last_sent: new Date() } }
      );
    }

    res.json({ ok, message: ok ? "Report sent" : "SMTP not configured" });
  } catch (err) {
    logger.error({ err }, "Send now report error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
