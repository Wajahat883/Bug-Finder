import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

router.use(requireAuth);

// POST /findings/bulk-update — Bulk update severity or status on multiple findings
router.post("/findings/bulk-update", async (req, res) => {
  try {
    const { ids, action, value } = req.body as { ids?: string[]; action?: string; value?: string };
    if (!ids?.length || !action) return res.status(400).json({ error: "ids array and action required" });

    const validIds = ids.filter((id) => ObjectId.isValid(id)).map((id) => new ObjectId(id));
    if (!validIds.length) return res.status(400).json({ error: "No valid finding IDs" });

    const update: Record<string, unknown> = { updated_at: new Date() };
    if (action === "severity" && value) {
      update["severity"] = value;
    } else if (action === "status" && value) {
      update["validation_status"] = value;
    } else if (action === "resolve") {
      update["resolved_at"] = new Date();
    } else if (action === "suppress") {
      update["validation_status"] = "false_positive";
    } else {
      return res.status(400).json({ error: "Invalid action. Use: severity, status, resolve, suppress" });
    }

    await col("findings").updateMany(
      { _id: { $in: validIds } } as Record<string, unknown>,
      { $set: update }
    );

    res.json({ ok: true, updated: validIds.length, action, value });
  } catch (err) {
    logger.error({ err }, "Bulk update error");
    res.status(500).json({ error: "Bulk update failed" });
  }
});

// GET /analytics/dashboard — Enhanced dashboard with MTTR, trends, SLA compliance
router.get("/analytics/dashboard", async (_req, res) => {
  try {
    const [findings, scans, remediations] = await Promise.all([
      col("findings").find({}).toArray() as Promise<Array<Record<string, unknown>>>,
      col("scan_jobs").find({ status: "completed" }).sort({ completed_at: -1 }).limit(30).toArray() as Promise<Array<Record<string, unknown>>>,
      col("remediations").find({}).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);

    const severities: Record<string, number> = {};
    let resolvedCount = 0;
    const resolvedDurations: number[] = [];

    for (const f of findings) {
      const sev = String(f["severity"] ?? "info");
      severities[sev] = (severities[sev] ?? 0) + 1;
      if (f["resolved_at"]) {
        resolvedCount++;
        const created = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
        const resolved = f["resolved_at"] instanceof Date ? f["resolved_at"] : new Date(f["resolved_at"] as string);
        const days = (resolved.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);
        if (days >= 0) resolvedDurations.push(days);
      }
    }

    const mttr = resolvedDurations.length > 0
      ? Math.round((resolvedDurations.reduce((a, b) => a + b, 0) / resolvedDurations.length) * 10) / 10
      : null;

    const slaCompliant = remediations.filter((r) => r["status"] === "completed" || r["status"] === "in_progress").length;
    const slaTotal = remediations.length;
    const slaCompliance = slaTotal > 0 ? Math.round((slaCompliant / slaTotal) * 100) : 100;

    const riskTrend = scans.slice(0, 10).reverse().map((s) => ({
      date: s["completed_at"] ? new Date(s["completed_at"] as string).toISOString().slice(0, 10) : null,
      risk: s["risk_score"] ?? 0,
      findings: s["findings_count"] ?? 0,
    }));

    const topEndpoints: Record<string, { count: number; maxSeverity: string }> = {};
    for (const f of findings) {
      const ep = String(f["endpoint"] ?? "");
      if (!ep) continue;
      if (!topEndpoints[ep]) topEndpoints[ep] = { count: 0, maxSeverity: "info" };
      topEndpoints[ep].count++;
      const sevOrder = ["critical", "high", "medium", "low", "info"];
      if (sevOrder.indexOf(String(f["severity"])) < sevOrder.indexOf(topEndpoints[ep].maxSeverity)) {
        topEndpoints[ep].maxSeverity = String(f["severity"]);
      }
    }

    const topEndpointsList = Object.entries(topEndpoints)
      .sort(([, a], [, b]) => b.count - a.count)
      .slice(0, 10)
      .map(([ep, data]) => ({ endpoint: ep, ...data }));

    res.json({
      total_findings: findings.length,
      total_scans: scans.length,
      severity_breakdown: severities,
      resolved_count: resolvedCount,
      mttr_days: mttr,
      sla_compliance_pct: slaCompliance,
      risk_trend: riskTrend,
      top_vulnerable_endpoints: topEndpointsList,
    });
  } catch (err) {
    logger.error({ err }, "Analytics dashboard error");
    res.status(500).json({ error: "Analytics failed" });
  }
});

// GET /analytics/activity — Recent activity feed with rich details
router.get("/analytics/activity", async (req, res) => {
  try {
    const limit = parseInt(String(req.query["limit"] ?? "30"));
    const events = await col("activity_events").find({}).sort({ timestamp: -1 }).limit(limit).toArray() as Array<Record<string, unknown>>;
    res.json(events.map((e) => ({
      id: String(e["_id"]),
      type: e["type"],
      message: e["message"],
      timestamp: e["timestamp"],
      severity: e["severity"] ?? null,
      scan_job_id: e["scan_job_id"] ? String(e["scan_job_id"]) : null,
    })));
  } catch (err) {
    logger.error({ err }, "Activity feed error");
    res.status(500).json({ error: "Activity feed failed" });
  }
});

export default router;
