import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

router.get("/dashboard/stats", async (req, res) => {
  try {
    const scanJobsCol = col("scan_jobs");
    const findingsCol = col("findings");
    const targetsCol = col("targets");

    const allJobs = (await scanJobsCol.find().toArray()) as Array<Record<string, unknown>>;
    const allFindings = (await findingsCol.find().toArray()) as Array<Record<string, unknown>>;
    const totalTargets = await targetsCol.countDocuments();

    const statusCounts = allJobs.reduce<Record<string, number>>((acc, j) => {
      const s = j["status"] as string;
      acc[s] = (acc[s] ?? 0) + 1;
      return acc;
    }, {});

    const sevCounts = allFindings.reduce<Record<string, number>>((acc, f) => {
      const s = f["severity"] as string;
      acc[s] = (acc[s] ?? 0) + 1;
      return acc;
    }, {});

    const totalCrit = sevCounts["critical"] ?? 0;
    const totalHigh = sevCounts["high"] ?? 0;
    const totalMed = sevCounts["medium"] ?? 0;
    const totalLow = sevCounts["low"] ?? 0;
    const totalInfo = sevCounts["info"] ?? 0;

    const riskScore = Math.min(100, totalCrit * 20 + totalHigh * 10 + totalMed * 4);

    // Scans over time (last 14 days)
    const today = new Date();
    const scansOverTime = Array.from({ length: 14 }, (_, i) => {
      const d = new Date(today);
      d.setDate(d.getDate() - (13 - i));
      const dateStr = d.toISOString().split("T")[0]!;
      const dayScans = allJobs.filter((j) => {
        const jDate = (j["created_at"] as Date | undefined)?.toISOString?.()?.split("T")[0];
        return jDate === dateStr;
      }).length;
      const dayFindings = allFindings.filter((f) => {
        const fDate = (f["created_at"] as Date | undefined)?.toISOString?.()?.split("T")[0];
        return fDate === dateStr;
      }).length;
      return { date: dateStr, scans: dayScans, findings: dayFindings };
    });

    res.json({
      total_scans: allJobs.length,
      active_scans: statusCounts["running"] ?? 0,
      completed_scans: statusCounts["completed"] ?? 0,
      failed_scans: statusCounts["failed"] ?? 0,
      total_findings: allFindings.length,
      critical_findings: totalCrit,
      high_findings: totalHigh,
      medium_findings: totalMed,
      low_findings: totalLow,
      info_findings: totalInfo,
      total_targets: totalTargets,
      risk_score: riskScore,
      findings_by_severity: [
        { severity: "critical", count: totalCrit, color: "#ef4444" },
        { severity: "high", count: totalHigh, color: "#f97316" },
        { severity: "medium", count: totalMed, color: "#eab308" },
        { severity: "low", count: totalLow, color: "#3b82f6" },
        { severity: "info", count: totalInfo, color: "#6b7280" },
      ],
      scans_over_time: scansOverTime,
    });
  } catch (err) {
    logger.error({ err }, "Dashboard stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/dashboard/activity", async (req, res) => {
  try {
    const limit = parseInt(String(req.query["limit"] ?? "20"));
    const activityCol = col("activity_events");
    const events = (await activityCol.find().sort({ timestamp: -1 }).toArray()) as Array<Record<string, unknown>>;

    const result = events.slice(0, limit).map((e) => ({
      id: String(e["_id"]),
      type: e["type"],
      message: e["message"],
      timestamp: e["timestamp"],
      scan_job_id: e["scan_job_id"] ? String(e["scan_job_id"]) : undefined,
      severity: e["severity"] ?? null,
    }));

    res.json(result);
  } catch (err) {
    logger.error({ err }, "Dashboard activity error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
