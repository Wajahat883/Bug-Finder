import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

// SLA deadlines by severity (business days)
const SLA_DAYS: Record<string, number> = {
  critical: 1,
  high: 7,
  medium: 30,
  low: 90,
  info: 365,
};

function addBusinessDays(date: Date, days: number): Date {
  const result = new Date(date);
  let added = 0;
  while (added < days) {
    result.setDate(result.getDate() + 1);
    const dow = result.getDay();
    if (dow !== 0 && dow !== 6) added++;
  }
  return result;
}

function getSlaStatus(dueDate: Date, resolvedAt?: Date | null): "on_track" | "at_risk" | "breached" | "resolved" {
  if (resolvedAt) return "resolved";
  const now = new Date();
  const msLeft = dueDate.getTime() - now.getTime();
  if (msLeft < 0) return "breached";
  const daysLeft = msLeft / (1000 * 60 * 60 * 24);
  if (daysLeft < 2) return "at_risk";
  return "on_track";
}

// GET /sla/summary — SLA summary across all findings
router.get("/sla/summary", async (req, res) => {
  try {
    const scanId = req.query["scan_id"] as string | undefined;
    const query: Record<string, unknown> = {};
    if (scanId && ObjectId.isValid(scanId)) {
      query["scan_job_id"] = new ObjectId(scanId);
    }

    const findings = await col("findings").find(query).toArray() as Array<Record<string, unknown>>;

    let on_track = 0, at_risk = 0, breached = 0, resolved = 0;
    const breakdown: Array<{
      id: string; title: string; severity: string; endpoint: string;
      sla_due: string; sla_status: string; days_remaining: number;
    }> = [];

    for (const f of findings) {
      const severity = String(f["severity"] ?? "info");
      const createdAt = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string ?? Date.now());
      const dueDate = addBusinessDays(createdAt, SLA_DAYS[severity] ?? 90);
      const resolvedAt = f["resolved_at"] ? new Date(f["resolved_at"] as string) : null;
      const status = getSlaStatus(dueDate, resolvedAt);

      if (status === "on_track") on_track++;
      else if (status === "at_risk") at_risk++;
      else if (status === "breached") breached++;
      else resolved++;

      const daysRemaining = resolvedAt ? 0 : Math.round((dueDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

      breakdown.push({
        id: String(f["_id"]),
        title: String(f["title"] ?? ""),
        severity,
        endpoint: String(f["endpoint"] ?? ""),
        sla_due: dueDate.toISOString(),
        sla_status: status,
        days_remaining: daysRemaining,
      });
    }

    res.json({
      total: findings.length,
      on_track,
      at_risk,
      breached,
      resolved,
      compliance_rate: findings.length > 0 ? Math.round(((on_track + resolved) / findings.length) * 100) : 100,
      findings: breakdown.sort((a, b) => a.days_remaining - b.days_remaining).slice(0, 50),
    });
  } catch (err) {
    logger.error({ err }, "SLA summary error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /sla/finding/:id — SLA info for a specific finding
router.get("/sla/finding/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const f = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) return res.status(404).json({ error: "Finding not found" });

    const severity = String(f["severity"] ?? "info");
    const createdAt = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string ?? Date.now());
    const dueDate = addBusinessDays(createdAt, SLA_DAYS[severity] ?? 90);
    const resolvedAt = f["resolved_at"] ? new Date(f["resolved_at"] as string) : null;
    const status = getSlaStatus(dueDate, resolvedAt);
    const daysAllowed = SLA_DAYS[severity] ?? 90;

    res.json({
      finding_id: id,
      severity,
      sla_days_allowed: daysAllowed,
      sla_due: dueDate.toISOString(),
      sla_status: status,
      days_remaining: Math.round((dueDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)),
      policy: `${severity.charAt(0).toUpperCase() + severity.slice(1)} findings must be remediated within ${daysAllowed} business days`,
    });
  } catch (err) {
    logger.error({ err }, "SLA finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /sla/finding/:id/resolve — Mark a finding as resolved
router.post("/sla/finding/:id/resolve", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    await col("findings").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { resolved_at: new Date(), resolution_note: req.body?.note ?? "" } }
    );

    res.json({ success: true, resolved_at: new Date().toISOString() });
  } catch (err) {
    logger.error({ err }, "SLA resolve finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
