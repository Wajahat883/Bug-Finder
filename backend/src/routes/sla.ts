import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();
router.use(requireAuth);

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

// GET /sla/velocity — avg time-to-fix (days) per severity for resolved findings
router.get("/sla/velocity", async (_req, res) => {
  try {
    const resolved = await col("findings").find({ resolved_at: { $exists: true, $ne: null } }).toArray() as Array<Record<string, unknown>>;
    const SLA_TARGETS: Record<string, number> = { critical: 1, high: 7, medium: 30, low: 90 };
    const groups: Record<string, number[]> = { critical: [], high: [], medium: [], low: [] };
    for (const f of resolved) {
      const sev = String(f["severity"] ?? "");
      if (!groups[sev]) continue;
      const created = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
      const resolvedDate = f["resolved_at"] instanceof Date ? f["resolved_at"] : new Date(f["resolved_at"] as string);
      const days = (resolvedDate.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);
      if (days >= 0) groups[sev].push(days);
    }
    const result = Object.entries(groups).map(([sev, vals]) => ({
      severity: sev,
      avg_days: vals.length > 0 ? Math.round((vals.reduce((a, b) => a + b, 0) / vals.length) * 10) / 10 : null,
      target_days: SLA_TARGETS[sev],
      count: vals.length,
      within_sla: vals.filter(d => d <= SLA_TARGETS[sev]).length,
    }));
    res.json(result);
  } catch (err) {
    logger.error({ err }, "SLA velocity error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /sla/heatmap — breach density per day for last 90 days
router.get("/sla/heatmap", async (_req, res) => {
  try {
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const findings = await col("findings").find({ created_at: { $gte: ninetyDaysAgo } }).toArray() as Array<Record<string, unknown>>;
    const dayMap: Record<string, number> = {};
    const SLA_DAYS2: Record<string, number> = { critical: 1, high: 7, medium: 30, low: 90, info: 365 };
    for (const f of findings) {
      const sev = String(f["severity"] ?? "info");
      const created = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
      const due = new Date(created.getTime() + (SLA_DAYS2[sev] ?? 90) * 24 * 60 * 60 * 1000);
      const resolvedAt = f["resolved_at"] ? (f["resolved_at"] instanceof Date ? f["resolved_at"] : new Date(f["resolved_at"] as string)) : null;
      if (!resolvedAt && due < new Date()) {
        const dayKey = due.toISOString().slice(0, 10);
        dayMap[dayKey] = (dayMap[dayKey] ?? 0) + 1;
      }
    }
    res.json(dayMap);
  } catch (err) {
    logger.error({ err }, "SLA heatmap error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /sla/burn-down — weekly on_track/at_risk/breached/resolved counts for last 6 weeks
router.get("/sla/burn-down", async (_req, res) => {
  try {
    const findings = await col("findings").find({}).toArray() as Array<Record<string, unknown>>;
    const SLA_DAYS3: Record<string, number> = { critical: 1, high: 7, medium: 30, low: 90, info: 365 };
    const weeks = [];
    for (let i = 5; i >= 0; i--) {
      const weekEnd = new Date(Date.now() - i * 7 * 24 * 60 * 60 * 1000);
      let on_track = 0, at_risk = 0, breached = 0, resolved_count = 0;
      for (const f of findings) {
        const created = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
        if (created > weekEnd) continue;
        const sev = String(f["severity"] ?? "info");
        const due = new Date(created.getTime() + (SLA_DAYS3[sev] ?? 90) * 24 * 60 * 60 * 1000);
        const resolvedAt = f["resolved_at"] ? (f["resolved_at"] instanceof Date ? f["resolved_at"] : new Date(f["resolved_at"] as string)) : null;
        if (resolvedAt && resolvedAt <= weekEnd) { resolved_count++; continue; }
        const msLeft = due.getTime() - weekEnd.getTime();
        if (msLeft < 0) breached++;
        else if (msLeft < 2 * 24 * 60 * 60 * 1000) at_risk++;
        else on_track++;
      }
      weeks.push({ week: `W${6 - i}`, on_track, at_risk, breached, resolved: resolved_count });
    }
    res.json(weeks);
  } catch (err) {
    logger.error({ err }, "SLA burn-down error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /sla/exceptions — list SLA extension requests
router.get("/sla/exceptions", async (_req, res) => {
  try {
    const items = await col("sla_exceptions").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(items.map(e => ({ ...e, id: String(e["_id"]) })));
  } catch (err) {
    logger.error({ err }, "List SLA exceptions error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /sla/exceptions — request SLA extension
router.post("/sla/exceptions", async (req, res) => {
  try {
    const { finding_id, reason, requested_days, analyst } = req.body as {
      finding_id?: string; reason?: string; requested_days?: number; analyst?: string;
    };
    if (!finding_id || !reason) return res.status(400).json({ error: "finding_id and reason required" });
    const insert = await col("sla_exceptions").insertOne({
      finding_id, reason, requested_days: requested_days ?? 7,
      analyst: analyst ?? "Unknown", status: "pending",
      created_at: new Date(), reviewed_at: null, reviewer: null, reviewer_note: null,
    });
    const saved = await col("sla_exceptions").findOne({ _id: insert.insertedId }) as Record<string, unknown>;
    res.status(201).json({ ...saved, id: String(saved["_id"]) });
  } catch (err) {
    logger.error({ err }, "Create SLA exception error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// PATCH /sla/exceptions/:id — approve or deny
router.patch("/sla/exceptions/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, reviewer_note, reviewer } = req.body as { status?: string; reviewer_note?: string; reviewer?: string };
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    await col("sla_exceptions").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { status, reviewer_note: reviewer_note ?? "", reviewer: reviewer ?? "Admin", reviewed_at: new Date() } }
    );
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Review SLA exception error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
