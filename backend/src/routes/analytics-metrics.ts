import { Router, Request } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

function userFilter(req: Request): Record<string, unknown> {
  const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
  return session?.role !== "admin" ? { user_id: session?.userId ?? null } : {};
}

// GET /metrics/mttr — Mean Time to Remediate grouped by severity (in hours)
router.get("/metrics/mttr", requireAuth, async (req, res) => {
  try {
    const filter = { resolved_at: { $exists: true, $ne: null }, ...userFilter(req) };
    const findings = (await col("findings").find(filter as Record<string, unknown>).toArray()) as Array<Record<string, unknown>>;
    const groups: Record<string, number[]> = { critical: [], high: [], medium: [], low: [] };
    for (const f of findings) {
      const sev = String(f["severity"] ?? "");
      if (!groups[sev]) continue;
      const created = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
      const resolved = f["resolved_at"] instanceof Date ? f["resolved_at"] : new Date(f["resolved_at"] as string);
      const hours = (resolved.getTime() - created.getTime()) / (1000 * 60 * 60);
      if (hours >= 0) groups[sev].push(hours);
    }
    const avg = (arr: number[]) => arr.length ? Math.round((arr.reduce((a, b) => a + b, 0) / arr.length) * 10) / 10 : null;
    const all = Object.values(groups).flat();
    res.json({
      critical: avg(groups["critical"]!),
      high: avg(groups["high"]!),
      medium: avg(groups["medium"]!),
      low: avg(groups["low"]!),
      overall: avg(all),
    });
  } catch (err) {
    logger.error({ err }, "MTTR error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /metrics/sla-compliance — % remediated within SLA window
router.get("/metrics/sla-compliance", requireAuth, async (req, res) => {
  try {
    const SLA_HOURS: Record<string, number> = { critical: 24, high: 168, medium: 720, low: 2160 };
    const findings = (await col("findings").find(userFilter(req)).toArray()) as Array<Record<string, unknown>>;
    const result: Record<string, { compliant: number; total: number; pct: number }> = {};
    for (const [sev, hours] of Object.entries(SLA_HOURS)) {
      const sevFindings = findings.filter((f) => String(f["severity"] ?? "") === sev);
      const total = sevFindings.length;
      if (total === 0) { result[sev] = { compliant: 0, total: 0, pct: 100 }; continue; }
      const compliant = sevFindings.filter((f) => {
        if (!f["resolved_at"]) return false;
        const created = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string);
        const resolved = f["resolved_at"] instanceof Date ? f["resolved_at"] : new Date(f["resolved_at"] as string);
        return (resolved.getTime() - created.getTime()) / (1000 * 60 * 60) <= hours;
      }).length;
      result[sev] = { compliant, total, pct: Math.round((compliant / total) * 100) };
    }
    res.json(result);
  } catch (err) {
    logger.error({ err }, "SLA compliance error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /metrics/false-positive-rate — FP rate grouped by scanner_name
router.get("/metrics/false-positive-rate", requireAuth, async (req, res) => {
  try {
    const findings = (await col("findings").find(userFilter(req)).toArray()) as Array<Record<string, unknown>>;
    const scanners: Record<string, { total: number; false_positives: number }> = {};
    for (const f of findings) {
      const scanner = String(f["scanner_name"] ?? "unknown");
      if (!scanners[scanner]) scanners[scanner] = { total: 0, false_positives: 0 };
      scanners[scanner].total++;
      if (f["validation_status"] === "false_positive") scanners[scanner].false_positives++;
    }
    const result = Object.entries(scanners).map(([scanner_name, d]) => ({
      scanner_name,
      total: d.total,
      false_positives: d.false_positives,
      fp_rate: d.total > 0 ? Math.round((d.false_positives / d.total) * 100 * 10) / 10 : 0,
    })).sort((a, b) => b.total - a.total);
    res.json(result);
  } catch (err) {
    logger.error({ err }, "FP rate error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /metrics/recurrence-rate — findings that reappeared across scans on same target
router.get("/metrics/recurrence-rate", requireAuth, async (req, res) => {
  try {
    const findings = (await col("findings").find(userFilter(req)).toArray()) as Array<Record<string, unknown>>;
    const grouped: Record<string, Set<string>> = {};
    for (const f of findings) {
      const key = `${String(f["title"] ?? "")}||${String(f["endpoint"] ?? "")}`;
      const scanId = f["scan_job_id"] ? String(f["scan_job_id"]) : null;
      if (!scanId) continue;
      if (!grouped[key]) grouped[key] = new Set();
      grouped[key].add(scanId);
    }
    const recurrent = Object.values(grouped).filter((s) => s.size > 1).length;
    const total = Object.keys(grouped).length;
    res.json({ recurrent, total, rate: total > 0 ? Math.round((recurrent / total) * 100 * 10) / 10 : 0 });
  } catch (err) {
    logger.error({ err }, "Recurrence rate error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /metrics/risk-velocity — risk score trend per target
router.get("/metrics/risk-velocity", requireAuth, async (req, res) => {
  try {
    const scans = (await col("scan_jobs").find({ status: "completed", ...userFilter(req) } as Record<string, unknown>).sort({ created_at: -1 }).limit(200).toArray()) as Array<Record<string, unknown>>;
    const byTarget: Record<string, Array<{ score: number; created_at: Date }>> = {};
    for (const s of scans) {
      const url = String(s["target_url"] ?? "");
      if (!byTarget[url]) byTarget[url] = [];
      byTarget[url].push({ score: Number(s["risk_score"] ?? 0), created_at: s["created_at"] instanceof Date ? s["created_at"] : new Date(s["created_at"] as string) });
    }
    const result = Object.entries(byTarget).map(([target_url, entries]) => {
      const sorted = entries.sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
      const current = sorted[0]?.score ?? 0;
      const previous = sorted[1]?.score ?? 0;
      const delta = current - previous;
      return { target_url, current_score: current, previous_score: previous, delta, trend: delta > 0 ? "up" : delta < 0 ? "down" : "stable" };
    }).filter((r) => r.previous_score > 0 || r.current_score > 0);
    res.json(result);
  } catch (err) {
    logger.error({ err }, "Risk velocity error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /analytics/scanner-performance — per-scanner: total findings, avg confidence, fp_rate
router.get("/analytics/scanner-performance", requireAuth, async (req, res) => {
  try {
    const findings = (await col("findings").find(userFilter(req)).toArray()) as Array<Record<string, unknown>>;
    const scanners: Record<string, { total: number; confidence_sum: number; false_positives: number }> = {};
    for (const f of findings) {
      const s = String(f["scanner_name"] ?? "unknown");
      if (!scanners[s]) scanners[s] = { total: 0, confidence_sum: 0, false_positives: 0 };
      scanners[s].total++;
      scanners[s].confidence_sum += Number(f["confidence"] ?? 0.5);
      if (f["validation_status"] === "false_positive") scanners[s].false_positives++;
    }
    const result = Object.entries(scanners).map(([scanner_name, d]) => ({
      scanner_name,
      total_findings: d.total,
      avg_confidence: d.total > 0 ? Math.round((d.confidence_sum / d.total) * 100) / 100 : 0,
      fp_rate: d.total > 0 ? Math.round((d.false_positives / d.total) * 100 * 10) / 10 : 0,
    })).sort((a, b) => b.total_findings - a.total_findings);
    res.json(result);
  } catch (err) {
    logger.error({ err }, "Scanner performance error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /analytics/finding-trends — findings per day for last 30 days
router.get("/analytics/finding-trends", requireAuth, async (req, res) => {
  try {
    const findings = (await col("findings").find(userFilter(req)).toArray()) as Array<Record<string, unknown>>;
    const today = new Date();
    const trend = Array.from({ length: 30 }, (_, i) => {
      const d = new Date(today);
      d.setDate(d.getDate() - (29 - i));
      const dateStr = d.toISOString().split("T")[0]!;
      const count = findings.filter((f) => {
        const fDate = (f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string)).toISOString().split("T")[0];
        return fDate === dateStr;
      }).length;
      return { date: dateStr, count };
    });
    res.json(trend);
  } catch (err) {
    logger.error({ err }, "Finding trends error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /analytics/top-vulnerable-targets — top 10 targets by finding count + risk score
router.get("/analytics/top-vulnerable-targets", requireAuth, async (req, res) => {
  try {
    const targets = (await col("targets").find(userFilter(req)).sort({ total_findings: -1 }).limit(10).toArray()) as Array<Record<string, unknown>>;
    res.json(targets.map((t) => ({
      id: String(t["_id"]),
      url: t["url"],
      domain: t["domain"],
      total_findings: t["total_findings"] ?? 0,
      critical_findings: t["critical_findings"] ?? 0,
      risk_score: t["risk_score"] ?? 0,
    })));
  } catch (err) {
    logger.error({ err }, "Top vulnerable targets error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /analytics/metrics/executive — KPI metrics for executive dashboard
router.get("/analytics/metrics/executive", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string; role?: string };
    const userFilter = sess.role !== "admin" ? { user_id: sess.userId } : {};

    const [allFindings, resolvedFindings, targets] = await Promise.all([
      col("findings").find(userFilter as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
      col("findings").find({ ...userFilter, status: "resolved" } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
      col("targets").find(userFilter as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);

    // MTTD: avg time from finding created to scan completed
    const mttdMs = allFindings.reduce((sum, f) => {
      const created = f["created_at"] ? new Date(f["created_at"] as string).getTime() : 0;
      const scanned = f["scan_completed_at"] ? new Date(f["scan_completed_at"] as string).getTime() : created;
      return sum + (scanned - created);
    }, 0) / Math.max(allFindings.length, 1);

    // MTTR: avg days to resolve
    const mttrMs = resolvedFindings.reduce((sum, f) => {
      const created = f["created_at"] ? new Date(f["created_at"] as string).getTime() : 0;
      const resolved = f["resolved_at"] ? new Date(f["resolved_at"] as string).getTime() : created;
      return sum + (resolved - created);
    }, 0) / Math.max(resolvedFindings.length, 1);

    // Velocity: resolved in last 7 days
    const weekAgo = new Date(Date.now() - 7 * 86400000);
    const recentResolved = resolvedFindings.filter(f => f["resolved_at"] && new Date(f["resolved_at"] as string) > weekAgo).length;

    // Top targets by finding count
    const targetMap: Record<string, number> = {};
    for (const f of allFindings) {
      const url = String(f["target_url"] ?? f["endpoint"] ?? "unknown");
      targetMap[url] = (targetMap[url] ?? 0) + 1;
    }
    const topTargets = Object.entries(targetMap).sort(([, a], [, b]) => b - a).slice(0, 5).map(([url, count]) => ({ url, finding_count: count, risk_score: Math.min(10, count * 0.5) }));

    res.json({
      mttd_hours: Math.round(mttdMs / 3600000 * 10) / 10,
      mttr_days: Math.round(mttrMs / 86400000 * 10) / 10,
      remediation_velocity: recentResolved,
      vulnerability_density: Math.round(allFindings.length / Math.max(targets.length, 1) * 10) / 10,
      open_critical: allFindings.filter(f => f["severity"] === "critical" && f["status"] !== "resolved").length,
      top_targets: topTargets,
    });
  } catch (err) {
    logger.error({ err }, "Executive metrics error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
