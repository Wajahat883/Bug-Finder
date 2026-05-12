import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

// POST /scan-jobs/compare — compare two scans
router.post("/scan-jobs/compare", async (req, res) => {
  try {
    const { scan_id_a, scan_id_b } = req.body as { scan_id_a: string; scan_id_b: string };

    if (!scan_id_a || !scan_id_b) {
      return res.status(400).json({ error: "scan_id_a and scan_id_b are required" });
    }
    if (!ObjectId.isValid(scan_id_a) || !ObjectId.isValid(scan_id_b)) {
      return res.status(400).json({ error: "Invalid scan IDs" });
    }

    const [scanA, scanB] = await Promise.all([
      col("scan_jobs").findOne({ _id: new ObjectId(scan_id_a) } as Record<string, unknown>) as Promise<Record<string, unknown> | null>,
      col("scan_jobs").findOne({ _id: new ObjectId(scan_id_b) } as Record<string, unknown>) as Promise<Record<string, unknown> | null>,
    ]);

    if (!scanA || !scanB) {
      return res.status(404).json({ error: "One or both scan jobs not found" });
    }

    const [findingsA, findingsB] = await Promise.all([
      col("findings").find({ scan_job_id: new ObjectId(scan_id_a) }).toArray() as Promise<Array<Record<string, unknown>>>,
      col("findings").find({ scan_job_id: new ObjectId(scan_id_b) }).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);

    // Build title-keyed sets for comparison
    const titlesA = new Set(findingsA.map(f => String(f["title"] ?? "")));
    const titlesB = new Set(findingsB.map(f => String(f["title"] ?? "")));

    const newFindings = findingsB.filter(f => !titlesA.has(String(f["title"] ?? "")));
    const resolvedFindings = findingsA.filter(f => !titlesB.has(String(f["title"] ?? "")));
    const persistedFindings = findingsA.filter(f => titlesB.has(String(f["title"] ?? "")));

    const formatFinding = (f: Record<string, unknown>) => ({
      id: String(f["_id"]),
      title: f["title"],
      category: f["category"],
      severity: f["severity"],
      endpoint: f["endpoint"],
      cvss_score: f["cvss_score"] ?? null,
      cwe_id: f["cwe_id"] ?? null,
      description: f["description"] ?? null,
      validation_status: f["validation_status"] ?? null,
    });

    // Key by title+endpoint for matching
    const key = (f: Record<string, unknown>) => `${String(f["title"] ?? "")}||${String(f["endpoint"] ?? "")}`;
    const mapA = new Map(findingsA.map(f => [key(f), f]));
    const mapB = new Map(findingsB.map(f => [key(f), f]));

    // Regressed: in A it was resolved/FP, but reappears in B
    const regressedFindings = findingsB.filter(fb => {
      const fa = mapA.get(key(fb));
      if (!fa) return false;
      const faStatus = String(fa["validation_status"] ?? "");
      return faStatus === "false_positive" || faStatus === "confirmed" || faStatus === "real";
    });

    // Severity changes: same finding (by title+endpoint) has different severity between scans
    const severityChanges: Array<{ id_a: string; id_b: string; title: string; endpoint: string; severity_a: string; severity_b: string }> = [];
    for (const [k, fb] of mapB.entries()) {
      const fa = mapA.get(k);
      if (!fa) continue;
      if (String(fa["severity"]) !== String(fb["severity"])) {
        severityChanges.push({
          id_a: String(fa["_id"]),
          id_b: String(fb["_id"]),
          title: String(fb["title"] ?? ""),
          endpoint: String(fb["endpoint"] ?? ""),
          severity_a: String(fa["severity"] ?? ""),
          severity_b: String(fb["severity"] ?? ""),
        });
      }
    }

    const riskDelta = (Number(scanB["risk_score"] ?? 0)) - (Number(scanA["risk_score"] ?? 0));
    const severityBreakdown = {
      a: { critical: scanA["critical_count"] ?? 0, high: scanA["high_count"] ?? 0, medium: scanA["medium_count"] ?? 0, low: scanA["low_count"] ?? 0 },
      b: { critical: scanB["critical_count"] ?? 0, high: scanB["high_count"] ?? 0, medium: scanB["medium_count"] ?? 0, low: scanB["low_count"] ?? 0 },
    };

    res.json({
      scan_a: { id: scan_id_a, target_url: scanA["target_url"], created_at: scanA["created_at"], risk_score: scanA["risk_score"] ?? 0, findings_count: findingsA.length },
      scan_b: { id: scan_id_b, target_url: scanB["target_url"], created_at: scanB["created_at"], risk_score: scanB["risk_score"] ?? 0, findings_count: findingsB.length },
      summary: {
        risk_delta: riskDelta,
        risk_trend: riskDelta > 0 ? "worse" : riskDelta < 0 ? "improved" : "unchanged",
        new_findings_count: newFindings.length,
        resolved_findings_count: resolvedFindings.length,
        persisted_findings_count: persistedFindings.length,
        regressed_findings_count: regressedFindings.length,
        severity_changes_count: severityChanges.length,
      },
      severity_breakdown: severityBreakdown,
      new_findings: newFindings.map(formatFinding),
      resolved_findings: resolvedFindings.map(formatFinding),
      persisted_findings: persistedFindings.map(formatFinding),
      regressed_findings: regressedFindings.map(formatFinding),
      severity_changes: severityChanges,
    });
  } catch (err) {
    logger.error({ err }, "Scan comparison error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /scan-jobs/:id/retest — retest a scan with same settings
router.post("/scan-jobs/:id/retest", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const original = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!original) return res.status(404).json({ error: "Scan job not found" });

    const { runScanPipeline } = await import("../services/scanner/index");

    const now = new Date();
    const insert = await col("scan_jobs").insertOne({
      target_url: original["target_url"],
      scan_profile: original["scan_profile"],
      status: "queued",
      progress: 0,
      created_at: now,
      started_at: null,
      completed_at: null,
      findings_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 0,
      risk_score: 0,
      ai_summary: null,
      validation_enabled: original["validation_enabled"] ?? false,
      fuzzing_enabled: original["fuzzing_enabled"] ?? false,
      bug_bounty_mode: original["bug_bounty_mode"] ?? false,
      authorization_acknowledged: true,
      scanner_engines: original["scanner_engines"] ?? [],
      error_message: null,
      retest_of: new ObjectId(id),
      session_cookie: original["session_cookie"] ?? null,
      auth_token: original["auth_token"] ?? null,
      custom_headers: original["custom_headers"] ?? null,
      is_authenticated_scan: original["is_authenticated_scan"] ?? false,
    });

    runScanPipeline({
      jobId: String(insert.insertedId),
      targetUrl: String(original["target_url"]),
      profile: (original["scan_profile"] as "quick" | "standard" | "deep") ?? "standard",
      validationEnabled: Boolean(original["validation_enabled"]),
      fuzzingEnabled: Boolean(original["fuzzing_enabled"]),
      bugBountyMode: Boolean(original["bug_bounty_mode"]),
      sessionCookie: original["session_cookie"] as string | undefined,
      authToken: original["auth_token"] as string | undefined,
    });

    await col("activity_events").insertOne({
      type: "scan_created",
      message: `Retest started for ${original["target_url"]}`,
      timestamp: now,
      scan_job_id: insert.insertedId,
      severity: null,
    });

    const job = await col("scan_jobs").findOne({ _id: insert.insertedId } as Record<string, unknown>) as Record<string, unknown>;
    res.status(201).json({ id: String(job["_id"]), status: job["status"], target_url: job["target_url"], retest_of: id });
  } catch (err) {
    logger.error({ err }, "Retest scan error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
