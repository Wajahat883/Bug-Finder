/**
 * Triage routes — False Positive / False Negative management
 * Phases 1-5: triage workflow, FP queue, FN risk scoring, AI assessment, metrics
 */
import { Router, type Request } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth, requireRole } from "../middlewares/rbac";
import { logAudit, auditFromReq } from "../lib/audit";
import { sendIntegrationAlerts } from "../services/alerts";

const router = Router();

// ── Helper: get session user ──────────────────────────────────────────────────
function getSession(req: any) {
  return req.session as { userId?: string; username?: string; role?: string };
}

// ── PHASE 1: Triage a finding (mark FP, confirm, suppress, needs-review) ─────

router.patch("/findings/:id/triage", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const session = getSession(req);
    const {
      status,           // open | confirmed | false_positive | suppressed | needs_review
      fp_reason,        // compensating_control | not_applicable | misidentification | already_fixed | accepted_risk | other
      fp_evidence,
      fp_reviewer_id,
      expiry_days,      // number — auto-resurface after N days
      triage_notes,
      suppress_days,
    } = req.body;

    const VALID_STATUSES = ["open", "confirmed", "false_positive", "suppressed", "needs_review"];
    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${VALID_STATUSES.join(", ")}` });
    }

    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { id };
    const finding = await col("findings").findOne(query as any);
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    // Phase 2: Four-eyes — FP submitter cannot also be reviewer
    if (status === "false_positive" && finding.fp_marked_by === session.userId) {
      return res.status(403).json({ error: "You cannot approve your own false positive submission. Assign a reviewer." });
    }

    const now = new Date();
    // Four-eyes workflow: submitting false_positive enters "needs_review" queue;
    // only POST /findings/:id/triage/review (by a different user) confirms it as false_positive.
    const storedStatus = status === "false_positive" ? "needs_review" : status;

    const updateFields: Record<string, unknown> = {
      triage_status: storedStatus,
      triage_updated_at: now,
      triage_updated_by: session.userId,
    };

    if (status === "false_positive") {
      updateFields["fp_reason"] = fp_reason ?? "other";
      updateFields["fp_evidence"] = fp_evidence ?? "";
      updateFields["fp_marked_by"] = session.userId;
      updateFields["fp_marked_at"] = now;
      updateFields["fp_reviewer_id"] = null;
      updateFields["fp_reviewed_at"] = null;
      updateFields["fp_rejected"] = false;
      if (expiry_days) {
        const expiry = new Date(now);
        expiry.setDate(expiry.getDate() + Number(expiry_days));
        updateFields["fp_expiry_date"] = expiry;
      }
    }

    if (status === "suppressed") {
      const days = Number(suppress_days ?? 30);
      const until = new Date(now);
      until.setDate(until.getDate() + days);
      updateFields["suppressed_until"] = until;
    }

    if (triage_notes) updateFields["triage_notes"] = triage_notes;

    await col("findings").updateOne(query as any, { $set: updateFields });

    // Write triage history
    await col("finding_triage_history").insertOne({
      finding_id: id,
      action: status,
      performed_by: session.userId,
      performed_by_username: session.username ?? "unknown",
      reason: fp_reason ?? null,
      evidence: fp_evidence ?? null,
      previous_status: finding.triage_status ?? "open",
      new_status: status,
      notes: triage_notes ?? null,
      created_at: now,
    });

    // Audit log
    await logAudit({
      userId: session.userId ?? "unknown",
      username: session.username ?? "unknown",
      action: `finding_triage_${status}`,
      resource: "finding",
      resourceId: id,
      details: { status, fp_reason, fp_evidence },
      ip: req.ip ?? "",
    });

    const updated = await col("findings").findOne(query as any);
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "Triage finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 2: FP review queue ──────────────────────────────────────────────────

router.get("/findings/false-positives", requireAuth, async (req, res) => {
  try {
    const session = getSession(req);
    const status = req.query["status"] as string ?? "all";
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "20"));

    const query: Record<string, unknown> = {};
    if (session.role !== "admin") query["user_id"] = session.userId;

    if (status === "pending_review") {
      // Findings submitted as FP awaiting a second reviewer
      query["triage_status"] = "needs_review";
    } else if (status === "confirmed_fp" || status === "approved") {
      // Reviewed and approved as genuine false positives
      query["triage_status"] = "false_positive";
      query["fp_reviewer_id"] = { $ne: null };
      query["fp_rejected"] = { $ne: true };
    } else if (status === "rejected_fp") {
      // FP submissions that were rejected by the reviewer (returned to open)
      query["fp_rejected"] = true;
    } else if (status === "suppressed") {
      query["triage_status"] = "suppressed";
    } else if (status === "expired") {
      query["triage_status"] = "false_positive";
      query["fp_expiry_date"] = { $lt: new Date() };
    } else {
      // "all" — show everything in the FP workflow
      query["$or"] = [
        { triage_status: "needs_review" },
        { triage_status: "false_positive" },
        { triage_status: "suppressed" },
        { fp_rejected: true },
      ];
    }

    const [items, total] = await Promise.all([
      col("findings")
        .find(query)
        .sort({ triage_updated_at: -1 })
        .skip((page - 1) * pageSize)
        .limit(pageSize)
        .toArray(),
      col("findings").countDocuments(query as any),
    ]);

    res.json({ items: items.map(f => ({ ...f, id: f._id?.toString() })), total, page, page_size: pageSize });
  } catch (err) {
    logger.error({ err }, "FP queue error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 2: Approve / reject a FP (senior/admin only) ───────────────────────

router.post("/findings/:id/triage/review", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const session = getSession(req);
    const { decision, notes } = req.body; // decision: approve | reject

    if (!["approve", "reject"].includes(decision)) {
      return res.status(400).json({ error: "decision must be 'approve' or 'reject'" });
    }

    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { id };
    const finding = await col("findings").findOne(query as any);
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    if (finding.fp_marked_by === session.userId) {
      return res.status(403).json({ error: "Four-eyes: reviewer must be a different user than the submitter." });
    }

    const approved = decision === "approve";
    const newStatus = approved ? "false_positive" : "open";
    await col("findings").updateOne(query as any, {
      $set: {
        triage_status: newStatus,
        fp_reviewer_id: session.userId,
        fp_reviewed_at: new Date(),
        fp_rejected: !approved,
        triage_notes: notes ?? finding.triage_notes,
        triage_updated_at: new Date(),
        triage_updated_by: session.userId,
      },
    });

    await col("finding_triage_history").insertOne({
      finding_id: id,
      action: `fp_${decision}d`,
      performed_by: session.userId,
      performed_by_username: session.username ?? "unknown",
      previous_status: finding.triage_status,
      new_status: newStatus,
      notes: notes ?? null,
      created_at: new Date(),
    });

    res.json({ ok: true, new_status: newStatus });
  } catch (err) {
    logger.error({ err }, "FP review error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 2: Suppress a finding ───────────────────────────────────────────────

router.post("/findings/:id/suppress", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const session = getSession(req);
    const { days = 30 } = req.body;

    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { id };
    const finding = await col("findings").findOne(query as any);
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    const until = new Date();
    until.setDate(until.getDate() + Number(days));

    await col("findings").updateOne(query as any, {
      $set: { triage_status: "suppressed", suppressed_until: until, triage_updated_by: session.userId, triage_updated_at: new Date() },
    });

    await col("finding_triage_history").insertOne({
      finding_id: id,
      action: "suppressed",
      performed_by: session.userId,
      performed_by_username: session.username ?? "unknown",
      previous_status: finding.triage_status ?? "open",
      new_status: "suppressed",
      notes: `Suppressed for ${days} days until ${until.toISOString()}`,
      created_at: new Date(),
    });

    res.json({ ok: true, suppressed_until: until });
  } catch (err) {
    logger.error({ err }, "Suppress error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 2: Triage history for a finding ────────────────────────────────────

router.get("/findings/:id/triage/history", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const history = await col("finding_triage_history")
      .find({ finding_id: id })
      .sort({ created_at: -1 })
      .limit(50)
      .toArray();
    res.json(history);
  } catch (err) {
    logger.error({ err }, "Triage history error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 3: FN risk score for a scan ─────────────────────────────────────────

router.get("/scan-jobs/:id/fn-risk", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { id };
    const scan = await col("scan_jobs").findOne(query as any);
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    const attackSurface = await col("attack_surface")
      .find({ scan_job_id: ObjectId.isValid(id) ? new ObjectId(id) : id })
      .toArray();

    const totalEndpoints = attackSurface.length || 1;
    const testedEndpoints = attackSurface.filter((e: any) => e.tested === true || e.requests_count > 0).length;
    const skippedModules = Number(scan.skipped_modules ?? 0);
    const totalModules = Number(scan.total_modules ?? 10);
    const timeoutEvents = Number(scan.timeout_events ?? 0);
    const lowConfidenceFindings = await col("findings").countDocuments({
      scan_job_id: ObjectId.isValid(id) ? new ObjectId(id) : id,
      confidence: { $lt: 0.5 },
    } as any);

    const untestedRatio = 1 - (testedEndpoints / totalEndpoints);
    const moduleSkipRatio = totalModules > 0 ? skippedModules / totalModules : 0;

    const fnRiskScore = Math.min(100, Math.round(
      untestedRatio * 40 +
      moduleSkipRatio * 35 +
      timeoutEvents * 5 +
      Number(lowConfidenceFindings) * 2
    ));

    const risk_level = fnRiskScore >= 70 ? "high" : fnRiskScore >= 40 ? "medium" : "low";

    // Persist score
    await col("scan_jobs").updateOne(query as any, { $set: { fn_risk_score: fnRiskScore, fn_risk_level: risk_level } });

    res.json({
      fn_risk_score: fnRiskScore,
      risk_level,
      breakdown: {
        total_endpoints: totalEndpoints,
        tested_endpoints: testedEndpoints,
        untested_endpoints: totalEndpoints - testedEndpoints,
        skipped_modules: skippedModules,
        total_modules: totalModules,
        timeout_events: timeoutEvents,
        low_confidence_findings: lowConfidenceFindings,
      },
    });
  } catch (err) {
    logger.error({ err }, "FN risk score error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 3: Coverage map for a scan ─────────────────────────────────────────

router.get("/scan-jobs/:id/coverage-map", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { id };
    const scan = await col("scan_jobs").findOne(query as any);
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    const attackSurface = await col("attack_surface")
      .find({ scan_job_id: ObjectId.isValid(id) ? new ObjectId(id) : id })
      .limit(200)
      .toArray();

    const findings = await col("findings")
      .find({ scan_job_id: ObjectId.isValid(id) ? new ObjectId(id) : id })
      .project({ endpoint: 1, severity: 1, title: 1 })
      .toArray();

    const findingsByEndpoint: Record<string, any[]> = {};
    for (const f of findings as any[]) {
      if (!findingsByEndpoint[f.endpoint]) findingsByEndpoint[f.endpoint] = [];
      findingsByEndpoint[f.endpoint].push(f);
    }

    const SCANNER_MODULES = [
      "Port Scanner", "Service Detection", "Auth Tester", "Injection Scanner",
      "XSS Scanner", "CORS Checker", "SSL/TLS Analyzer", "Header Inspector",
      "Directory Bruteforce", "API Fuzzer",
    ];

    const coverageMap = (attackSurface as any[]).map(ep => {
      const epFindings = findingsByEndpoint[ep.url ?? ep.endpoint ?? ""] ?? [];
      const tested = ep.tested === true || (ep.requests_count ?? 0) > 0;
      const hasFinding = epFindings.length > 0;
      return {
        endpoint: ep.url ?? ep.endpoint ?? ep.path ?? "unknown",
        method: ep.method ?? "GET",
        status: hasFinding ? "finding" : tested ? "tested" : "untested",
        findings: epFindings.map(f => ({ id: f._id?.toString(), title: f.title, severity: f.severity })),
        confidence: ep.confidence ?? (tested ? 0.8 : 0),
      };
    });

    // Module coverage matrix
    const moduleMatrix = SCANNER_MODULES.map(mod => ({
      module: mod,
      status: (scan.completed_modules as string[] ?? []).includes(mod) ? "complete"
        : (scan.skipped_modules_list as string[] ?? []).includes(mod) ? "skipped"
        : "not_run",
    }));

    res.json({ coverage_map: coverageMap, module_matrix: moduleMatrix, total_endpoints: attackSurface.length });
  } catch (err) {
    logger.error({ err }, "Coverage map error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 3: Manual finding submission ───────────────────────────────────────

router.post("/findings/manual", requireAuth, async (req, res) => {
  try {
    const session = getSession(req);
    const { scan_job_id, title, severity, category, endpoint, description, evidence, poc, source } = req.body;

    if (!title || !severity || !endpoint) {
      return res.status(400).json({ error: "title, severity, and endpoint are required" });
    }

    const VALID_SOURCES = ["manual_review", "external_pentest", "bug_bounty", "threat_intelligence", "other"];
    const finding = {
      scan_job_id: scan_job_id ? (ObjectId.isValid(scan_job_id) ? new ObjectId(scan_job_id) : scan_job_id) : null,
      title,
      severity: severity.toLowerCase(),
      category: category ?? "Manual",
      endpoint,
      description: description ?? "",
      evidence: evidence ?? "",
      poc: poc ?? "",
      manually_added: true,
      manually_added_source: VALID_SOURCES.includes(source) ? source : "other",
      validation_status: "pending",
      triage_status: "open",
      scanner_name: "Manual Submission",
      user_id: session.userId,
      created_by: session.userId,
      created_by_username: session.username ?? "unknown",
      created_at: new Date(),
      updated_at: new Date(),
    };

    const result = await col("findings").insertOne(finding);

    // Non-blocking Slack/Teams alerts for critical/high findings
    if (["critical", "high"].includes(finding["severity"] as string)) {
      sendIntegrationAlerts(finding as Record<string, unknown>).catch(() => {});
    }

    await logAudit({
      userId: session.userId ?? "unknown",
      username: session.username ?? "unknown",
      action: "finding_manual_submit",
      resource: "finding",
      resourceId: result.insertedId.toString(),
      details: { title, severity, source },
      ip: req.ip ?? "",
    });

    res.status(201).json({ ...finding, id: result.insertedId.toString(), _id: result.insertedId });
  } catch (err) {
    logger.error({ err }, "Manual finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 3: Scanner feedback (FN improvement) ───────────────────────────────

router.post("/scanner/feedback", requireAuth, async (req, res) => {
  try {
    const session = getSession(req);
    const { finding_id, missed_by_module, suggested_payload, endpoint_pattern, notes } = req.body;

    await col("scanner_feedback").insertOne({
      finding_id,
      missed_by_module,
      suggested_payload,
      endpoint_pattern,
      notes,
      submitted_by: session.userId,
      submitted_by_username: session.username,
      created_at: new Date(),
      status: "pending_review",
    });

    res.json({ ok: true, message: "Scanner feedback submitted. It will be reviewed for the next scanner release." });
  } catch (err) {
    logger.error({ err }, "Scanner feedback error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 4: AI-assisted FP probability assessment ────────────────────────────

router.post("/ai/triage/:findingId", requireAuth, async (req, res) => {
  try {
    const findingId = String(req.params["findingId"]);
    const query = ObjectId.isValid(findingId) ? { _id: new ObjectId(findingId) } : { id: findingId };
    const finding = await col("findings").findOne(query as any);
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    // Use stored AI assessment if fresh (< 24h)
    const cached = finding.ai_triage_assessment as any;
    if (cached && cached.assessed_at) {
      const age = Date.now() - new Date(cached.assessed_at).getTime();
      if (age < 24 * 60 * 60 * 1000) return res.json(cached);
    }

    const title = String(finding.title ?? "");
    const severity = String(finding.severity ?? "");
    const category = String(finding.category ?? "");
    const endpoint = String(finding.endpoint ?? "");
    const evidence = String(finding.evidence ?? "").slice(0, 500);
    const scanner = String(finding.scanner_name ?? "");

    // Rule-based heuristic scoring (no external AI call required)
    let fpScore = 0;
    const signals: string[] = [];

    if (endpoint.includes("localhost") || endpoint.includes("127.0.0.1")) { fpScore += 25; signals.push("Endpoint is localhost — likely not production"); }
    if (title.toLowerCase().includes("missing") && severity === "info") { fpScore += 15; signals.push("'Missing' info-level findings have high FP rate"); }
    if (scanner.toLowerCase().includes("zap") && category === "CORS") { fpScore += 20; signals.push("ZAP CORS findings often flag non-exploitable configurations"); }
    if (!evidence || evidence.trim() === "") { fpScore += 20; signals.push("No evidence recorded — scanner may not have confirmed exploitability"); }
    if (title.toLowerCase().includes("x-frame-options") || title.toLowerCase().includes("content-type")) { fpScore += 30; signals.push("Header-only findings are often informational with low real-world impact"); }
    if (severity === "critical" && evidence && evidence.length > 100) { fpScore -= 20; signals.push("Critical finding with substantial evidence — likely real"); }

    fpScore = Math.max(0, Math.min(100, fpScore));
    const suggested_action = fpScore >= 70 ? "review" : fpScore >= 40 ? "verify" : "confirm_real";

    const assessment = {
      fp_probability: fpScore,
      confidence: fpScore > 60 || fpScore < 20 ? "high" : "medium",
      suggested_action,
      reasoning: signals.length > 0 ? signals.join(". ") : "No strong FP signals detected — finding appears genuine.",
      assessed_at: new Date().toISOString(),
      model: "rule-based-v1",
    };

    // Cache assessment on the finding
    await col("findings").updateOne(query as any, { $set: { ai_triage_assessment: assessment } });

    res.json(assessment);
  } catch (err) {
    logger.error({ err }, "AI triage error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 5: FP/FN stats for metrics dashboard ───────────────────────────────

router.get("/triage/stats", requireAuth, async (req, res) => {
  try {
    const session = getSession(req);
    const userFilter: Record<string, unknown> = session.role !== "admin" ? { user_id: session.userId } : {};

    const now = new Date();
    const thirtyDaysAgo = new Date(now); thirtyDaysAgo.setDate(now.getDate() - 30);
    const sixtyDaysAgo = new Date(now); sixtyDaysAgo.setDate(now.getDate() - 60);

    const [
      totalFindings,
      fpCount,
      confirmedCount,
      suppressedCount,
      needsReviewCount,
      manualCount,
      fpThisMonth,
      fpLastMonth,
      expiredCount,
    ] = await Promise.all([
      col("findings").countDocuments(userFilter as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "false_positive" } as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "confirmed" } as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "suppressed" } as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "needs_review" } as any),
      col("findings").countDocuments({ ...userFilter, manually_added: true } as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "false_positive", fp_marked_at: { $gte: thirtyDaysAgo } } as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "false_positive", fp_marked_at: { $gte: sixtyDaysAgo, $lt: thirtyDaysAgo } } as any),
      col("findings").countDocuments({ ...userFilter, triage_status: "false_positive", fp_expiry_date: { $lt: now } } as any),
    ]);

    const fpRate = totalFindings > 0 ? Math.round((fpCount / totalFindings) * 100) : 0;
    const fpRateLastMonth = (totalFindings - fpThisMonth) > 0
      ? Math.round((fpLastMonth / (totalFindings - fpThisMonth)) * 100) : 0;
    const scannerAccuracy = (confirmedCount + fpCount) > 0
      ? Math.round((confirmedCount / (confirmedCount + fpCount)) * 100) : null;

    // FP by reason breakdown
    const fpByReason = await col("findings").aggregate([
      { $match: { ...userFilter, triage_status: "false_positive", fp_reason: { $ne: null } } },
      { $group: { _id: "$fp_reason", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]).toArray();

    // Weekly FP trend (last 8 weeks)
    const weeklyFpTrend: { week: string; fp_count: number; total_count: number }[] = [];
    for (let i = 7; i >= 0; i--) {
      const wStart = new Date(now); wStart.setDate(now.getDate() - (i + 1) * 7);
      const wEnd = new Date(now); wEnd.setDate(now.getDate() - i * 7);
      const [wFp, wTotal] = await Promise.all([
        col("findings").countDocuments({ ...userFilter, fp_marked_at: { $gte: wStart, $lt: wEnd } } as any),
        col("findings").countDocuments({ ...userFilter, created_at: { $gte: wStart, $lt: wEnd } } as any),
      ]);
      weeklyFpTrend.push({ week: wStart.toISOString().slice(0, 10), fp_count: wFp, total_count: wTotal });
    }

    // MTTR per triage status (time from created_at to triage_updated_at)
    const avgTriageTime = await col("finding_triage_history").aggregate([
      { $match: { action: { $in: ["false_positive", "confirmed"] } } },
      { $group: { _id: "$action", avg_hours: { $avg: { $divide: [{ $subtract: ["$created_at", new Date(0)] }, 3600000] } } } },
    ]).toArray();

    res.json({
      total_findings: totalFindings,
      fp_count: fpCount,
      confirmed_count: confirmedCount,
      suppressed_count: suppressedCount,
      needs_review_count: needsReviewCount,
      manually_added_count: manualCount,
      expired_fp_count: expiredCount,
      fp_rate_this_month: fpThisMonth,
      fp_rate_last_month: fpLastMonth,
      fp_rate_pct: fpRate,
      fp_rate_change: fpRate - fpRateLastMonth,
      scanner_accuracy: scannerAccuracy,
      fp_by_reason: fpByReason.map(r => ({ reason: r._id, count: r.count })),
      weekly_fp_trend: weeklyFpTrend,
      avg_triage_time_hours: avgTriageTime,
    });
  } catch (err) {
    logger.error({ err }, "Triage stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PHASE 5: FP expiry job endpoint (called by cron) ─────────────────────────

router.post("/triage/run-expiry-job", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const now = new Date();
    const expired = await col("findings").find({
      triage_status: "false_positive",
      fp_expiry_date: { $lt: now },
    } as any).toArray();

    let reopened = 0;
    for (const f of expired as any[]) {
      await col("findings").updateOne(
        { _id: f._id },
        { $set: { triage_status: "open", triage_updated_at: now }, $unset: { fp_expiry_date: "" } }
      );
      await col("finding_triage_history").insertOne({
        finding_id: f._id?.toString(),
        action: "fp_expired",
        performed_by: "system",
        performed_by_username: "system",
        previous_status: "false_positive",
        new_status: "open",
        notes: "FP auto-expired and re-opened for re-evaluation",
        created_at: now,
      });
      reopened++;
    }

    // Also un-suppress expired suppressions
    const expiredSuppressions = await col("findings").find({
      triage_status: "suppressed",
      suppressed_until: { $lt: now },
    } as any).toArray();

    for (const f of expiredSuppressions as any[]) {
      await col("findings").updateOne(
        { _id: f._id },
        { $set: { triage_status: "open", triage_updated_at: now }, $unset: { suppressed_until: "" } }
      );
      reopened++;
    }

    res.json({ ok: true, reopened, expired_fp: expired.length, expired_suppressions: expiredSuppressions.length });
  } catch (err) {
    logger.error({ err }, "Expiry job error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
