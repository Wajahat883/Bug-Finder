import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth, requireAdmin } from "../middlewares/rbac";
import { auditFromReq } from "../lib/audit";
import { checkSsrf } from "../lib/ssrf-guard";
import { getComplianceTags } from "../lib/compliance-map";
import { redactObject, FINDING_SENSITIVE_FIELDS } from "../lib/pii-redact";

const router = Router();
router.use(requireAuth);

function formatJob(j: Record<string, unknown>) {
  return {
    id: String(j["_id"]),
    target_url: j["target_url"],
    scan_profile: j["scan_profile"],
    status: j["status"],
    progress: j["progress"] ?? 0,
    created_at: j["created_at"],
    started_at: j["started_at"] ?? null,
    completed_at: j["completed_at"] ?? null,
    findings_count: j["findings_count"] ?? 0,
    critical_count: j["critical_count"] ?? 0,
    high_count: j["high_count"] ?? 0,
    medium_count: j["medium_count"] ?? 0,
    low_count: j["low_count"] ?? 0,
    info_count: j["info_count"] ?? 0,
    risk_score: j["risk_score"] ?? 0,
    ai_summary: j["ai_summary"] ?? null,
    validation_enabled: j["validation_enabled"] ?? false,
    fuzzing_enabled: j["fuzzing_enabled"] ?? false,
    bug_bounty_mode: j["bug_bounty_mode"] ?? false,
    authorization_acknowledged: j["authorization_acknowledged"] ?? false,
    scanner_engines: j["scanner_engines"] ?? [],
    error_message: j["error_message"] ?? null,
    scope_hosts: j["scope_hosts"] ?? [],
    diff_stats: j["diff_stats"] ?? null,
  };
}

router.get("/scan-jobs", async (req, res) => {
  try {
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "20"));
    const status = req.query["status"] as string | undefined;
    const search = req.query["search"] as string | undefined;

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const query: Record<string, unknown> = {};
    if (session.role !== "admin") query.user_id = session.userId;
    if (status) query["status"] = status;
    if (search) {
      query["target_url"] = { $regex: search, $options: "i" };
    }

    const col_ = col("scan_jobs");
    const [all, total] = await Promise.all([
      col_.find(query).sort({ created_at: -1 }).skip((page - 1) * pageSize).limit(pageSize).toArray() as Promise<Array<Record<string, unknown>>>,
      (col_.countDocuments as (q: Record<string, unknown>) => Promise<number>)(query),
    ]);
    const items = all.map(formatJob);

    res.json({ items, total, page, page_size: pageSize });
  } catch (err) {
    logger.error({ err }, "List scan jobs error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/scan-jobs", async (req, res) => {
  try {
    const body = req.body as {
      target_url: string;
      scan_profile: string;
      validation_enabled?: boolean;
      fuzzing_enabled?: boolean;
      bug_bounty_mode?: boolean;
      authorization_acknowledged: boolean;
      authorization_note?: string;
      scanner_engines?: string[];
      template_id?: string;
      session_cookie?: string;
      auth_token?: string;
      custom_headers?: Record<string, string>;
      scope_hosts?: string[];
      openapi_spec_url?: string;
    };

    if (!body.target_url || !body.scan_profile) {
      return res.status(400).json({ error: "target_url and scan_profile are required" });
    }

    // POINT 1: SSRF Protection — block private/internal IPs
    const ssrfCheck = checkSsrf(body.target_url);
    if (!ssrfCheck.allowed) {
      logger.warn({ targetUrl: body.target_url, reason: ssrfCheck.reason }, "SSRF scan attempt blocked");
      return res.status(400).json({ error: `Scan target not allowed: ${ssrfCheck.reason}` });
    }

    if (!body.authorization_acknowledged) {
      return res.status(400).json({ error: "Authorization must be acknowledged before scanning" });
    }

    // If template_id supplied, load and merge template settings
    let templateSettings: Record<string, unknown> = {};
    if (body.template_id) {
      const { ObjectId: OId } = await import("mongodb");
      if (OId.isValid(body.template_id)) {
        const tmpl = await col("scan_templates").findOne({ _id: new OId(body.template_id) } as Record<string, unknown>) as Record<string, unknown> | null;
        if (tmpl) templateSettings = tmpl;
      }
    }

    const engines = body.scanner_engines ?? (templateSettings["scanner_engines"] as string[] | undefined) ?? ["tls_check", "header_scan", "cors_check", "cookie_checker"];
    if (body.validation_enabled) engines.push("xss_validator", "sqli_scanner");
    if (body.fuzzing_enabled) engines.push("fuzzer");
    if (body.bug_bounty_mode) engines.push("idor_checker", "auth_tester");

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const now = new Date();
    const insert = await col("scan_jobs").insertOne({
      target_url: body.target_url,
      scan_profile: body.scan_profile,
      user_id: session.userId,
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
      validation_enabled: body.validation_enabled ?? (templateSettings["validation_enabled"] as boolean | undefined) ?? false,
      fuzzing_enabled: body.fuzzing_enabled ?? (templateSettings["fuzzing_enabled"] as boolean | undefined) ?? false,
      bug_bounty_mode: body.bug_bounty_mode ?? (templateSettings["bug_bounty_mode"] as boolean | undefined) ?? false,
      authorization_acknowledged: body.authorization_acknowledged,
      authorization_note: body.authorization_note ?? null,
      scanner_engines: engines,
      session_cookie: body.session_cookie ?? null,
      auth_token: body.auth_token ?? null,
      custom_headers: body.custom_headers ?? (templateSettings["auth_headers"] as Record<string, string> | undefined) ?? {},
      scope_hosts: body.scope_hosts ?? (templateSettings["scope_hosts"] as string[] | undefined) ?? [],
      openapi_spec_url: body.openapi_spec_url ?? null,
      error_message: null,
    });

    // Log activity
    await col("activity_events").insertOne({
      type: "scan_created",
      message: `New scan job created for ${body.target_url}`,
      timestamp: now,
      scan_job_id: insert.insertedId,
      severity: null,
    });

    // POINT 4: Backpressure — check queue capacity before accepting job
    const { enqueueScan } = await import("../services/queue/manager");
    const enqueueResult = await enqueueScan({
      jobId: String(insert.insertedId),
      targetUrl: body.target_url,
      profile: (body.scan_profile ?? templateSettings["scan_profile"] ?? "standard") as "quick" | "standard" | "deep",
      validationEnabled: body.validation_enabled ?? (templateSettings["validation_enabled"] as boolean | undefined) ?? false,
      fuzzingEnabled: body.fuzzing_enabled ?? (templateSettings["fuzzing_enabled"] as boolean | undefined) ?? false,
      bugBountyMode: body.bug_bounty_mode ?? (templateSettings["bug_bounty_mode"] as boolean | undefined) ?? false,
      sessionCookie: body.session_cookie,
      authToken: body.auth_token,
      customHeaders: body.custom_headers ?? (templateSettings["auth_headers"] as Record<string, string> | undefined),
      scopeHosts: body.scope_hosts ?? (templateSettings["scope_hosts"] as string[] | undefined),
      openapiSpecUrl: body.openapi_spec_url ?? undefined,
    });
    if (!enqueueResult.ok) {
      // Remove the scan job we just created since it can't be queued
      await col("scan_jobs").updateOne({ _id: insert.insertedId } as Record<string, unknown>, { $set: { status: "failed", error_message: enqueueResult.reason } });
      return res.status(503).json({ error: enqueueResult.reason ?? "Queue full" });
    }

    const job = (await col("scan_jobs").findOne({ _id: insert.insertedId } as Record<string, unknown>)) as Record<string, unknown>;
    res.status(201).json(formatJob(job));
  } catch (err) {
    logger.error({ err }, "Create scan job error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scan-jobs/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const job = (await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!job) return res.status(404).json({ error: "Scan job not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (!session?.userId) return res.status(401).json({ error: "Not authenticated" });
    if (session.role !== "admin" && job.user_id !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    res.json(formatJob(job));
  } catch (err) {
    logger.error({ err }, "Get scan job error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scan-jobs/:id/findings", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const query: Record<string, unknown> = { scan_job_id: new ObjectId(id) };
    const severity = req.query["severity"] as string | undefined;
    const valStatus = req.query["validation_status"] as string | undefined;
    if (severity) query["severity"] = severity;
    if (valStatus) query["validation_status"] = valStatus;

    const findings = (await col("findings").find(query).toArray()) as Array<Record<string, unknown>>;
    res.json(findings.map(formatFinding));
  } catch (err) {
    logger.error({ err }, "Get scan job findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scan-jobs/:id/attack-surface", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const job = (await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!job) return res.status(404).json({ error: "Not found" });

    const findings = (await col("findings").find({ scan_job_id: new ObjectId(id) }).toArray()) as Array<Record<string, unknown>>;
    const targetUrl = job["target_url"] as string;
    const domain = new URL(targetUrl).hostname;

    const nodes = [
      { id: "domain_0", label: domain, type: "domain", severity: null },
    ];

    const endpoints = [...new Set(findings.map((f) => f["endpoint"] as string))];
    endpoints.slice(0, 6).forEach((ep, i) => {
      nodes.push({ id: `ep_${i}`, label: ep, type: "endpoint", severity: null });
    });

    findings.slice(0, 8).forEach((f, i) => {
      nodes.push({ id: `finding_${i}`, label: f["title"] as string, type: "finding", severity: f["severity"] as string });
    });

    const edges = [];
    endpoints.slice(0, 6).forEach((_, i) => {
      edges.push({ source: "domain_0", target: `ep_${i}`, type: "depends-on" });
    });
    findings.slice(0, 8).forEach((f, i) => {
      const epIdx = endpoints.indexOf(f["endpoint"] as string);
      if (epIdx >= 0) {
        edges.push({ source: `ep_${epIdx}`, target: `finding_${i}`, type: "has-finding" });
      } else {
        edges.push({ source: "domain_0", target: `finding_${i}`, type: "has-finding" });
      }
    });

    res.json({
      nodes,
      edges,
      metrics: {
        node_count: nodes.length,
        edge_count: edges.length,
        finding_nodes: findings.slice(0, 8).length,
        endpoint_nodes: endpoints.slice(0, 6).length,
      },
    });
  } catch (err) {
    logger.error({ err }, "Attack surface error");
    res.status(500).json({ error: "Internal server error" });
  }
});


function formatFinding(f: Record<string, unknown>) {
  const redacted = redactObject(f, FINDING_SENSITIVE_FIELDS);
  const cweId = String(redacted["cwe_id"] ?? "");
  const complianceTags = cweId ? getComplianceTags(cweId) : (redacted["compliance_tags"] ?? []);
  const createdAt = redacted["created_at"] as Date | string | null;
  const daysOpen = createdAt
    ? Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000)
    : null;
  return {
    id: String(redacted["_id"] ?? ""),
    scan_job_id: redacted["scan_job_id"] ? String(redacted["scan_job_id"]) : null,
    title: redacted["title"] ?? "Untitled",
    category: redacted["category"] ?? "",
    severity: redacted["severity"] ?? "low",
    validation_status: redacted["validation_status"] ?? "needs_review",
    confidence: redacted["confidence"] ?? 0,
    endpoint: redacted["endpoint"] ?? "",
    description: redacted["description"] ?? "",
    evidence: redacted["evidence"] ?? null,
    recommended_fix: redacted["recommended_fix"] ?? null,
    cvss_score: redacted["cvss_score"] ?? null,
    cwe_id: redacted["cwe_id"] ?? null,
    risk_score: redacted["risk_score"] ?? 0,
    scanner_name: redacted["scanner_name"] ?? "",
    created_at: redacted["created_at"] ?? null,
    target_url: redacted["target_url"] ?? null,
    compliance_tags: complianceTags,
    days_open: daysOpen,
    is_duplicate: redacted["is_duplicate"] ?? false,
    duplicate_of: redacted["duplicate_of"] ?? null,
    retest_status: redacted["retest_status"] ?? null,
    assigned_to: redacted["assigned_to"] ?? null,
    notes: redacted["notes"] ?? null,
    fp_reason: redacted["fp_reason"] ?? null,
  };
}

// Pause a running scan
router.post("/scan-jobs/:id/pause", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const result = await col("scan_jobs").findOneAndUpdate(
      { _id: new ObjectId(id), status: "running" } as Record<string, unknown>,
      { $set: { status: "paused", updated_at: new Date() } } as Record<string, unknown>,
      { returnDocument: "after" }
    );
    if (!result) return res.status(404).json({ error: "Scan not found or not running" });
    res.json({ ok: true, status: "paused" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Resume a paused scan
router.post("/scan-jobs/:id/resume", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const result = await col("scan_jobs").findOneAndUpdate(
      { _id: new ObjectId(id), status: "paused" } as Record<string, unknown>,
      { $set: { status: "running", updated_at: new Date() } } as Record<string, unknown>,
      { returnDocument: "after" }
    );
    if (!result) return res.status(404).json({ error: "Scan not found or not paused" });
    res.json({ ok: true, status: "running" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /scan-jobs/:id — Abort/cancel a running scan
router.delete("/scan-jobs/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    if (!["running", "queued", "pending"].includes(String(scan["status"] ?? ""))) {
      return res.status(400).json({ error: "Scan is not running or queued" });
    }
    // Set abort flag in Redis for the scanner to pick up
    try {
      const { getRedis } = await import("../lib/redis");
      await getRedis().set(`scan:abort:${id}`, "1", "EX", 300);
    } catch { /* non-fatal if Redis unavailable */ }
    // Update status immediately
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { status: "cancelled", cancelled_at: new Date(), updated_at: new Date() } }
    );
    await auditFromReq(req, "scan.abort", "scan_jobs", id);
    res.json({ ok: true, message: "Scan abort requested" });
  } catch (err) {
    logger.error({ err }, "Scan abort error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /scan-jobs/:id/progress — SSE stream for real-time scan progress
router.get("/scan-jobs/:id/progress", requireAuth, async (req, res) => {
  const { id } = req.params;
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  let closed = false;
  const send = (data: Record<string, unknown>) => {
    if (!closed) res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  const interval = setInterval(async () => {
    try {
      const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
      if (!scan) { clearInterval(interval); res.end(); return; }
      send({
        status: scan["status"],
        progress: scan["progress"] ?? 0,
        modules_total: scan["modules_total"] ?? 0,
        modules_done: scan["modules_done"] ?? 0,
        current_module: scan["current_module"] ?? null,
        findings_count: scan["findings_count"] ?? 0,
        updated_at: scan["updated_at"],
      });
      if (["completed", "failed", "cancelled"].includes(String(scan["status"] ?? ""))) {
        clearInterval(interval);
        send({ done: true, status: scan["status"] });
        res.end();
      }
    } catch { clearInterval(interval); res.end(); }
  }, 2000);

  req.on("close", () => { closed = true; clearInterval(interval); });
});

// PATCH /scan-jobs/:id/priority — Set scan priority (admin)
router.patch("/scan-jobs/:id/priority", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { priority } = req.body as { priority?: number };
    if (priority === undefined || priority < 1 || priority > 10) {
      return res.status(400).json({ error: "priority must be 1-10 (10 = highest)" });
    }
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { priority, updated_at: new Date() } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /scan-jobs/bulk — Launch scans for multiple targets at once
router.post("/scan-jobs/bulk", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string; role?: string };
    const { target_urls, profile, options } = req.body as {
      target_urls?: string[];
      profile?: string;
      options?: Record<string, unknown>;
    };
    if (!target_urls || !Array.isArray(target_urls) || target_urls.length === 0) {
      return res.status(400).json({ error: "target_urls array is required" });
    }
    if (target_urls.length > 20) {
      return res.status(400).json({ error: "Cannot bulk-scan more than 20 targets at once" });
    }
    // Basic URL validation
    const validUrls = target_urls.filter(u => { try { new URL(u); return true; } catch { return false; } });
    if (validUrls.length === 0) return res.status(400).json({ error: "No valid URLs provided" });

    const results: Array<{ url: string; scan_id: string }> = [];
    for (const url of validUrls) {
      const ins = await col("scan_jobs").insertOne({
        target_url: url,
        status: "queued",
        profile: profile ?? "standard",
        options: options ?? {},
        user_id: sess.userId,
        priority: 5,
        progress: 0,
        modules_total: 0,
        modules_done: 0,
        findings_count: 0,
        created_at: new Date(),
        updated_at: new Date(),
      });
      results.push({ url, scan_id: String(ins.insertedId) });
    }
    await auditFromReq(req, "scan.bulk_launch", "scan_jobs", results.map(r => r.scan_id).join(","), { count: results.length });
    res.status(201).json({ ok: true, scans: results });
  } catch (err) {
    logger.error({ err }, "Bulk scan launch error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /scan-jobs/queue — View the scan queue with priority ordering (admin)
router.get("/scan-jobs/queue", requireAdmin, async (_req, res) => {
  try {
    const queued = await col("scan_jobs").find({ status: { $in: ["queued", "pending"] } } as Record<string, unknown>)
      .sort({ priority: -1, created_at: 1 })
      .limit(50)
      .toArray() as Array<Record<string, unknown>>;
    res.json(queued.map(s => ({
      id: String(s["_id"]),
      target_url: s["target_url"],
      status: s["status"],
      priority: s["priority"] ?? 5,
      created_at: s["created_at"],
      user_id: s["user_id"],
    })));
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/scan-jobs/:id/pause", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { redisSet } = await import("../lib/redis");
    await redisSet(`scan:paused:${id}`, "1", 24 * 3600);
    await col("scan_jobs").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: { paused: true, paused_at: new Date() } });
    res.json({ ok: true, status: "paused" });
  } catch (err) {
    res.status(500).json({ error: "Failed to pause scan" });
  }
});

router.patch("/scan-jobs/:id/resume", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { redisDel } = await import("../lib/redis");
    await redisDel(`scan:paused:${id}`);
    await col("scan_jobs").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: { paused: false, resumed_at: new Date() } });
    res.json({ ok: true, status: "running" });
  } catch (err) {
    res.status(500).json({ error: "Failed to resume scan" });
  }
});

export { formatFinding };
export default router;
