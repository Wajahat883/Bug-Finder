import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { runScanPipeline } from "../services/scanner/index";

const router = Router();

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
    const all = (await col_.find(query).sort({ created_at: -1 }).toArray()) as Array<Record<string, unknown>>;
    const total = all.length;
    const items = all.slice((page - 1) * pageSize, page * pageSize).map(formatJob);

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
    };

    if (!body.target_url || !body.scan_profile) {
      return res.status(400).json({ error: "target_url and scan_profile are required" });
    }
    if (!body.authorization_acknowledged) {
      return res.status(400).json({ error: "Authorization must be acknowledged before scanning" });
    }

    const engines = body.scanner_engines ?? ["tls_check", "header_scan", "cors_check", "cookie_checker"];
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
      validation_enabled: body.validation_enabled ?? false,
      fuzzing_enabled: body.fuzzing_enabled ?? false,
      bug_bounty_mode: body.bug_bounty_mode ?? false,
      authorization_acknowledged: body.authorization_acknowledged,
      authorization_note: body.authorization_note ?? null,
      scanner_engines: engines,
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

    // Run real scan pipeline in background
    runScanPipeline({
      jobId: String(insert.insertedId),
      targetUrl: body.target_url,
      profile: body.scan_profile as "quick" | "standard" | "deep",
      validationEnabled: body.validation_enabled ?? false,
      fuzzingEnabled: body.fuzzing_enabled ?? false,
      bugBountyMode: body.bug_bounty_mode ?? false,
    });

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
    if (session.role !== "admin" && job.user_id !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    res.json(formatJob(job));
  } catch (err) {
    logger.error({ err }, "Get scan job error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/scan-jobs/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    await col("scan_jobs").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    await col("findings").deleteOne({ scan_job_id: new ObjectId(id) } as Record<string, unknown>);
    res.status(204).send();
  } catch (err) {
    logger.error({ err }, "Delete scan job error");
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
  return {
    id: String(f["_id"]),
    scan_job_id: f["scan_job_id"] ? String(f["scan_job_id"]) : null,
    title: f["title"],
    category: f["category"],
    severity: f["severity"],
    validation_status: f["validation_status"],
    confidence: f["confidence"],
    endpoint: f["endpoint"],
    description: f["description"],
    evidence: f["evidence"] ?? null,
    recommended_fix: f["recommended_fix"] ?? null,
    cvss_score: f["cvss_score"] ?? null,
    cwe_id: f["cwe_id"] ?? null,
    risk_score: f["risk_score"] ?? 0,
    scanner_name: f["scanner_name"],
    created_at: f["created_at"],
    target_url: f["target_url"] ?? null,
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
    res.json({ ok: true });
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
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

export { formatFinding };
export default router;
