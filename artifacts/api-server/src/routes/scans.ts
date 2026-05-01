import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

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

    const query: Record<string, unknown> = {};
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

    const now = new Date();
    const insert = await col("scan_jobs").insertOne({
      target_url: body.target_url,
      scan_profile: body.scan_profile,
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

    // Simulate scan progression in background
    simulateScan(String(insert.insertedId), body.scan_profile, engines.length);

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

// ---------------------------------------------------------------------------
// Scan simulation
// ---------------------------------------------------------------------------
function simulateScan(jobId: string, profile: string, engineCount: number) {
  const totalMs = profile === "quick" ? 15000 : profile === "standard" ? 30000 : 50000;
  const steps = 10;
  const stepMs = totalMs / steps;

  let step = 0;

  const interval = setInterval(async () => {
    step++;
    const progress = Math.round((step / steps) * 100);

    if (step === 1) {
      await col("scan_jobs").updateOne(
        { _id: new ObjectId(jobId) } as Record<string, unknown>,
        { $set: { status: "running", started_at: new Date(), progress } }
      );
      await col("activity_events").insertOne({
        type: "scan_started",
        message: `Scan started`,
        timestamp: new Date(),
        scan_job_id: new ObjectId(jobId),
        severity: null,
      });
    } else if (step < steps) {
      await col("scan_jobs").updateOne(
        { _id: new ObjectId(jobId) } as Record<string, unknown>,
        { $set: { progress } }
      );
    } else {
      clearInterval(interval);
      await completeScan(jobId);
    }
  }, stepMs);
}

async function completeScan(jobId: string) {
  try {
    const job = (await col("scan_jobs").findOne({ _id: new ObjectId(jobId) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!job) return;

    const targetUrl = job["target_url"] as string;
    const profile = job["scan_profile"] as string;

    const findingTemplates = [
      { title: "Missing Content-Security-Policy Header", severity: "high", category: "Security Headers", cvss: 7.4, cwe: "CWE-693", scanner: "header_scan", fix: "Add a Content-Security-Policy header to all responses." },
      { title: "Cookie Missing HttpOnly Flag", severity: "medium", category: "Session Management", cvss: 5.0, cwe: "CWE-1004", scanner: "cookie_checker", fix: "Set HttpOnly flag on all cookies." },
      { title: "Missing HSTS Header", severity: "medium", category: "TLS/Transport", cvss: 5.3, cwe: "CWE-319", scanner: "tls_check", fix: "Add Strict-Transport-Security header." },
      { title: "Overly Permissive CORS Policy", severity: "high", category: "CORS", cvss: 7.5, cwe: "CWE-346", scanner: "cors_check", fix: "Restrict CORS origins to trusted domains." },
      { title: "Reflected XSS in Search Parameter", severity: "high", category: "XSS", cvss: 7.8, cwe: "CWE-79", scanner: "xss_validator", fix: "Encode all user input before rendering." },
      { title: "SQL Injection Vulnerability", severity: "critical", category: "Injection", cvss: 9.8, cwe: "CWE-89", scanner: "sqli_scanner", fix: "Use parameterized queries." },
    ];

    const numFindings = profile === "quick" ? 3 : profile === "standard" ? 5 : 8;
    const selected = findingTemplates.slice(0, numFindings);

    let critCount = 0, highCount = 0, medCount = 0, lowCount = 0, infoCount = 0;
    const endpoints = ["/api/users", "/search", "/login", "/api/data", "/admin"];

    for (const tmpl of selected) {
      const sev = tmpl.severity as "critical" | "high" | "medium" | "low" | "info";
      if (sev === "critical") critCount++;
      else if (sev === "high") highCount++;
      else if (sev === "medium") medCount++;
      else if (sev === "low") lowCount++;
      else infoCount++;

      const findInsert = await col("findings").insertOne({
        scan_job_id: new ObjectId(jobId),
        title: tmpl.title,
        category: tmpl.category,
        severity: sev,
        validation_status: "real",
        confidence: 0.85 + Math.random() * 0.15,
        endpoint: endpoints[Math.floor(Math.random() * endpoints.length)],
        description: `${tmpl.title} was detected during the security scan of ${targetUrl}.`,
        evidence: `HTTP/1.1 200 OK\nServer: nginx\n[Evidence captured at ${new Date().toISOString()}]`,
        recommended_fix: tmpl.fix,
        cvss_score: tmpl.cvss,
        cwe_id: tmpl.cwe,
        risk_score: sev === "critical" ? 90 : sev === "high" ? 70 : sev === "medium" ? 45 : 20,
        scanner_name: tmpl.scanner,
        created_at: new Date(),
        target_url: targetUrl,
      });

      await col("activity_events").insertOne({
        type: "finding_created",
        message: `${sev.toUpperCase()} finding: ${tmpl.title}`,
        timestamp: new Date(),
        scan_job_id: new ObjectId(jobId),
        severity: sev,
      });

      // Create remediation for critical/high
      if (sev === "critical" || sev === "high") {
        await col("remediations").insertOne({
          finding_id: findInsert.insertedId,
          scan_job_id: new ObjectId(jobId),
          title: `Fix: ${tmpl.title}`,
          description: `Remediation task for ${tmpl.title}`,
          patch_snippet: tmpl.fix,
          status: "pending",
          created_at: new Date(),
          updated_at: new Date(),
        });
      }
    }

    const riskScore = Math.min(100, critCount * 25 + highCount * 15 + medCount * 8);
    const aiSummary = `Security scan of ${targetUrl} completed. Found ${numFindings} vulnerabilities including ${critCount} critical and ${highCount} high severity issues. Immediate attention required for critical findings. Risk score: ${riskScore}/100.`;

    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      {
        $set: {
          status: "completed",
          progress: 100,
          completed_at: new Date(),
          findings_count: selected.length,
          critical_count: critCount,
          high_count: highCount,
          medium_count: medCount,
          low_count: lowCount,
          info_count: infoCount,
          risk_score: riskScore,
          ai_summary: aiSummary,
        },
      }
    );

    await col("activity_events").insertOne({
      type: "scan_completed",
      message: `Scan completed: ${numFindings} findings on ${targetUrl}`,
      timestamp: new Date(),
      scan_job_id: new ObjectId(jobId),
      severity: null,
    });
  } catch (err) {
    logger.error({ err }, "Error completing scan simulation");
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      { $set: { status: "failed", error_message: "Scan simulation error" } }
    );
  }
}

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

export { formatFinding };
export default router;
