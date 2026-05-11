import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { formatFinding } from "./scans";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

// ── List findings ────────────────────────────────────────────────────────────

router.get("/findings", requireAuth, async (req, res) => {
  try {
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "20"));
    const severity = req.query["severity"] as string | undefined;
    const valStatus = req.query["validation_status"] as string | undefined;
    const search = req.query["search"] as string | undefined;
    const scanJobId = req.query["scan_job_id"] as string | undefined;
    const suppressFp = req.query["suppress_fp"] === "true";

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const query: Record<string, unknown> = {};
    if (session.role !== "admin") query.user_id = session.userId;
    if (severity) query["severity"] = severity;
    if (valStatus) query["validation_status"] = valStatus;
    if (search) {
      query["$or"] = [
        { title: { $regex: search, $options: "i" } },
        { endpoint: { $regex: search, $options: "i" } },
        { cwe_id: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }
    if (scanJobId && ObjectId.isValid(scanJobId)) query["scan_job_id"] = new ObjectId(scanJobId);
    if (suppressFp) query["validation_status"] = { $ne: "false_positive" };

    const all = (await col("findings").find(query).sort({ created_at: -1 }).toArray()) as Array<Record<string, unknown>>;
    const total = all.length;
    const items = all.slice((page - 1) * pageSize, page * pageSize).map(formatFinding);

    res.json({ items, total, page, page_size: pageSize, total_pages: Math.ceil(total / pageSize) });
  } catch (err) {
    logger.error({ err }, "List findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Get single finding ───────────────────────────────────────────────────────

router.get("/findings/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const finding = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (session.role !== "admin" && finding.user_id !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    res.json(formatFinding(finding));
  } catch (err) {
    logger.error({ err }, "Get finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Update finding (validation status, notes) ────────────────────────────────

router.patch("/findings/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const body = req.body as {
      validation_status?: string;
      notes?: string;
      fp_reason?: string;
      suppress_globally?: boolean;
    };

    const allowed = ["confirmed", "false_positive", "needs_review", "real", "informational"];
    const updates: Record<string, unknown> = { updated_at: new Date() };
    if (body.validation_status && allowed.includes(body.validation_status)) {
      updates["validation_status"] = body.validation_status;
    }
    if (body.notes !== undefined) updates["notes"] = body.notes;
    if (body.fp_reason !== undefined) updates["fp_reason"] = body.fp_reason;

    await col("findings").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: updates });

    // If marking as false positive + suppress globally, add to suppression list
    if (body.validation_status === "false_positive" && body.suppress_globally) {
      const finding = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
      if (finding) {
        const targetUrl = String(finding["target_url"] ?? "");
        let domain = "";
        try { domain = new URL(targetUrl).hostname; } catch { domain = targetUrl; }

        const suppressKey = `${domain}||${finding["title"]}||${finding["endpoint"]}`;
        await col("fp_suppressions").updateOne(
          { key: suppressKey } as Record<string, unknown>,
          {
            $set: {
              key: suppressKey,
              domain,
              title: finding["title"],
              endpoint: finding["endpoint"],
              category: finding["category"],
              reason: body.fp_reason ?? "Manually marked as false positive",
              created_by: (req.session as Record<string, unknown>)["username"] ?? "unknown",
              updated_at: new Date(),
            },
            $setOnInsert: { created_at: new Date() },
          },
          { upsert: true }
        );
      }
    }

    // If un-marking as false positive, remove suppression if exists
    if (body.validation_status && body.validation_status !== "false_positive") {
      const finding = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
      if (finding) {
        let domain = "";
        try { domain = new URL(String(finding["target_url"] ?? "")).hostname; } catch { domain = String(finding["target_url"] ?? ""); }
        const suppressKey = `${domain}||${finding["title"]}||${finding["endpoint"]}`;
        await col("fp_suppressions").deleteOne({ key: suppressKey } as Record<string, unknown>);
      }
    }

    const updated = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
    res.json(formatFinding(updated));
  } catch (err) {
    logger.error({ err }, "Update finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── List false-positive suppressions ─────────────────────────────────────────

router.get("/fp-suppressions", requireAuth, async (req, res) => {
  try {
    const domain = req.query["domain"] as string | undefined;
    const query: Record<string, unknown> = {};
    if (domain) query["domain"] = domain;
    const suppressions = await col("fp_suppressions").find(query).sort({ updated_at: -1 }).toArray();
    res.json(suppressions.map((s) => ({
      id: String(s["_id"]),
      domain: s["domain"],
      title: s["title"],
      endpoint: s["endpoint"],
      category: s["category"],
      reason: s["reason"],
      created_by: s["created_by"],
      created_at: s["created_at"],
    })));
  } catch (err) {
    logger.error({ err }, "List FP suppressions error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/fp-suppressions/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    await col("fp_suppressions").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete FP suppression error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Scan diff ─────────────────────────────────────────────────────────────────

router.get("/scan-jobs/:id/diff", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const currentScan = (await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!currentScan) return res.status(404).json({ error: "Scan not found" });

    const targetUrl = String(currentScan["target_url"] ?? "");
    let domain = "";
    try { domain = new URL(targetUrl).hostname; } catch { domain = targetUrl; }

    // Find previous completed scan on same target (before this one)
    const prevScan = (await col("scan_jobs")
      .find({
        target_url: { $regex: domain, $options: "i" },
        status: "completed",
        _id: { $ne: new ObjectId(id) },
        created_at: { $lt: currentScan["created_at"] },
      } as Record<string, unknown>)
      .sort({ created_at: -1 })
      .limit(1)
      .toArray())[0] as Record<string, unknown> | undefined;

    if (!prevScan) {
      return res.json({
        has_previous: false,
        new_findings: [],
        fixed_findings: [],
        recurring_findings: [],
        stats: { new: 0, fixed: 0, recurring: 0 },
      });
    }

    // Load findings for both scans
    const [currentFindings, prevFindings] = await Promise.all([
      col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
      col("findings").find({ scan_job_id: prevScan["_id"] } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);

    // Key = title + endpoint (normalized)
    const key = (f: Record<string, unknown>) => `${String(f["title"])}||${String(f["endpoint"])}`;

    const currentKeys = new Set(currentFindings.map(key));
    const prevKeys = new Set(prevFindings.map(key));

    const newFindings = currentFindings.filter((f) => !prevKeys.has(key(f)));
    const fixedFindings = prevFindings.filter((f) => !currentKeys.has(key(f)));
    const recurringFindings = currentFindings.filter((f) => prevKeys.has(key(f)));

    res.json({
      has_previous: true,
      previous_scan_id: String(prevScan["_id"]),
      previous_scan_date: prevScan["completed_at"] ?? prevScan["created_at"],
      new_findings: newFindings.map(formatFinding),
      fixed_findings: fixedFindings.map(formatFinding),
      recurring_findings: recurringFindings.map(formatFinding),
      stats: {
        new: newFindings.length,
        fixed: fixedFindings.length,
        recurring: recurringFindings.length,
      },
    });
  } catch (err) {
    logger.error({ err }, "Scan diff error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Export findings ───────────────────────────────────────────────────────────

router.get("/findings/export/:format", requireAuth, async (req, res) => {
  try {
    const { format: fmt } = req.params;
    const scanJobId = req.query["scan_job_id"] as string | undefined;
    const severity = req.query["severity"] as string | undefined;

    const query: Record<string, unknown> = {};
    if (scanJobId && ObjectId.isValid(scanJobId)) query["scan_job_id"] = new ObjectId(scanJobId);
    if (severity) query["severity"] = severity;

    const findings = (await col("findings").find(query).sort({ created_at: -1 }).limit(5000).toArray()) as Array<Record<string, unknown>>;
    const formatted = findings.map(formatFinding);

    if (fmt === "json") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="findings-${Date.now()}.json"`);
      return res.json(formatted);
    }

    if (fmt === "csv") {
      const headers = ["id", "title", "severity", "category", "endpoint", "cvss_score", "cwe_id", "validation_status", "scanner_name", "created_at"];
      const escape = (v: unknown) => {
        const s = String(v ?? "").replace(/"/g, '""');
        return s.includes(",") || s.includes("\n") || s.includes('"') ? `"${s}"` : s;
      };
      const rows = [headers.join(","), ...formatted.map((f) => headers.map((h) => escape((f as Record<string, unknown>)[h])).join(","))];
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="findings-${Date.now()}.csv"`);
      return res.send(rows.join("\n"));
    }

    return res.status(400).json({ error: "Unsupported format. Use: json, csv" });
  } catch (err) {
    logger.error({ err }, "Export findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scan-jobs/export/:format", requireAuth, async (req, res) => {
  try {
    const { format: fmt } = req.params;
    const scans = await col("scan_jobs").find({}).sort({ created_at: -1 }).limit(1000).toArray() as Array<Record<string, unknown>>;

    if (fmt === "json") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="scans-${Date.now()}.json"`);
      return res.json(scans.map((s) => ({
        id: String(s["_id"]), target_url: s["target_url"], scan_profile: s["scan_profile"],
        status: s["status"], risk_score: s["risk_score"], findings_count: s["findings_count"],
        created_at: s["created_at"], completed_at: s["completed_at"],
      })));
    }
    if (fmt === "csv") {
      const headers = ["id", "target_url", "scan_profile", "status", "risk_score", "findings_count", "critical_count", "high_count", "created_at"];
      const escape = (v: unknown) => { const s = String(v ?? "").replace(/"/g, '""'); return s.includes(",") || s.includes('"') ? `"${s}"` : s; };
      const rows = [headers.join(","), ...scans.map((s) => headers.map((h) => escape(h === "id" ? String(s["_id"]) : s[h])).join(","))];
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="scans-${Date.now()}.csv"`);
      return res.send(rows.join("\n"));
    }
    return res.status(400).json({ error: "Unsupported format" });
  } catch (err) {
    logger.error({ err }, "Export scans error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Cancel scan ───────────────────────────────────────────────────────────────

router.post("/scan-jobs/:id/cancel", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const job = (await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!job) return res.status(404).json({ error: "Scan not found" });
    if (!["queued", "running"].includes(String(job["status"]))) {
      return res.status(400).json({ error: "Only queued or running scans can be cancelled" });
    }

    await col("scan_jobs").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { status: "cancelled", completed_at: new Date() } }
    );

    // Signal the scanner via a shared cancellation flag in the job document
    const { scanEvents } = await import("../services/scanner/index");
    scanEvents.emit(`cancel:${id}`);

    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Cancel scan error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── CVE enrichment for a finding ─────────────────────────────────────────────

router.get("/findings/:id/cve", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const finding = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Not found" });

    const cweId = String(finding["cwe_id"] ?? "").replace("CWE-", "");
    const title = String(finding["title"] ?? "");

    // Try NVD API for CVEs related to CWE or keywords
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-${cweId}&resultsPerPage=5`;
    let cves: Array<Record<string, unknown>> = [];

    try {
      const nvdRes = await fetch(nvdUrl, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(8000),
      });
      if (nvdRes.ok) {
        const data = await nvdRes.json() as Record<string, unknown>;
        const vulns = (data["vulnerabilities"] as Array<Record<string, unknown>>) ?? [];
        cves = vulns.slice(0, 5).map((v: Record<string, unknown>) => {
          const cve = v["cve"] as Record<string, unknown>;
          const metrics = (cve["metrics"] as Record<string, unknown>) ?? {};
          const cvssV3 = ((metrics["cvssMetricV31"] as Array<Record<string, unknown>>) ?? [])[0]?.["cvssData"] as Record<string, unknown> | undefined;
          const descriptions = (cve["descriptions"] as Array<Record<string, unknown>>) ?? [];
          const enDesc = descriptions.find((d) => d["lang"] === "en");
          return {
            id: cve["id"],
            description: enDesc?.["value"] ?? "No description",
            cvss_score: cvssV3?.["baseScore"] ?? null,
            cvss_severity: cvssV3?.["baseSeverity"] ?? null,
            published: cve["published"],
            url: `https://nvd.nist.gov/vuln/detail/${cve["id"]}`,
          };
        });
      }
    } catch {
      // NVD may be unavailable — return cached data if any
    }

    // Update finding with CVE enrichment
    if (cves.length > 0) {
      await col("findings").updateOne(
        { _id: new ObjectId(id) } as Record<string, unknown>,
        { $set: { cve_enrichment: cves, cve_enriched_at: new Date() } }
      );
    }

    res.json({ cves, cwe_id: finding["cwe_id"], title });
  } catch (err) {
    logger.error({ err }, "CVE enrichment error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Kill chain correlation ─────────────────────────────────────────────────────

router.get("/scan-jobs/:id/kill-chains", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const findings = (await col("findings")
      .find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>)
      .toArray()) as Array<Record<string, unknown>>;

    const chains = detectKillChains(findings);
    res.json(chains);
  } catch (err) {
    logger.error({ err }, "Kill chain error");
    res.status(500).json({ error: "Internal server error" });
  }
});

interface KillChain {
  id: string;
  name: string;
  description: string;
  severity: string;
  finding_ids: string[];
  finding_titles: string[];
  attack_path: string[];
}

function detectKillChains(findings: Array<Record<string, unknown>>): KillChain[] {
  const chains: KillChain[] = [];
  const cats = new Set(findings.map((f) => String(f["category"]).toLowerCase()));
  const titles = findings.map((f) => String(f["title"]).toLowerCase());
  const hasCat = (s: string) => [...cats].some((c) => c.includes(s));
  const hasTitle = (s: string) => titles.some((t) => t.includes(s));
  const findingsByTitle = (s: string) => findings.filter((f) => String(f["title"]).toLowerCase().includes(s));
  const findingsByCat = (s: string) => findings.filter((f) => String(f["category"]).toLowerCase().includes(s));

  // Chain 1: SSRF → Cloud Metadata → RCE
  if (hasTitle("ssrf") || hasCat("ssrf")) {
    const ssrfF = [...findingsByTitle("ssrf"), ...findingsByCat("ssrf")];
    const metaF = findings.filter((f) => String(f["title"]).toLowerCase().includes("metadata") || String(f["evidence"] ?? "").includes("169.254.169.254"));
    if (ssrfF.length > 0 && metaF.length > 0) {
      const all = [...ssrfF, ...metaF];
      chains.push({
        id: "ssrf-cloud-takeover",
        name: "SSRF → Cloud Metadata → Credential Theft",
        description: "Server-Side Request Forgery combined with exposed cloud metadata endpoint enables theft of IAM credentials, potentially leading to full cloud account takeover.",
        severity: "critical",
        finding_ids: all.map((f) => String(f["_id"])),
        finding_titles: all.map((f) => String(f["title"])),
        attack_path: ["Exploit SSRF to reach internal network", "Access cloud metadata at 169.254.169.254", "Steal IAM role credentials", "Escalate to cloud admin / data exfiltration"],
      });
    }
  }

  // Chain 2: SQLi → Auth Bypass → Privilege Escalation
  if ((hasTitle("sql") || hasCat("injection")) && (hasTitle("auth") || hasTitle("access"))) {
    const sqliF = findings.filter((f) => String(f["title"]).toLowerCase().includes("sql") || String(f["category"]).toLowerCase().includes("injection"));
    const authF = findings.filter((f) => String(f["category"]).toLowerCase().includes("auth") || String(f["title"]).toLowerCase().includes("auth bypass"));
    if (sqliF.length > 0 && authF.length > 0) {
      const all = [...sqliF.slice(0, 2), ...authF.slice(0, 2)];
      chains.push({
        id: "sqli-auth-bypass",
        name: "SQL Injection → Authentication Bypass → Data Exfiltration",
        description: "SQL injection vulnerability combined with authentication weaknesses enables bypassing login controls and extracting the full user database.",
        severity: "critical",
        finding_ids: all.map((f) => String(f["_id"])),
        finding_titles: all.map((f) => String(f["title"])),
        attack_path: ["Inject SQL payload into login form", "Bypass authentication check", "Enumerate users table", "Extract password hashes / PII"],
      });
    }
  }

  // Chain 3: XSS → Session Hijacking → Account Takeover
  if (hasTitle("xss") || hasTitle("cross-site scripting")) {
    const xssF = findings.filter((f) => String(f["title"]).toLowerCase().includes("xss") || String(f["title"]).toLowerCase().includes("cross-site"));
    const cookieF = findings.filter((f) => String(f["category"]).toLowerCase().includes("cookie") || String(f["title"]).toLowerCase().includes("httponly") || String(f["title"]).toLowerCase().includes("cookie"));
    const all = [...xssF.slice(0, 2), ...cookieF.slice(0, 2)];
    if (xssF.length > 0) {
      chains.push({
        id: "xss-session-hijack",
        name: "XSS → Session Hijacking → Account Takeover",
        description: "Cross-site scripting combined with insecure cookie settings allows an attacker to steal session tokens and take over victim accounts.",
        severity: "high",
        finding_ids: all.map((f) => String(f["_id"])),
        finding_titles: all.map((f) => String(f["title"])),
        attack_path: ["Inject malicious script via XSS", "Steal session cookie (missing HttpOnly flag)", "Replay session cookie to impersonate user", "Access account and sensitive data"],
      });
    }
  }

  // Chain 4: Open Redirect → Phishing → Credential Theft
  if (hasTitle("redirect") || hasTitle("open redirect")) {
    const redF = findings.filter((f) => String(f["title"]).toLowerCase().includes("redirect"));
    chains.push({
      id: "open-redirect-phishing",
      name: "Open Redirect → Phishing Campaign",
      description: "Open redirect from a trusted domain can be weaponized in phishing campaigns, making malicious links appear legitimate and bypassing email filters.",
      severity: "medium",
      finding_ids: redF.map((f) => String(f["_id"])),
      finding_titles: redF.map((f) => String(f["title"])),
      attack_path: ["Craft redirect URL using trusted domain", "Send phishing link via email/social engineering", "Victim clicks trusted domain link, redirected to attacker site", "Capture credentials on fake login page"],
    });
  }

  // Chain 5: Exposed Admin + Default Creds
  if (hasTitle("unauthenticated access") && (hasTitle("default credential") || hasTitle("rate limit"))) {
    const adminF = findings.filter((f) => String(f["title"]).toLowerCase().includes("unauthenticated"));
    const credF = findings.filter((f) => String(f["title"]).toLowerCase().includes("default") || String(f["title"]).toLowerCase().includes("rate limit"));
    const all = [...adminF.slice(0, 2), ...credF.slice(0, 2)];
    chains.push({
      id: "exposed-admin-brute",
      name: "Exposed Admin Panel → Brute Force → Full Compromise",
      description: "Exposed admin panel combined with missing rate limiting allows automated credential brute-forcing leading to full administrative compromise.",
      severity: "critical",
      finding_ids: all.map((f) => String(f["_id"])),
      finding_titles: all.map((f) => String(f["title"])),
      attack_path: ["Access exposed admin panel without authentication", "Brute-force credentials (no rate limiting)", "Log in as administrator", "Full application and data compromise"],
    });
  }

  return chains.filter((c) => c.finding_ids.length > 0);
}

// ── Retest finding ────────────────────────────────────────────────────────────
router.post("/findings/:id/retest", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string,unknown>) as Record<string,unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    const { runScanPipeline } = await import("../services/scanner/index");
    const insert = await col("scan_jobs").insertOne({
      target_url: finding["target_url"] ?? finding["endpoint"],
      scan_profile: "quick",
      status: "queued",
      progress: 0,
      created_at: new Date(),
      started_at: null, completed_at: null,
      findings_count: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0,
      risk_score: 0, ai_summary: null,
      validation_enabled: true, fuzzing_enabled: false, bug_bounty_mode: false,
      authorization_acknowledged: true,
      retest_for_finding_id: new ObjectId(id),
      error_message: null,
    });

    await col("findings").updateOne({ _id: new ObjectId(id) } as Record<string,unknown>, { $set: { retest_scan_id: insert.insertedId, retest_status: "pending", retest_requested_at: new Date() } });

    runScanPipeline({ jobId: String(insert.insertedId), targetUrl: String(finding["target_url"] ?? finding["endpoint"]), profile: "quick", validationEnabled: true, fuzzingEnabled: false, bugBountyMode: false }).catch(() => {});
    res.json({ ok: true, scan_id: String(insert.insertedId) });
  } catch(err) { logger.error({err},"retest error"); res.status(500).json({ error: "Internal server error" }); }
});

// ── Assign finding ────────────────────────────────────────────────────────────
router.post("/findings/:id/assign", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const { assignee } = req.body as { assignee?: string };
    await col("findings").updateOne({ _id: new ObjectId(id) } as Record<string,unknown>, { $set: { assignee: assignee ?? null, assigned_at: assignee ? new Date() : null } });
    res.json({ ok: true });
  } catch(err) { logger.error({err},"assign error"); res.status(500).json({ error: "Internal server error" }); }
});

export default router;
