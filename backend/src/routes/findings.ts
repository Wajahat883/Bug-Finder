import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { formatFinding } from "./scans";
import { requireAuth } from "../middlewares/rbac";
import { getComplianceTags } from "../lib/compliance-map";
import { engagementScopeFilter } from "../middlewares/resource-rbac";
import { logAudit, auditFromReq } from "../lib/audit";
import { withTenant } from "../middlewares/tenant";
import { sendIntegrationAlerts } from "../services/alerts";

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
    let query: Record<string, unknown> = withTenant({}, (req as unknown as { tenantId?: string }).tenantId);
    if (session.role !== "admin") query["user_id"] = session.userId ?? null;
    // Apply engagement-level RBAC scope filter
    const scopeFilter = engagementScopeFilter(req);
    if (scopeFilter) Object.assign(query, scopeFilter);
    if (severity) query["severity"] = severity;
    if (valStatus) query["validation_status"] = valStatus;
    if (search) {
      const safeSearch = String(search);
      query["$or"] = [
        { title: { $regex: safeSearch, $options: "i" } },
        { endpoint: { $regex: safeSearch, $options: "i" } },
        { cwe_id: { $regex: safeSearch, $options: "i" } },
        { category: { $regex: safeSearch, $options: "i" } },
      ];
    }
    if (scanJobId && ObjectId.isValid(scanJobId)) query["scan_job_id"] = new ObjectId(scanJobId);
    if (suppressFp) query["validation_status"] = { $ne: "false_positive" };

    const [items, total] = await Promise.all([
      col("findings")
        .find(query)
        .sort({ created_at: -1 })
        .skip((page - 1) * pageSize)
        .limit(pageSize)
        .toArray()
        .then(rows => (rows as Array<Record<string, unknown>>).map(formatFinding)),
      col("findings").countDocuments(query as Record<string, unknown>),
    ]);

    res.json({ items, total, page, page_size: pageSize, total_pages: Math.ceil(total / pageSize) });
  } catch (err) {
    logger.error({ err }, "List findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Static-path GET routes (must precede /findings/:id to avoid shadowing) ───

// GET /findings/enrich-all — admin bulk CVE enrichment (defined early to avoid shadowing by :id)
router.get("/findings/enrich-all", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (session.role !== "admin") return res.status(403).json({ error: "Admin only" });
    const pending = await col("findings")
      .find({ cve_id: { $exists: true, $ne: null }, epss_score: { $exists: false } } as Record<string, unknown>)
      .project({ _id: 1, cve_id: 1 })
      .limit(500)
      .toArray() as Array<Record<string, unknown>>;
    for (const f of pending) {
      const fid = String(f["_id"]);
      const cveId = String(f["cve_id"] ?? "");
      if (cveId) enrichFindingWithCVE(fid, cveId).catch(() => {});
    }
    res.json({ ok: true, queued: pending.length });
  } catch (err) {
    logger.error({ err }, "Bulk CVE enrichment error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /findings/saved-filters
router.get("/findings/saved-filters", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const filters = await col("saved_filters").find({ user_id: sess.userId, resource: "findings" } as Record<string, unknown>).sort({ created_at: -1 }).toArray();
    res.json(filters.map(f => ({ id: String(f["_id"]), name: f["name"], filters: f["filters"], created_at: f["created_at"] })));
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /findings/saved-filters
router.post("/findings/saved-filters", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const { name, filters } = req.body as { name?: string; filters?: Record<string, unknown> };
    if (!name || !filters) return res.status(400).json({ error: "name and filters are required" });
    const insert = await col("saved_filters").insertOne({ user_id: sess.userId, resource: "findings", name, filters, created_at: new Date() });
    res.status(201).json({ id: String(insert.insertedId), name, filters });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Get single finding ───────────────────────────────────────────────────────

router.get("/findings/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};
    const finding = (await col("findings").findOne({ _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });
    res.json(formatFinding(finding));
  } catch (err) {
    logger.error({ err }, "Get finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── PATCH /findings/bulk (must precede /findings/:id) ────────────────────────

router.patch("/findings/bulk", requireAuth, async (req, res) => {
  try {
    const { ids, action, assignee_id, status, risk_accepted, risk_reason } = req.body as {
      ids?: string[];
      action?: string;
      assignee_id?: string;
      status?: string;
      risk_accepted?: boolean;
      risk_reason?: string;
    };
    if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: "ids array is required" });
    if (ids.length > 100) return res.status(400).json({ error: "Cannot bulk-update more than 100 findings at once" });

    const objectIds = ids.map(id => new ObjectId(id));
    const update: Record<string, unknown> = { updated_at: new Date() };

    if (action === "assign" && assignee_id) {
      update["assignee_id"] = assignee_id;
    } else if (action === "status" && status) {
      update["status"] = status;
    } else if (action === "accept_risk") {
      update["risk_accepted"] = true;
      update["risk_accepted_at"] = new Date();
      update["risk_reason"] = risk_reason ?? "Risk accepted via bulk operation";
      update["triage_status"] = "accepted";
    } else if (action === "retest") {
      update["retest_status"] = "pending";
    } else if (action === "delete") {
      await col("findings").updateMany(
        { _id: { $in: objectIds } } as Record<string, unknown>,
        { $set: { deleted: true, deleted_at: new Date() } }
      );
      await auditFromReq(req, "finding.bulk_delete", "findings", ids.join(","), { count: ids.length });
      return res.json({ ok: true, affected: ids.length });
    } else {
      return res.status(400).json({ error: "action must be assign, status, accept_risk, retest, or delete" });
    }

    await col("findings").updateMany(
      { _id: { $in: objectIds } } as Record<string, unknown>,
      { $set: update }
    );
    await auditFromReq(req, `finding.bulk_${action}`, "findings", ids.join(","), { count: ids.length, action });
    res.json({ ok: true, affected: ids.length });
  } catch (err) {
    logger.error({ err }, "Bulk findings update error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Update finding (validation status, notes) ────────────────────────────────

router.patch("/findings/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
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
      if (body.validation_status === "confirmed" || body.validation_status === "real") {
        // Track resolved_at when marking as resolved
      }
    }
    if (body.notes !== undefined) updates["notes"] = body.notes;
    if (body.fp_reason !== undefined) updates["fp_reason"] = body.fp_reason;

    // Track status history
    const session = (req as unknown as { session: Record<string, unknown> & { userId?: string; role?: string } }).session;
    const ownerFilter = session["role"] !== "admin" ? { user_id: session["userId"] ?? null } : {};
    const existing = (await col("findings").findOne({ _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>)) as Record<string, unknown> | null;
    const historyEntry = body.validation_status ? {
      status: body.validation_status,
      changed_by: (session["username"] as string) ?? (session["userId"] as string) ?? "unknown",
      changed_at: new Date(),
      previous_status: existing?.["validation_status"] ?? null,
    } : null;

    if (!existing) return res.status(404).json({ error: "Finding not found" });
    await col("findings").updateOne(
      { _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>,
      {
        $set: updates,
        ...(historyEntry ? { $push: { status_history: historyEntry } } : {}),
      } as Record<string, unknown>
    );

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
              created_by: (req.session as unknown as Record<string, unknown>)["username"] ?? "unknown",
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

    // Audit log
    logAudit({
      userId: session["userId"] ?? "",
      username: String(session["username"] ?? session["userId"] ?? ""),
      action: "finding.update",
      resource: "finding",
      resourceId: id,
      details: { changes: updates },
      ip: req.ip,
    }).catch(() => {});

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
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    await col("fp_suppressions").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete FP suppression error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Bulk actions ──────────────────────────────────────────────────────────────

router.post("/findings/bulk", requireAuth, async (req, res) => {
  try {
    const { ids, action, value } = req.body as {
      ids?: string[];
      action?: "mark_fp" | "mark_real" | "mark_informational" | "delete" | "assign";
      value?: string;
    };

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: "ids array is required and must not be empty" });
    }
    if (!action) {
      return res.status(400).json({ error: "action is required" });
    }
    if (ids.length > 200) {
      return res.status(400).json({ error: "Maximum 200 findings per bulk operation" });
    }

    const validIds = ids.filter(id => ObjectId.isValid(id)).map(id => new ObjectId(id));
    if (validIds.length === 0) {
      return res.status(400).json({ error: "No valid finding IDs provided" });
    }

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};

    let updated = 0;

    if (action === "delete") {
      const result = await col("findings").deleteMany({ _id: { $in: validIds }, ...ownerFilter } as Record<string, unknown>);
      updated = (result as unknown as { deletedCount: number }).deletedCount ?? validIds.length;
      logAudit({
        userId: session.userId ?? "",
        username: String((session as Record<string, unknown>)["username"] ?? session.userId ?? ""),
        action: "finding.bulk_delete",
        resource: "finding",
        details: { count: updated, ids: ids.slice(0, 20) },
        ip: req.ip,
      }).catch(() => {});
      res.json({ ok: true, action, affected: updated });
      return;
    }

    const statusMap: Record<string, string> = {
      mark_fp: "false_positive",
      mark_real: "real",
      mark_informational: "informational",
    };

    if (action in statusMap) {
      await col("findings").updateMany(
        { _id: { $in: validIds }, ...ownerFilter } as Record<string, unknown>,
        { $set: { validation_status: statusMap[action], updated_at: new Date() } }
      );
      updated = validIds.length;
    } else if (action === "assign" && value) {
      await col("findings").updateMany(
        { _id: { $in: validIds }, ...ownerFilter } as Record<string, unknown>,
        { $set: { assigned_to: value, updated_at: new Date() } }
      );
      updated = validIds.length;
    } else {
      return res.status(400).json({ error: `Unknown action: ${action}` });
    }

    res.json({ ok: true, action, affected: updated });
  } catch (err) {
    logger.error({ err }, "Bulk findings action error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Scan diff ─────────────────────────────────────────────────────────────────

router.get("/scan-jobs/:id/diff", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
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

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const query: Record<string, unknown> = {};
    if (session.role !== "admin") query["user_id"] = session.userId ?? null;
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

    if (fmt === "sarif") {
      const rules = [...new Set(formatted.map((f) => (f as Record<string, unknown>)["cwe_id"] as string).filter(Boolean))].map((cweId) => ({
        id: cweId,
        name: cweId.replace("-", ""),
        shortDescription: { text: cweId },
        helpUri: `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`,
      }));
      const results = formatted.map((f) => {
        const finding = f as Record<string, unknown>;
        const sev = String(finding["severity"] ?? "medium");
        const levelMap: Record<string, string> = { critical: "error", high: "error", medium: "warning", low: "note", info: "none" };
        return {
          ruleId: String(finding["cwe_id"] ?? "unknown"),
          level: levelMap[sev] ?? "warning",
          message: { text: String(finding["title"] ?? "") + "\n\n" + String(finding["description"] ?? "") },
          locations: [{ physicalLocation: { artifactLocation: { uri: String(finding["endpoint"] ?? "") } } }],
          properties: {
            severity: finding["severity"],
            category: finding["category"],
            cvss_score: finding["cvss_score"],
            scanner_name: finding["scanner_name"],
            finding_id: finding["id"],
          },
        };
      });
      const sarif = {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [{
          tool: {
            driver: {
              name: "Bug Finder Pro",
              version: "1.0.0",
              informationUri: "https://bugfinderpro.com",
              rules,
            },
          },
          results,
        }],
      };
      res.setHeader("Content-Type", "application/sarif+json");
      res.setHeader("Content-Disposition", `attachment; filename="findings-${Date.now()}.sarif.json"`);
      return res.json(sarif);
    }

    return res.status(400).json({ error: "Unsupported format. Use: json, csv, sarif" });
  } catch (err) {
    logger.error({ err }, "Export findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scan-jobs/export/:format", requireAuth, async (req, res) => {
  try {
    const { format: fmt } = req.params;
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};
    const scans = await col("scan_jobs").find(ownerFilter).sort({ created_at: -1 }).limit(1000).toArray() as Array<Record<string, unknown>>;

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
    const id = String(req.params["id"]);
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

// ── CVE/EPSS background enrichment ───────────────────────────────────────────

/**
 * Fetches NVD v2 + EPSS data for a specific CVE ID and persists it onto the
 * finding document. Designed to be called non-blocking after insert:
 *   enrichFindingWithCVE(id, cveId).catch(() => {})
 */
export async function enrichFindingWithCVEExport(findingId: string, cveId: string): Promise<void> {
  return enrichFindingWithCVE(findingId, cveId);
}

async function enrichFindingWithCVE(findingId: string, cveId: string): Promise<void> {
  if (!ObjectId.isValid(findingId)) return;

  const updates: Record<string, unknown> = { cve_enriched_at: new Date() };

  // ── NVD API v2 ────────────────────────────────────────────────────────────
  try {
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    const nvdRes = await fetch(nvdUrl, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });
    if (nvdRes.ok) {
      const data = await nvdRes.json() as Record<string, unknown>;
      const vulns = (data["vulnerabilities"] as Array<Record<string, unknown>>) ?? [];
      const first = vulns[0];
      if (first) {
        const cve = first["cve"] as Record<string, unknown>;
        const descriptions = (cve["descriptions"] as Array<Record<string, unknown>>) ?? [];
        const enDesc = descriptions.find((d) => d["lang"] === "en");
        if (enDesc?.["value"]) updates["nvd_description"] = enDesc["value"];

        const metrics = (cve["metrics"] as Record<string, unknown>) ?? {};
        const cvssV31 = ((metrics["cvssMetricV31"] as Array<Record<string, unknown>>) ?? [])[0];
        if (cvssV31) {
          const cvssData = cvssV31["cvssData"] as Record<string, unknown> | undefined;
          if (cvssData?.["baseScore"]) updates["cvss_v3_score"] = cvssData["baseScore"];
        }

        // Check for known exploits (CISA KEV references or vuln references tagged "Exploit")
        const refs = (cve["references"] as Array<Record<string, unknown>>) ?? [];
        const hasExploit = refs.some((r) => {
          const tags = (r["tags"] as string[]) ?? [];
          return tags.some((t) => t.toLowerCase().includes("exploit"));
        });
        updates["known_exploits"] = hasExploit;
      }
    }
  } catch { /* NVD unavailable — skip */ }

  // ── EPSS (Exploit Prediction Scoring System) ──────────────────────────────
  try {
    const epssUrl = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
    const epssRes = await fetch(epssUrl, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (epssRes.ok) {
      const epssData = await epssRes.json() as Record<string, unknown>;
      const dataArr = (epssData["data"] as Array<Record<string, unknown>>) ?? [];
      const epssEntry = dataArr[0];
      if (epssEntry) {
        const epssScore = parseFloat(String(epssEntry["epss"] ?? "0"));
        const epssPercentile = parseFloat(String(epssEntry["percentile"] ?? "0"));
        if (!isNaN(epssScore)) updates["epss_score"] = epssScore;
        if (!isNaN(epssPercentile)) updates["epss_percentile"] = epssPercentile;
      }
    }
  } catch { /* EPSS unavailable — skip */ }

  if (Object.keys(updates).length > 1) { // more than just cve_enriched_at
    await col("findings").updateOne(
      { _id: new ObjectId(findingId) } as Record<string, unknown>,
      { $set: updates }
    );
  }
}

// ── Admin: Bulk CVE/EPSS enrichment ──────────────────────────────────────────

router.get("/findings/enrich-all", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (session.role !== "admin") return res.status(403).json({ error: "Admin only" });

    // Find all findings with a cve_id but no epss_score yet
    const pending = await col("findings")
      .find({ cve_id: { $exists: true, $ne: null }, epss_score: { $exists: false } } as Record<string, unknown>)
      .project({ _id: 1, cve_id: 1 })
      .limit(500)
      .toArray() as Array<Record<string, unknown>>;

    // Kick off enrichment non-blocking — each promise is individually caught
    for (const f of pending) {
      const id = String(f["_id"]);
      const cveId = String(f["cve_id"] ?? "");
      if (cveId) enrichFindingWithCVE(id, cveId).catch(() => {});
    }

    res.json({ ok: true, queued: pending.length });
  } catch (err) {
    logger.error({ err }, "Bulk CVE enrichment error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Get stored CVE enrichment data for a finding ──────────────────────────────

router.get("/findings/:id/cve-details", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};

    const finding = (await col("findings").findOne(
      { _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>
    )) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    res.json({
      finding_id: id,
      cve_id: finding["cve_id"] ?? null,
      nvd_description: finding["nvd_description"] ?? null,
      cvss_v3_score: finding["cvss_v3_score"] ?? null,
      epss_score: finding["epss_score"] ?? null,
      epss_percentile: finding["epss_percentile"] ?? null,
      known_exploits: finding["known_exploits"] ?? null,
      cve_enriched_at: finding["cve_enriched_at"] ?? null,
    });
  } catch (err) {
    logger.error({ err }, "CVE details fetch error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── CVE enrichment for a finding ─────────────────────────────────────────────

router.get("/findings/:id/cve", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
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
    const id = String(req.params["id"]);
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

// ── Deduplicate scan findings ─────────────────────────────────────────────────
router.post("/scan-jobs/:id/deduplicate", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const { clusterFindings } = await import("../services/dedup");
    const clusters = await clusterFindings(id);
    let markedCount = 0;
    for (const cluster of clusters) {
      if (cluster.cluster.length <= 1) continue;
      // Mark all but representative as duplicates
      const duplicateIds = cluster.cluster.slice(1).filter(did => ObjectId.isValid(did)).map(did => new ObjectId(did));
      if (duplicateIds.length > 0) {
        await col("findings").updateMany(
          { _id: { $in: duplicateIds } } as Record<string, unknown>,
          { $set: { is_duplicate: true, duplicate_of: cluster.representative, updated_at: new Date() } }
        );
        markedCount += duplicateIds.length;
      }
    }
    res.json({ clusters, marked_duplicates: markedCount });
  } catch (err) {
    logger.error({ err }, "Deduplicate error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Retest finding ────────────────────────────────────────────────────────────
router.post("/findings/:id/retest", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
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

// ── Raw evidence (full untruncated evidence for critical/high findings) ───────
router.get("/findings/:id/raw-evidence", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};

    // Verify the caller owns (or is admin for) the parent finding
    const finding = (await col("findings").findOne({ _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    if (!finding["has_raw_evidence"]) {
      return res.json({ available: false, message: "Full evidence not stored for this finding (medium/low/info severity)" });
    }

    const rawEvidence = (await col("raw_evidence").findOne({ finding_id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!rawEvidence) {
      return res.json({ available: false, message: "Raw evidence record not found or has expired (30-day TTL)" });
    }

    res.json({
      available: true,
      finding_id: id,
      title: rawEvidence["title"],
      endpoint: rawEvidence["endpoint"],
      severity: rawEvidence["severity"],
      scanner_name: rawEvidence["scanner_name"],
      evidence_full: rawEvidence["evidence_full"],
      created_at: rawEvidence["created_at"],
      expires_at: rawEvidence["expires_at"],
    });
  } catch (err) {
    logger.error({ err }, "Raw evidence fetch error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Finding status history ────────────────────────────────────────────────────
router.get("/findings/:id/history", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const finding = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });
    res.json({ history: (finding["status_history"] as unknown[]) ?? [] });
  } catch (err) {
    logger.error({ err }, "Finding history error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Enrich finding with EPSS + CISA KEV ──────────────────────────────────────
router.post("/findings/:id/enrich", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const { enrichFindingWithIntel } = await import("../services/vuln-intel");
    await enrichFindingWithIntel(id);
    const updated = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
    res.json(formatFinding(updated));
  } catch (err) {
    logger.error({ err }, "Finding enrich error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Assign finding ────────────────────────────────────────────────────────────
router.post("/findings/:id/assign", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const { assignee } = req.body as { assignee?: string };
    await col("findings").updateOne({ _id: new ObjectId(id) } as Record<string,unknown>, { $set: { assignee: assignee ?? null, assigned_at: assignee ? new Date() : null } });
    res.json({ ok: true });
  } catch(err) { logger.error({err},"assign error"); res.status(500).json({ error: "Internal server error" }); }
});

// ── Enterprise: Assign finding to a user ─────────────────────────────────────
router.patch("/findings/:id/assign", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { assignee_id } = req.body as { assignee_id?: string };
    if (!assignee_id) return res.status(400).json({ error: "assignee_id is required" });
    // Verify assignee exists
    const assignee = await col("users").findOne({ _id: new ObjectId(assignee_id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!assignee) return res.status(404).json({ error: "Assignee user not found" });
    const before = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    await col("findings").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { assignee_id, assignee_name: String(assignee["username"] ?? assignee["email"] ?? ""), assigned_at: new Date(), updated_at: new Date() } }
    );
    await auditFromReq(req, "finding.assign", "findings", id, { assignee_id }, before ?? undefined, { assignee_id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Enterprise: Formal risk acceptance ───────────────────────────────────────
router.post("/findings/:id/accept-risk", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { justification, owner_name, review_date } = req.body as {
      justification?: string;
      owner_name?: string;
      review_date?: string;
    };
    if (!justification) return res.status(400).json({ error: "justification is required" });
    const sess = req.session as unknown as { userId?: string; username?: string };
    await col("findings").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: {
        risk_accepted: true,
        risk_accepted_at: new Date(),
        risk_accepted_by: sess.userId,
        risk_accepted_by_name: sess.username,
        risk_justification: justification,
        risk_owner: owner_name ?? sess.username ?? "unknown",
        risk_review_date: review_date ? new Date(review_date) : new Date(Date.now() + 90 * 86400000),
        triage_status: "accepted",
        updated_at: new Date(),
      }}
    );
    await auditFromReq(req, "finding.risk_accepted", "findings", id, { justification, owner_name });
    res.json({ ok: true, message: "Risk acceptance recorded" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Enterprise: Mark as verified false negative ───────────────────────────────
router.post("/findings/:id/false-negative", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { reason } = req.body as { reason?: string };
    const sess = req.session as unknown as { userId?: string; username?: string };
    await col("findings").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: {
        fn_verified: true,
        fn_verified_at: new Date(),
        fn_verified_by: sess.userId,
        fn_reason: reason ?? "Verified real vulnerability missed by scanner",
        triage_status: "confirmed",
        updated_at: new Date(),
      }, $inc: { fn_count: 1 } }
    );
    await auditFromReq(req, "finding.false_negative", "findings", id, { reason });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Enterprise: Upload evidence file (base64) ─────────────────────────────────
router.post("/findings/:id/evidence", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { filename, content_type, base64_data, data, label, description } = req.body as {
      filename?: string;
      content_type?: string;
      base64_data?: string;
      data?: string;
      label?: string;
      description?: string;
    };
    const fileData = base64_data ?? data;
    if (!filename || !fileData) return res.status(400).json({ error: "filename and data (base64) are required" });
    const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/gif", "application/json", "text/plain", "application/octet-stream", "application/har+json"];
    const ct = content_type ?? "application/octet-stream";
    if (!ALLOWED_TYPES.includes(ct)) return res.status(400).json({ error: "File type not allowed" });
    const buf = Buffer.from(fileData, "base64");
    if (buf.length > 10 * 1024 * 1024) return res.status(400).json({ error: "File too large (max 10MB)" });

    const insert = await col("evidence_files").insertOne({
      finding_id: id,
      filename,
      content_type: ct,
      data: fileData,
      size_bytes: buf.length,
      label: label ?? description ?? null,
      description: description ?? null,
      created_at: new Date(),
    });
    await auditFromReq(req, "finding.evidence_upload", "findings", id, { filename, size: buf.length });
    res.status(201).json({ id: String(insert.insertedId), filename, size_bytes: buf.length });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Enterprise: List evidence files for a finding ─────────────────────────────
router.get("/findings/:id/evidence", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const files = await col("evidence_files").find({ finding_id: id } as Record<string, unknown>).sort({ created_at: -1 }).toArray();
    res.json(files.map(f => ({ id: String(f["_id"]), filename: f["filename"], content_type: f["content_type"], size_bytes: f["size_bytes"], label: f["label"] ?? f["description"] ?? null, created_at: f["created_at"], base64_data: f["data"] ?? null })));
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Enterprise: Saved filter presets ─────────────────────────────────────────
router.get("/findings/saved-filters", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const filters = await col("saved_filters").find({ user_id: sess.userId, resource: "findings" } as Record<string, unknown>).sort({ created_at: -1 }).toArray();
    res.json(filters.map(f => ({ id: String(f["_id"]), name: f["name"], filters: f["filters"], created_at: f["created_at"] })));
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/findings/saved-filters", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const { name, filters } = req.body as { name?: string; filters?: Record<string, unknown> };
    if (!name || !filters) return res.status(400).json({ error: "name and filters are required" });
    const insert = await col("saved_filters").insertOne({ user_id: sess.userId, resource: "findings", name, filters, created_at: new Date() });
    res.status(201).json({ id: String(insert.insertedId), name, filters });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/findings/saved-filters/:id", requireAuth, async (req, res) => {
  try {
    await col("saved_filters").deleteOne({ _id: new ObjectId(String(req.params.id)) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Vulnerability intelligence (cached enrichment data) ───────────────────────
router.get("/findings/:id/vuln-intel", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Not found" });
    const cached = await col("vuln_intel").findOne({ finding_id: id } as Record<string, unknown>) as Record<string, unknown> | null;
    if (cached) return res.json(cached);
    res.json({ cve_id: finding["cve_id"] ?? null, description: null, cvss_v3_score: finding["cvss_score"] ?? null, cvss_v4_score: null, epss_score: null, epss_percentile: null, patch_available: null, public_exploits: [], first_seen: null, last_modified: null, affected_products: [] });
  } catch { res.status(500).json({ error: "Internal server error" }); }
});

// ── CVSS v4 inline calculator ─────────────────────────────────────────────────
router.post("/cvss/calculate", requireAuth, async (req, res) => {
  const { metrics } = req.body as { metrics: Record<string, string> };
  const avScore = ({ N: 0, A: 0.85, L: 0.55, P: 0.2 } as Record<string, number>)[metrics.AV ?? "N"] ?? 0;
  const acScore = ({ L: 0, H: 0.44 } as Record<string, number>)[metrics.AC ?? "L"] ?? 0;
  const vcScore = ({ N: 0, L: 0.22, H: 0.56 } as Record<string, number>)[metrics.VC ?? "N"] ?? 0;
  const viScore = ({ N: 0, L: 0.22, H: 0.56 } as Record<string, number>)[metrics.VI ?? "N"] ?? 0;
  const vaScore = ({ N: 0, L: 0.22, H: 0.56 } as Record<string, number>)[metrics.VA ?? "N"] ?? 0;
  const impact = Math.min(1 - (1 - vcScore) * (1 - viScore) * (1 - vaScore), 1);
  const base = Math.round((10 - (1 - impact) * (1 - avScore) * (1 - acScore) * 10) * 10) / 10;
  const score = Math.max(0, Math.min(10, base));
  const severity = score === 0 ? "none" : score < 4 ? "low" : score < 7 ? "medium" : score < 9 ? "high" : "critical";
  const vector = `CVSS:4.0/AV:${metrics.AV ?? "N"}/AC:${metrics.AC ?? "L"}/AT:${metrics.AT ?? "N"}/PR:${metrics.PR ?? "N"}/UI:${metrics.UI ?? "N"}/VC:${metrics.VC ?? "N"}/VI:${metrics.VI ?? "N"}/VA:${metrics.VA ?? "N"}`;
  res.json({ score, severity, vector });
});

export default router;

