/**
 * CI/CD Integration routes
 *
 * GET  /scan-jobs/:id/sarif         — SARIF 2.1.0 export for GitHub Code Scanning
 * GET  /scan-jobs/:id/exit-code     — Returns { exit_code: 0|1 } for pipeline gates
 * POST /scan-jobs/:id/set-baseline  — Pin this scan as the comparison baseline
 * GET  /scan-jobs/:id/diff          — New/resolved findings vs pinned baseline
 */

import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();
router.use(requireAuth);

// ── SARIF 2.1.0 export ────────────────────────────────────────────────────────

router.get("/scan-jobs/:id/sarif", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Scan not found" });

    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (session.role !== "admin" && scan["user_id"] !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const findings = await col("findings")
      .find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>)
      .toArray() as Array<Record<string, unknown>>;

    const SEVERITY_LEVEL: Record<string, string> = {
      critical: "error", high: "error", medium: "warning", low: "note", info: "note",
    };

    // Build SARIF rules — one per unique finding title
    const ruleMap = new Map<string, Record<string, unknown>>();
    for (const f of findings) {
      const ruleId = String(f["cwe_id"] ?? f["title"]).replace(/\s+/g, "_").replace(/[^a-zA-Z0-9_-]/g, "");
      if (!ruleMap.has(ruleId)) {
        ruleMap.set(ruleId, {
          id: ruleId,
          name: String(f["title"] ?? ""),
          shortDescription: { text: String(f["title"] ?? "") },
          fullDescription: { text: String(f["description"] ?? "") },
          helpUri: f["cwe_id"] ? `https://cwe.mitre.org/data/definitions/${String(f["cwe_id"]).replace("CWE-", "")}.html` : undefined,
          properties: {
            tags: [String(f["category"] ?? ""), "security"],
            "security-severity": String(f["cvss_score"] ?? 5.0),
          },
        });
      }
    }

    // Build SARIF results
    const results = findings.map((f) => {
      const ruleId = String(f["cwe_id"] ?? f["title"]).replace(/\s+/g, "_").replace(/[^a-zA-Z0-9_-]/g, "");
      const level = SEVERITY_LEVEL[String(f["severity"] ?? "medium")] ?? "warning";

      // Extract URI from endpoint — strip query string for file URI
      let artifactUri = String(f["endpoint"] ?? scan["target_url"] ?? "");
      try {
        const u = new URL(artifactUri);
        artifactUri = `${u.origin}${u.pathname}`;
      } catch { /* use as-is */ }

      return {
        ruleId,
        level,
        message: {
          text: [
            String(f["description"] ?? ""),
            f["recommended_fix"] ? `\n\nFix: ${String(f["recommended_fix"])}` : "",
          ].join(""),
        },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: artifactUri, uriBaseId: "%SRCROOT%" },
            region: { startLine: 1 },
          },
          logicalLocations: [{
            name: String(f["endpoint"] ?? ""),
            kind: "url",
          }],
        }],
        partialFingerprints: {
          "bug-finder/dedup-key/v1": String(f["dedup_key"] ?? `${f["title"]}||${f["endpoint"]}`),
        },
        properties: {
          severity: String(f["severity"] ?? ""),
          cvss_score: f["cvss_score"],
          cwe_id: f["cwe_id"],
          scanner: f["scanner_name"],
          confidence: f["confidence"],
          finding_id: String(f["_id"]),
          evidence_snippet: typeof f["evidence"] === "string" ? f["evidence"].slice(0, 400) : "",
        },
      };
    });

    const sarif = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: {
          driver: {
            name: "Bug Finder Pro",
            version: "1.0.0",
            informationUri: "https://bugfinderpro.com",
            rules: [...ruleMap.values()],
          },
        },
        results,
        properties: {
          scan_id: id,
          target_url: scan["target_url"],
          scan_profile: scan["scan_profile"],
          completed_at: scan["completed_at"],
          risk_score: scan["risk_score"],
        },
      }],
    };

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="bugfinder-sarif-${id.slice(0, 8)}.json"`);
    res.json(sarif);
  } catch (err) {
    logger.error({ err }, "SARIF export error");
    res.status(500).json({ error: "SARIF export failed" });
  }
});

// ── Exit-code endpoint — for CI/CD pipeline gates ─────────────────────────────
// Returns exit_code: 1 if any critical or high findings exist (pipeline should fail).
// Returns exit_code: 0 if clean (pipeline should pass).
// Optional ?min_severity=high|critical (default: critical)

router.get("/scan-jobs/:id/exit-code", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Scan not found" });

    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    if (scan["status"] !== "completed") {
      return res.status(202).json({ exit_code: null, status: scan["status"], message: "Scan not yet complete" });
    }

    const minSeverity = String(req.query["min_severity"] ?? "critical");
    const severities = minSeverity === "high" ? ["critical", "high"] : ["critical"];

    const criticalCount = Number(scan["critical_count"] ?? 0);
    const highCount = Number(scan["high_count"] ?? 0);

    const shouldFail = severities.includes("high")
      ? (criticalCount > 0 || highCount > 0)
      : criticalCount > 0;

    res.json({
      exit_code: shouldFail ? 1 : 0,
      scan_id: id,
      status: scan["status"],
      target_url: scan["target_url"],
      risk_score: scan["risk_score"],
      critical: criticalCount,
      high: highCount,
      medium: Number(scan["medium_count"] ?? 0),
      low: Number(scan["low_count"] ?? 0),
      total: Number(scan["findings_count"] ?? 0),
      min_severity_checked: minSeverity,
      message: shouldFail
        ? `Pipeline gate FAILED — ${criticalCount} critical, ${highCount} high findings`
        : "Pipeline gate PASSED — no blocking findings",
    });
  } catch (err) {
    logger.error({ err }, "Exit-code endpoint error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Baseline pinning ──────────────────────────────────────────────────────────
// Pin a completed scan as the "baseline" for this target.
// Future scans on the same target will diff against this baseline
// instead of the most-recent-previous scan.

router.post("/scan-jobs/:id/set-baseline", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Scan not found" });

    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    if (scan["status"] !== "completed") {
      return res.status(400).json({ error: "Only completed scans can be set as baseline" });
    }

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (session.role !== "admin" && scan["user_id"] !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const targetUrl = String(scan["target_url"] ?? "");
    let domain: string;
    try { domain = new URL(targetUrl).hostname; } catch {
      return res.status(400).json({ error: "Invalid target URL on scan" });
    }

    // Unset previous baseline for this target+user combination
    const prevQuery: Record<string, unknown> = {
      target_url: { $regex: domain, $options: "i" },
      is_baseline: true,
    };
    if (session.role !== "admin") prevQuery["user_id"] = session.userId;
    await col("scan_jobs").updateMany(prevQuery, { $set: { is_baseline: false } } as Record<string, unknown>);

    // Set this scan as baseline
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { is_baseline: true, baseline_set_at: new Date(), baseline_set_by: session.userId } }
    );

    res.json({ ok: true, baseline_scan_id: id, target_url: targetUrl, domain });
  } catch (err) {
    logger.error({ err }, "Set baseline error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Diff against baseline ─────────────────────────────────────────────────────
// Returns structured new/recurring/resolved diff between this scan and the
// pinned baseline (or the most-recent previous scan if no baseline is pinned).

router.get("/scan-jobs/:id/diff", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Scan not found" });

    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    if (session.role !== "admin" && scan["user_id"] !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const targetUrl = String(scan["target_url"] ?? "");
    let domain: string;
    try { domain = new URL(targetUrl).hostname; } catch {
      return res.status(400).json({ error: "Invalid target URL" });
    }

    // Find pinned baseline or fall back to most-recent previous completed scan
    const baselineQuery: Record<string, unknown> = {
      target_url: { $regex: domain, $options: "i" },
      status: "completed",
      _id: { $ne: new ObjectId(id) },
    };
    if (session.role !== "admin") baselineQuery["user_id"] = session.userId;

    const [pinnedBaseline, mostRecentPrev] = await Promise.all([
      col("scan_jobs").find({ ...baselineQuery, is_baseline: true } as Record<string, unknown>).sort({ completed_at: -1 }).limit(1).toArray(),
      col("scan_jobs").find(baselineQuery).sort({ completed_at: -1 }).limit(1).toArray(),
    ]);

    const baselineScan = (pinnedBaseline[0] ?? mostRecentPrev[0]) as Record<string, unknown> | undefined;
    if (!baselineScan) {
      return res.json({ message: "No baseline or previous scan found for this target", diff: null });
    }

    const [currentFindings, baselineFindings] = await Promise.all([
      col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
      col("findings").find({ scan_job_id: baselineScan["_id"] } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);

    const key = (f: Record<string, unknown>) => `${String(f["title"])}||${String(f["endpoint"])}`;
    const baselineKeys = new Set(baselineFindings.map(key));
    const currentKeys = new Set(currentFindings.map(key));

    const formatF = (f: Record<string, unknown>) => ({
      id: String(f["_id"]),
      title: f["title"],
      severity: f["severity"],
      endpoint: f["endpoint"],
      category: f["category"],
      cwe_id: f["cwe_id"],
      cvss_score: f["cvss_score"],
    });

    const newFindings = currentFindings.filter(f => !baselineKeys.has(key(f))).map(formatF);
    const recurringFindings = currentFindings.filter(f => baselineKeys.has(key(f))).map(formatF);
    const resolvedFindings = baselineFindings.filter(f => !currentKeys.has(key(f))).map(formatF);

    res.json({
      scan_id: id,
      baseline_scan_id: String(baselineScan["_id"]),
      baseline_is_pinned: !!(baselineScan["is_baseline"]),
      baseline_completed_at: baselineScan["completed_at"],
      current_completed_at: scan["completed_at"],
      diff: {
        new_count: newFindings.length,
        recurring_count: recurringFindings.length,
        resolved_count: resolvedFindings.length,
        new: newFindings,
        recurring: recurringFindings,
        resolved: resolvedFindings,
      },
    });
  } catch (err) {
    logger.error({ err }, "Diff endpoint error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
