import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";
import { checkSsrf } from "../lib/ssrf-guard";

const router = Router();

function formatTarget(t: Record<string, unknown>) {
  return {
    id: String(t["_id"]),
    url: t["url"],
    domain: t["domain"],
    last_scanned: t["last_scanned"] ?? null,
    total_scans: t["total_scans"] ?? 0,
    total_findings: t["total_findings"] ?? 0,
    critical_findings: t["critical_findings"] ?? 0,
    high_findings: t["high_findings"] ?? 0,
    risk_score: t["risk_score"] ?? 0,
    status: t["status"] ?? "active",
    tags: (t["tags"] as string[]) ?? [],
    tech_stack: (t["tech_stack"] as string[]) ?? [],
    subdomains: (t["subdomains"] as string[]) ?? [],
    risk_history: (t["risk_history"] as Array<{ score: number; date: string }>) ?? [],
  };
}

// ── List targets ────────────────────────────────────────────────────────────

router.get("/targets", requireAuth, async (req, res) => {
  try {
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "50"));
    const search = req.query["search"] as string | undefined;
    const tag = req.query["tag"] as string | undefined;
    const sortBy = (req.query["sort_by"] as string) ?? "last_scanned";
    const sortDir = req.query["sort_dir"] === "asc" ? 1 : -1;

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const query: Record<string, unknown> = {};
    if (session.role !== "admin") query["user_id"] = session.userId ?? null;
    if (search) query["domain"] = { $regex: search, $options: "i" };
    if (tag) query["tags"] = tag;

    const sortField: Record<string, 1 | -1> = {};
    const allowed = ["last_scanned", "risk_score", "total_findings", "domain", "total_scans"];
    sortField[allowed.includes(sortBy) ? sortBy : "last_scanned"] = sortDir;

    const all = (await col("targets").find(query).sort(sortField).toArray()) as Array<Record<string, unknown>>;
    const total = all.length;
    const items = all.slice((page - 1) * pageSize, page * pageSize).map(formatTarget);

    // Collect all unique tags across all targets for filter sidebar
    const allTags = [...new Set(all.flatMap((t) => (t["tags"] as string[]) ?? []))].sort();

    res.json({ items, total, page, page_size: pageSize, all_tags: allTags });
  } catch (err) {
    logger.error({ err }, "List targets error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Get single target ───────────────────────────────────────────────────────

router.get("/targets/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};

    const target = (await col("targets").findOne({ _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!target) return res.status(404).json({ error: "Target not found" });
    res.json(formatTarget(target));
  } catch (err) {
    logger.error({ err }, "Get target error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Bulk import targets ─────────────────────────────────────────────────────

router.post("/targets/bulk-import", requireAuth, async (req, res) => {
  try {
    const { urls, tags = [] } = req.body as { urls?: string[]; tags?: string[] };
    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ error: "urls array is required" });
    }

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    let imported = 0, skipped = 0;
    for (const rawUrl of urls) {
      const url = rawUrl.trim();
      if (!url) continue;
      try {
        const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
        const domain = parsed.hostname;
        const normalizedUrl = parsed.origin;

        const ssrfResult = checkSsrf(normalizedUrl);
        if (!ssrfResult.allowed) { skipped++; continue; }

        // Require at least one dot in hostname to filter out bare single-word hostnames
        if (!domain.includes(".")) { skipped++; continue; }

        const existing = await col("targets").findOne({ domain } as Record<string, unknown>);
        if (existing) {
          // Merge tags
          if (tags.length > 0) {
            const existing_tags = (existing["tags"] as string[]) ?? [];
            const merged = [...new Set([...existing_tags, ...tags])];
            await col("targets").updateOne(
              { domain } as Record<string, unknown>,
              { $set: { tags: merged, updated_at: new Date() } }
            );
          }
          skipped++;
          continue;
        }

        await col("targets").insertOne({
          url: normalizedUrl,
          domain,
          user_id: session.userId,
          tags,
          tech_stack: [],
          subdomains: [],
          risk_history: [],
          last_scanned: null,
          total_scans: 0,
          total_findings: 0,
          critical_findings: 0,
          high_findings: 0,
          risk_score: 0,
          status: "active",
          created_at: new Date(),
          updated_at: new Date(),
        });
        imported++;
      } catch {
        skipped++;
      }
    }

    res.json({ imported, skipped, total: urls.length });
  } catch (err) {
    logger.error({ err }, "Bulk import targets error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Update target tags ──────────────────────────────────────────────────────

router.patch("/targets/:id/tags", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const { tags } = req.body as { tags?: string[] };
    if (!Array.isArray(tags)) return res.status(400).json({ error: "tags must be an array" });

    await col("targets").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { tags, updated_at: new Date() } }
    );

    const updated = (await col("targets").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
    res.json(formatTarget(updated));
  } catch (err) {
    logger.error({ err }, "Update target tags error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/targets/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};

    const result = await col("targets").deleteOne({ _id: new ObjectId(id), ...ownerFilter } as Record<string, unknown>);
    if (result.deletedCount === 0) return res.status(404).json({ error: "Target not found or access denied" });
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete target error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Risk trend for a target ─────────────────────────────────────────────────

router.get("/targets/:id/risk-trend", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const target = (await col("targets").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!target) return res.status(404).json({ error: "Target not found" });

    const domain = target["domain"] as string;
    const scans = (await col("scan_jobs")
      .find({ target_url: { $regex: domain, $options: "i" }, status: "completed" } as Record<string, unknown>)
      .sort({ completed_at: -1 })
      .limit(10)
      .toArray()) as Array<Record<string, unknown>>;

    const trend = scans
      .reverse()
      .map((s) => ({
        date: s["completed_at"] ? new Date(s["completed_at"] as string).toISOString().slice(0, 10) : null,
        risk_score: Number(s["risk_score"]) || 0,
        findings: Number(s["findings_count"]) || 0,
        scan_id: String(s["_id"]),
      }));

    res.json(trend);
  } catch (err) {
    logger.error({ err }, "Target risk trend error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Recurring (deduplicated) findings for a target ──────────────────────────

router.get("/targets/:id/recurring-findings", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const target = (await col("targets").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!target) return res.status(404).json({ error: "Target not found" });

    const domain = target["domain"] as string;
    const findings = (await col("findings")
      .find({ target_url: { $regex: domain, $options: "i" } } as Record<string, unknown>)
      .sort({ created_at: -1 })
      .toArray()) as Array<Record<string, unknown>>;

    // Group by title+endpoint — recurring = seen in more than one scan
    const groups: Record<string, { title: string; endpoint: string; severity: string; count: number; scan_ids: string[]; last_seen: string }> = {};
    for (const f of findings) {
      const key = `${f["title"]}||${f["endpoint"]}`;
      if (!groups[key]) {
        groups[key] = {
          title: String(f["title"]),
          endpoint: String(f["endpoint"]),
          severity: String(f["severity"]),
          count: 0,
          scan_ids: [],
          last_seen: String(f["created_at"]),
        };
      }
      groups[key].count++;
      const sid = String(f["scan_job_id"]);
      if (!groups[key].scan_ids.includes(sid)) groups[key].scan_ids.push(sid);
      if (new Date(String(f["created_at"])) > new Date(groups[key].last_seen)) {
        groups[key].last_seen = String(f["created_at"]);
      }
    }

    const recurring = Object.values(groups)
      .filter((g) => g.count > 1)
      .sort((a, b) => b.count - a.count);

    res.json(recurring);
  } catch (err) {
    logger.error({ err }, "Recurring findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Global attack surface aggregation ──────────────────────────────────────

router.get("/attack-surface", requireAuth, async (req, res) => {
  try {
    const tagFilter = req.query["tag"] as string | undefined;

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const ownerFilter = session.role !== "admin" ? { user_id: session.userId ?? null } : {};
    const targetQuery: Record<string, unknown> = { ...ownerFilter };
    if (tagFilter) targetQuery["tags"] = tagFilter;
    const targets = (await col("targets").find(targetQuery).toArray()) as Array<Record<string, unknown>>;
    const domainSet = new Set(targets.map((t) => String(t["domain"])));

    // All findings for these targets
    const allFindings = (await col("findings").find(ownerFilter).toArray()) as Array<Record<string, unknown>>;
    const scopedFindings = tagFilter
      ? allFindings.filter((f) => {
          try { return domainSet.has(new URL(String(f["target_url"])).hostname); } catch { return false; }
        })
      : allFindings;

    // Category breakdown (radar/bar)
    const categoryMap: Record<string, { critical: number; high: number; medium: number; low: number }> = {};
    for (const f of scopedFindings) {
      const cat = String(f["category"] ?? "Other");
      if (!categoryMap[cat]) categoryMap[cat] = { critical: 0, high: 0, medium: 0, low: 0 };
      const sev = String(f["severity"]);
      if (sev === "critical") categoryMap[cat].critical++;
      else if (sev === "high") categoryMap[cat].high++;
      else if (sev === "medium") categoryMap[cat].medium++;
      else if (sev === "low") categoryMap[cat].low++;
    }
    const categoryData = Object.entries(categoryMap)
      .map(([name, counts]) => ({ name, ...counts, total: counts.critical + counts.high + counts.medium + counts.low }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 10);

    // Endpoint inventory — unique endpoint × method × max_severity
    const endpointMap: Record<string, { url: string; method: string; severity: string; parameters: string[]; last_seen: string; finding_count: number }> = {};
    const severityOrder = ["critical", "high", "medium", "low", "info"];
    for (const f of scopedFindings) {
      const ep = String(f["endpoint"] ?? "");
      if (!ep) continue;
      const method = String(f["http_method"] ?? "GET");
      const key = `${method}||${ep}`;
      if (!endpointMap[key]) {
        endpointMap[key] = { url: ep, method, severity: String(f["severity"]), parameters: [], last_seen: String(f["created_at"]), finding_count: 0 };
      }
      endpointMap[key].finding_count++;
      // Keep highest severity
      if (severityOrder.indexOf(String(f["severity"])) < severityOrder.indexOf(endpointMap[key].severity)) {
        endpointMap[key].severity = String(f["severity"]);
      }
      if (new Date(String(f["created_at"])) > new Date(endpointMap[key].last_seen)) {
        endpointMap[key].last_seen = String(f["created_at"]);
      }
      // Extract parameter names from endpoint URL
      try {
        const urlObj = new URL(ep.startsWith("http") ? ep : `https://x.com${ep}`);
        urlObj.searchParams.forEach((_, k) => {
          if (!endpointMap[key].parameters.includes(k)) endpointMap[key].parameters.push(k);
        });
      } catch { /* ignore */ }
    }
    const endpointInventory = Object.values(endpointMap)
      .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
      .slice(0, 100);

    // Risk heatmap — targets × top categories
    const topCategories = categoryData.slice(0, 6).map((c) => c.name);
    const heatmap = targets.slice(0, 20).map((t) => {
      const domain = String(t["domain"]);
      const row: Record<string, unknown> = { domain };
      for (const cat of topCategories) {
        const worst = scopedFindings
          .filter((f) => {
            try { return new URL(String(f["target_url"])).hostname === domain && String(f["category"]) === cat; } catch { return false; }
          })
          .reduce((worst, f) => {
            const idx = severityOrder.indexOf(String(f["severity"]));
            return idx < severityOrder.indexOf(worst) ? String(f["severity"]) : worst;
          }, "none");
        row[cat] = worst;
      }
      return row;
    });

    // Discovered subdomains across all targets
    const subdomains = targets.flatMap((t) =>
      ((t["subdomains"] as string[]) ?? []).map((s) => ({ subdomain: s, parent: String(t["domain"]), target_id: String(t["_id"]) }))
    );

    // Exposure trend — critical+high per week for last 8 weeks
    const now = Date.now();
    const weeks = Array.from({ length: 8 }, (_, i) => {
      const start = new Date(now - (7 - i) * 7 * 86400000);
      const end = new Date(now - (6 - i) * 7 * 86400000);
      return {
        week: start.toISOString().slice(0, 10),
        critical: scopedFindings.filter((f) => String(f["severity"]) === "critical" && new Date(String(f["created_at"])) >= start && new Date(String(f["created_at"])) < end).length,
        high: scopedFindings.filter((f) => String(f["severity"]) === "high" && new Date(String(f["created_at"])) >= start && new Date(String(f["created_at"])) < end).length,
      };
    });

    // Open ports/services from port scan findings
    const portFindings = scopedFindings.filter((f) =>
      String(f["category"]).toLowerCase().includes("port") ||
      String(f["scanner_name"] ?? "").toLowerCase().includes("port") ||
      String(f["title"]).toLowerCase().includes("open port")
    ).map((f) => ({
      endpoint: String(f["endpoint"]),
      title: String(f["title"]),
      severity: String(f["severity"]),
      target: String(f["target_url"]),
    })).slice(0, 30);

    res.json({
      summary: {
        total_targets: targets.length,
        total_findings: scopedFindings.length,
        critical: scopedFindings.filter((f) => String(f["severity"]) === "critical").length,
        high: scopedFindings.filter((f) => String(f["severity"]) === "high").length,
        unique_endpoints: Object.keys(endpointMap).length,
        unique_categories: categoryData.length,
      },
      category_data: categoryData,
      endpoint_inventory: endpointInventory,
      heatmap,
      heatmap_categories: topCategories,
      subdomains,
      exposure_trend: weeks,
      open_ports: portFindings,
      all_tags: [...new Set(targets.flatMap((t) => (t["tags"] as string[]) ?? []))].sort(),
    });
  } catch (err) {
    logger.error({ err }, "Attack surface error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /targets/:id/monitor — manually trigger attack surface monitoring for a target
router.post("/targets/:id/monitor", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const target = (await col("targets").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!target) return res.status(404).json({ error: "Target not found" });

    // Run in background
    import("../services/monitor/attack-surface-monitor").then(({ runAttackSurfaceMonitorForTarget }) => {
      runAttackSurfaceMonitorForTarget(String(target["_id"]), String(target["url"] ?? "")).catch((err) => {
        logger.error({ err }, "Manual monitor error");
      });
    }).catch(() => {});

    res.json({ ok: true, message: "Attack surface monitoring started in background" });
  } catch (err) {
    logger.error({ err }, "Target monitor error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
