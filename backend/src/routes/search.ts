import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

// GET /search — Full-text search across findings, targets, and scans
router.get("/search", requireAuth, async (req, res) => {
  try {
    const q = (req.query["q"] as string)?.trim();
    const type = req.query["type"] as string | undefined;
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "20"));

    if (!q || q.length < 2) {
      return res.json({ findings: [], targets: [], scans: [], total: 0 });
    }

    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const uf = session?.role !== "admin" ? { user_id: session?.userId ?? null } : {};

    const regex = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    const searchQuery = {
      ...uf,
      $or: [
        { title: { $regex: regex } },
        { description: { $regex: regex } },
        { evidence: { $regex: regex } },
        { endpoint: { $regex: regex } },
        { cwe_id: { $regex: regex } },
        { category: { $regex: regex } },
      ],
    };

    const [findings, targets, scans] = await Promise.all([
      !type || type === "findings"
        ? col("findings")
            .find(searchQuery)
            .sort({ created_at: -1 })
            .skip((page - 1) * pageSize)
            .limit(pageSize)
            .toArray()
        : Promise.resolve([]),
      !type || type === "targets"
        ? col("targets")
            .find({ ...uf, $or: [{ domain: { $regex: regex } }, { url: { $regex: regex } }] })
            .limit(10)
            .toArray()
        : Promise.resolve([]),
      !type || type === "scans"
        ? col("scan_jobs")
            .find({ ...uf, $or: [{ target_url: { $regex: regex } }, { ai_summary: { $regex: regex } }] })
            .sort({ created_at: -1 })
            .limit(10)
            .toArray()
        : Promise.resolve([]),
    ]);

    const formatted = {
      findings: (findings as Array<Record<string, unknown>>).map((f) => ({
        id: String(f["_id"]),
        title: f["title"],
        severity: f["severity"],
        endpoint: f["endpoint"],
        category: f["category"],
        cvss_score: f["cvss_score"],
        cwe_id: f["cwe_id"],
        description: String(f["description"] ?? "").slice(0, 200),
        created_at: f["created_at"],
      })),
      targets: (targets as Array<Record<string, unknown>>).map((t) => ({
        id: String(t["_id"]),
        domain: t["domain"],
        url: t["url"],
        risk_score: t["risk_score"],
      })),
      scans: (scans as Array<Record<string, unknown>>).map((s) => ({
        id: String(s["_id"]),
        target_url: s["target_url"],
        status: s["status"],
        risk_score: s["risk_score"],
        findings_count: s["findings_count"],
        created_at: s["created_at"],
      })),
      total: (findings as Array<unknown>).length + (targets as Array<unknown>).length + (scans as Array<unknown>).length,
    };

    res.json(formatted);
  } catch (err) {
    logger.error({ err }, "Search error");
    res.status(500).json({ error: "Search failed" });
  }
});

export default router;
