import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

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
    tags: t["tags"] ?? [],
  };
}

router.get("/targets", async (req, res) => {
  try {
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "20"));
    const search = req.query["search"] as string | undefined;

    const query: Record<string, unknown> = {};
    if (search) query["domain"] = { $regex: search, $options: "i" };

    const all = (await col("targets").find(query).sort({ last_scanned: -1 }).toArray()) as Array<Record<string, unknown>>;
    const total = all.length;
    const items = all.slice((page - 1) * pageSize, page * pageSize).map(formatTarget);

    res.json({ items, total, page, page_size: pageSize });
  } catch (err) {
    logger.error({ err }, "List targets error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/targets/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const target = (await col("targets").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!target) return res.status(404).json({ error: "Target not found" });

    res.json(formatTarget(target));
  } catch (err) {
    logger.error({ err }, "Get target error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
