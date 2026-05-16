import { Router } from "express";
import { col } from "../lib/db";
import { requireAdmin } from "../middlewares/rbac";

const router = Router();

router.get("/audit-log", requireAdmin, async (req, res) => {
  try {
    const logs = await col("audit_log").find({}).sort({ created_at: -1 }).toArray();
    res.json(logs);
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/audit-log/export", requireAdmin, async (req, res) => {
  try {
    const { format = "csv", from, to } = req.query as Record<string, string>;
    const query: Record<string, unknown> = {};
    if (from || to) {
      query["created_at"] = {
        ...(from ? { $gte: new Date(from) } : {}),
        ...(to ? { $lte: new Date(to) } : {}),
      };
    }
    const entries = await col("audit_log").find(query).sort({ created_at: -1 }).limit(10000).toArray() as Array<Record<string, unknown>>;

    if (format === "json") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="audit-log.json"`);
      return res.json(entries.map(e => ({
        id: String(e["_id"]),
        action: e["action"],
        actor: e["username"] ?? e["userId"],
        resource: e["resource"],
        timestamp: e["created_at"],
        ip: e["ip"],
        details: e["details"],
      })));
    }

    // CSV
    const header = "timestamp,actor,action,resource,resource_id,ip,details\n";
    const rows = entries.map(e => [
      String(e["created_at"] ?? ""),
      String(e["username"] ?? e["userId"] ?? ""),
      String(e["action"] ?? ""),
      String(e["resource"] ?? ""),
      String(e["resource_id"] ?? ""),
      String(e["ip"] ?? ""),
      JSON.stringify(e["details"] ?? {}).replace(/"/g, '""'),
    ].map(v => `"${v}"`).join(",")).join("\n");

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="audit-log.csv"`);
    res.send(header + rows);
  } catch {
    res.status(500).json({ error: "Export failed" });
  }
});

export default router;
