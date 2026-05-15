import { Router } from "express";
import { col } from "../lib/db";
import { requireAdmin } from "../middlewares/rbac";
import { formatAsCef, verifyAuditChain } from "../lib/audit";

const router = Router();

router.get("/siem/export", requireAdmin, async (req, res) => {
  try {
    const { format = "json", limit = "500", since } = req.query as Record<string, string>;
    const maxLimit = Math.min(parseInt(limit) || 500, 5000);
    const query: Record<string, unknown> = {};
    if (since) query["created_at"] = { $gte: new Date(since) };

    const entries = await col("audit_log").find(query).sort({ created_at: -1 }).limit(maxLimit).toArray() as Array<Record<string, unknown>>;

    if (format === "cef") {
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", `attachment; filename="audit-${Date.now()}.cef"`);
      res.send(entries.map(e => formatAsCef(e)).join("\n"));
    } else if (format === "splunk") {
      res.setHeader("Content-Type", "application/x-ndjson");
      res.setHeader("Content-Disposition", `attachment; filename="audit-${Date.now()}.ndjson"`);
      res.send(entries.map(e => JSON.stringify({
        time: e["created_at"] instanceof Date ? (e["created_at"] as Date).getTime() / 1000 : Date.now() / 1000,
        host: process.env["APP_URL"] ?? "bugfinder",
        source: "bugfinder:audit",
        sourcetype: "bugfinder:audit",
        event: { ...e, _id: String(e["_id"]) },
      })).join("\n"));
    } else {
      res.json(entries.map(e => ({ ...e, _id: String(e["_id"]) })));
    }
  } catch {
    res.status(500).json({ error: "Export failed" });
  }
});

router.get("/siem/audit-chain/verify", requireAdmin, async (_req, res) => {
  try {
    const result = await verifyAuditChain(500);
    res.json(result);
  } catch {
    res.status(500).json({ error: "Verification failed" });
  }
});

export default router;
