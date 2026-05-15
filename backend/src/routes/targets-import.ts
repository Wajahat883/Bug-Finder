import { Router } from "express";
import { col } from "../lib/db";
import { requireAuth } from "../middlewares/rbac";
import { logger } from "../lib/logger";
import { auditFromReq } from "../lib/audit";

const router = Router();

router.post("/targets/import", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const { csv_data } = req.body as { csv_data?: string };
    if (!csv_data) return res.status(400).json({ error: "csv_data (base64) is required" });

    const csvText = Buffer.from(csv_data, "base64").toString("utf-8");
    const lines = csvText.split(/\r?\n/).filter(l => l.trim());
    const firstLine = lines[0]?.toLowerCase() ?? "";
    const dataLines = firstLine.includes("url") || firstLine.includes("target") ? lines.slice(1) : lines;

    const imported: string[] = [];
    const skipped: string[] = [];

    for (const line of dataLines.slice(0, 200)) {
      const parts = line.split(",");
      const rawUrl = parts[0]?.trim() ?? "";
      if (!rawUrl) continue;

      let url = rawUrl;
      if (!url.startsWith("http")) url = "https://" + url;

      try { new URL(url); } catch {
        skipped.push(rawUrl);
        continue;
      }

      const label = parts[1]?.trim() ?? "";
      const tags = parts[2]?.trim()?.split(";").filter(Boolean) ?? [];

      await col("targets").updateOne(
        { url, user_id: sess.userId } as Record<string, unknown>,
        { $set: { url, label: label || url, tags, user_id: sess.userId, updated_at: new Date() }, $setOnInsert: { created_at: new Date() } } as Record<string, unknown>,
        { upsert: true }
      );
      imported.push(url);
    }

    await auditFromReq(req, "targets.import", "targets", undefined, { imported_count: imported.length });
    res.json({ ok: true, imported: imported.length, skipped: skipped.length, skipped_urls: skipped.slice(0, 10) });
  } catch (err) {
    logger.error({ err }, "Target import error");
    res.status(500).json({ error: "Import failed" });
  }
});

export default router;
