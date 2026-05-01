import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { formatFinding } from "./scans";

const router = Router();

router.get("/findings", async (req, res) => {
  try {
    const page = parseInt(String(req.query["page"] ?? "1"));
    const pageSize = parseInt(String(req.query["page_size"] ?? "20"));
    const severity = req.query["severity"] as string | undefined;
    const valStatus = req.query["validation_status"] as string | undefined;
    const search = req.query["search"] as string | undefined;
    const scanJobId = req.query["scan_job_id"] as string | undefined;

    const query: Record<string, unknown> = {};
    if (severity) query["severity"] = severity;
    if (valStatus) query["validation_status"] = valStatus;
    if (search) query["title"] = { $regex: search, $options: "i" };
    if (scanJobId && ObjectId.isValid(scanJobId)) {
      query["scan_job_id"] = new ObjectId(scanJobId);
    }

    const all = (await col("findings").find(query).sort({ created_at: -1 }).toArray()) as Array<Record<string, unknown>>;
    const total = all.length;
    const items = all.slice((page - 1) * pageSize, page * pageSize).map(formatFinding);

    res.json({ items, total, page, page_size: pageSize });
  } catch (err) {
    logger.error({ err }, "List findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/findings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const finding = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    res.json(formatFinding(finding));
  } catch (err) {
    logger.error({ err }, "Get finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/findings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const body = req.body as { validation_status?: string; notes?: string };
    const updates: Record<string, unknown> = {};
    if (body.validation_status) updates["validation_status"] = body.validation_status;
    if (body.notes) updates["notes"] = body.notes;

    await col("findings").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: updates });
    const updated = (await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
    res.json(formatFinding(updated));
  } catch (err) {
    logger.error({ err }, "Update finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
