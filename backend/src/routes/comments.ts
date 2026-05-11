import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

router.get("/findings/:id/comments", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const comments = await col("finding_comments").find({ finding_id: id }).sort({ created_at: 1 }).toArray() as Array<Record<string,unknown>>;
    res.json(comments.map(c => ({ ...c, id: String(c["_id"]) })));
  } catch(err) { logger.error({err},"list comments error"); res.status(500).json({ error: "Internal server error" }); }
});

router.post("/findings/:id/comments", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { text, author } = req.body as { text?: string; author?: string };
    if (!text) return res.status(400).json({ error: "text required" });
    const insert = await col("finding_comments").insertOne({ finding_id: id, text, author: author ?? "Unknown", created_at: new Date() });
    const saved = await col("finding_comments").findOne({ _id: insert.insertedId }) as Record<string,unknown>;
    res.status(201).json({ ...saved, id: String(saved["_id"]) });
  } catch(err) { logger.error({err},"create comment error"); res.status(500).json({ error: "Internal server error" }); }
});

router.delete("/findings/:findingId/comments/:commentId", requireAuth, async (req, res) => {
  try {
    const { commentId } = req.params;
    await col("finding_comments").deleteOne({ _id: new ObjectId(commentId) } as Record<string,unknown>);
    res.json({ ok: true });
  } catch(err) { logger.error({err},"delete comment error"); res.status(500).json({ error: "Internal server error" }); }
});

export default router;
