import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

function mapComment(c: Record<string, unknown>) {
  return {
    id: String(c["_id"]),
    body: c["body"] ?? c["text"] ?? "",
    text: c["text"] ?? c["body"] ?? "",
    author: c["author"] ?? "Unknown",
    created_at: c["created_at"],
    edited: c["edited"] ?? false,
    resource: c["resource"] ?? null,
    resource_id: c["resource_id"] ?? c["finding_id"] ?? null,
  };
}

router.get("/findings/:id/comments", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const comments = await col("finding_comments").find({ finding_id: id }).sort({ created_at: 1 }).toArray() as Array<Record<string,unknown>>;
    res.json(comments.map(mapComment));
  } catch(err) { logger.error({err},"list comments error"); res.status(500).json({ error: "Internal server error" }); }
});

router.post("/findings/:id/comments", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    const { text, author } = req.body as { text?: string; author?: string };
    if (!text) return res.status(400).json({ error: "text required" });
    const insert = await col("finding_comments").insertOne({ finding_id: id, text, author: author ?? "Unknown", created_at: new Date() });
    const saved = await col("finding_comments").findOne({ _id: insert.insertedId }) as Record<string,unknown>;
    res.status(201).json(mapComment(saved));
  } catch(err) { logger.error({err},"create comment error"); res.status(500).json({ error: "Internal server error" }); }
});

router.delete("/findings/:findingId/comments/:commentId", requireAuth, async (req, res) => {
  try {
    const commentId = String(req.params["commentId"]);
    await col("finding_comments").deleteOne({ _id: new ObjectId(commentId) } as Record<string,unknown>);
    res.json({ ok: true });
  } catch(err) { logger.error({err},"delete comment error"); res.status(500).json({ error: "Internal server error" }); }
});

router.get("/comments", requireAuth, async (req, res) => {
  try {
    const resource = req.query["resource"] as string | undefined;
    const resourceId = req.query["resource_id"] as string | undefined;
    if (!resource || !resourceId) return res.status(400).json({ error: "resource and resource_id query params required" });
    const filter: Record<string, unknown> = { resource, resource_id: resourceId };
    if (resource === "finding") {
      filter["finding_id"] = resourceId;
      delete filter["resource"];
      delete filter["resource_id"];
    }
    const comments = await col("finding_comments").find(filter).sort({ created_at: 1 }).toArray() as Array<Record<string,unknown>>;
    res.json(comments.map(mapComment));
  } catch(err) { logger.error({err},"generic list comments error"); res.status(500).json({ error: "Internal server error" }); }
});

router.post("/comments", requireAuth, async (req, res) => {
  try {
    const { resource, resource_id, body } = req.body as { resource?: string; resource_id?: string; body?: string };
    if (!body) return res.status(400).json({ error: "body required" });
    if (!resource || !resource_id) return res.status(400).json({ error: "resource and resource_id required" });
    const session = (req as unknown as { session: { username?: string } }).session;
    const doc: Record<string, unknown> = {
      resource, resource_id, body, text: body,
      author: session.username ?? "Unknown",
      created_at: new Date(),
    };
    if (resource === "finding") doc["finding_id"] = resource_id;
    const insert = await col("finding_comments").insertOne(doc);
    const saved = await col("finding_comments").findOne({ _id: insert.insertedId }) as Record<string,unknown>;
    res.status(201).json(mapComment(saved));
  } catch(err) { logger.error({err},"generic create comment error"); res.status(500).json({ error: "Internal server error" }); }
});

router.delete("/comments/:commentId", requireAuth, async (req, res) => {
  try {
    const commentId = String(req.params["commentId"]);
    const result = await col("finding_comments").deleteOne({ _id: new ObjectId(commentId) } as Record<string,unknown>);
    if (result.deletedCount === 0) return res.status(404).json({ error: "Comment not found" });
    res.json({ ok: true });
  } catch(err) { logger.error({err},"generic delete comment error"); res.status(500).json({ error: "Internal server error" }); }
});

export default router;
