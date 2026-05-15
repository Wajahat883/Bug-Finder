import { Router } from "express";
import { col } from "../lib/db";
import { requireAuth } from "../middlewares/rbac";
import { logger } from "../lib/logger";

const router = Router();

router.post("/ai/feedback", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const { endpoint, rating, content } = req.body as {
      endpoint?: string;
      rating?: string;
      content?: string;
    };
    if (!endpoint || !rating || !["positive", "negative"].includes(rating)) {
      return res.status(400).json({ error: "endpoint and rating (positive/negative) are required" });
    }
    await col("ai_feedback").insertOne({
      user_id: sess.userId,
      endpoint,
      rating,
      content_preview: String(content ?? "").slice(0, 500),
      created_at: new Date(),
    });
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "AI feedback error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/ai/feedback/stats", requireAuth, async (_req, res) => {
  try {
    const all = await col("ai_feedback").find({}).toArray() as Array<Record<string, unknown>>;
    const positive = all.filter(f => f["rating"] === "positive").length;
    const negative = all.filter(f => f["rating"] === "negative").length;
    const byEndpoint: Record<string, { positive: number; negative: number }> = {};
    for (const f of all) {
      const ep = String(f["endpoint"] ?? "unknown");
      if (!byEndpoint[ep]) byEndpoint[ep] = { positive: 0, negative: 0 };
      if (f["rating"] === "positive") byEndpoint[ep].positive++;
      else byEndpoint[ep].negative++;
    }
    res.json({
      total: all.length,
      positive,
      negative,
      satisfaction_rate: all.length ? Math.round((positive / all.length) * 100) : 0,
      by_endpoint: byEndpoint,
    });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
