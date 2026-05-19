import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

// GET /webhooks/delivery-log — View delivery history
router.get("/webhooks/delivery-log", requireAuth, async (req, res) => {
  try {
    const webhookId = req.query["webhook_id"] as string | undefined;
    const limit = parseInt(String(req.query["limit"] ?? "50"));
    const query: Record<string, unknown> = {};
    if (webhookId) query["webhook_id"] = webhookId;
    const logs = await col("webhook_deliveries").find(query).sort({ sent_at: -1 }).limit(limit).toArray() as Array<Record<string, unknown>>;
    res.json(logs.map((l) => ({
      id: String(l["_id"]),
      webhook_id: l["webhook_id"],
      webhook_name: l["webhook_name"],
      event: l["event"],
      url: l["url"],
      status_code: l["status_code"],
      success: l["success"],
      response_body: String(l["response_body"] ?? "").slice(0, 500),
      error: l["error"] ?? null,
      retry_count: l["retry_count"] ?? 0,
      sent_at: l["sent_at"],
      duration_ms: l["duration_ms"],
    })));
  } catch (err) {
    logger.error({ err }, "Delivery log error");
    res.status(500).json({ error: "Failed to load delivery log" });
  }
});

// POST /webhooks/delivery-log/retry/:id — Retry a failed delivery
router.post("/webhooks/delivery-log/retry/:id", requireAuth, async (req, res) => {
  try {
    const delivery = await col("webhook_deliveries").findOne({ _id: new ObjectId(String(req.params.id)) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!delivery) return res.status(404).json({ error: "Delivery not found" });

    const url = String(delivery["url"] ?? "");
    try {
      const parsed = new URL(url);
      if (!["https:", "http:"].includes(parsed.protocol)) {
        return res.status(400).json({ error: "Invalid webhook URL protocol" });
      }
    } catch {
      return res.status(400).json({ error: "Invalid webhook URL" });
    }

    const startTime = Date.now();
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: delivery["event"], retry: true, original_id: req.params.id }),
        signal: AbortSignal.timeout(10000),
      });
      const body = await response.text().catch(() => "");
      await col("webhook_deliveries").updateOne(
        { _id: new ObjectId(String(req.params.id)) } as Record<string, unknown>,
        { $set: { status_code: response.status, success: response.ok, response_body: body, retry_count: (Number(delivery["retry_count"]) || 0) + 1, duration_ms: Date.now() - startTime, sent_at: new Date(), error: null } }
      );
      res.json({ ok: response.ok, status: response.status });
    } catch (err) {
      await col("webhook_deliveries").updateOne(
        { _id: new ObjectId(String(req.params.id)) } as Record<string, unknown>,
        { $set: { error: err instanceof Error ? err.message : "Retry failed", retry_count: (Number(delivery["retry_count"]) || 0) + 1, sent_at: new Date() } }
      );
      res.json({ ok: false, error: err instanceof Error ? err.message : "Unknown" });
    }
  } catch (err) {
    res.status(500).json({ error: "Retry failed" });
  }
});

// DELETE /webhooks/delivery-log — Clear old logs
router.delete("/webhooks/delivery-log", requireAuth, async (req, res) => {
  try {
    const days = parseInt(String(req.query["older_than"] ?? "30"));
    const cutoff = new Date(Date.now() - days * 86400000);
    const result = await col("webhook_deliveries").deleteMany({ sent_at: { $lt: cutoff } } as Record<string, unknown>);
    res.json({ ok: true, deleted: (result as { deletedCount?: number }).deletedCount ?? 0 });
  } catch (err) {
    logger.error({ err }, "Clear delivery log error");
    res.status(500).json({ error: "Failed to clear logs" });
  }
});

export default router;
