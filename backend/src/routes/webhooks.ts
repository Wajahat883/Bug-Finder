import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

export async function triggerWebhooks(event: string, payload: Record<string,unknown>) {
  try {
    const hooks = await col("webhooks").find({ events: event, enabled: true }).toArray() as Array<Record<string,unknown>>;
    for (const hook of hooks) {
      fetch(String(hook["url"]), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(hook["secret"] ? { "X-Webhook-Secret": String(hook["secret"]) } : {}) },
        body: JSON.stringify({ event, timestamp: new Date().toISOString(), ...payload }),
      }).catch(err => logger.warn({ err, url: hook["url"] }, "Webhook delivery failed"));
    }
  } catch(err) { logger.error({err}, "triggerWebhooks error"); }
}

router.get("/webhooks", requireAuth, async (_req, res) => {
  try {
    const hooks = await col("webhooks").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string,unknown>>;
    res.json(hooks.map(h => ({ ...h, id: String(h["_id"]) })));
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.post("/webhooks", requireAuth, async (req, res) => {
  try {
    const { url, events, secret, name } = req.body as { url?: string; events?: string[]; secret?: string; name?: string };
    if (!url || !events?.length) return res.status(400).json({ error: "url and events[] required" });
    const insert = await col("webhooks").insertOne({ url, events, secret: secret ?? null, name: name ?? url, enabled: true, created_at: new Date(), delivery_count: 0, last_triggered: null });
    const saved = await col("webhooks").findOne({ _id: insert.insertedId }) as Record<string,unknown>;
    res.status(201).json({ ...saved, id: String(saved["_id"]) });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.patch("/webhooks/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { enabled } = req.body as { enabled?: boolean };
    await col("webhooks").updateOne({ _id: new ObjectId(id) } as Record<string,unknown>, { $set: { enabled } });
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.delete("/webhooks/:id", requireAuth, async (req, res) => {
  try {
    await col("webhooks").deleteOne({ _id: new ObjectId(req.params.id) } as Record<string,unknown>);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.post("/webhooks/:id/test", requireAuth, async (req, res) => {
  try {
    const hook = await col("webhooks").findOne({ _id: new ObjectId(req.params.id) } as Record<string,unknown>) as Record<string,unknown> | null;
    if (!hook) return res.status(404).json({ error: "Not found" });
    const r = await fetch(String(hook["url"]), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event: "test", timestamp: new Date().toISOString(), message: "Bug Finder Pro webhook test" }) }).catch(() => null);
    res.json({ ok: r?.ok ?? false, status: r?.status ?? 0 });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

export default router;
