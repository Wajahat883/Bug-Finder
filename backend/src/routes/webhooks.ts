import { Router } from "express";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

function signWebhookPayload(secret: string, body: string): string {
  return "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
}

export async function triggerWebhooks(event: string, payload: Record<string,unknown>) {
  try {
    const hooks = await col("webhooks").find({ events: event, enabled: true }).toArray() as Array<Record<string,unknown>>;
    for (const hook of hooks) {
      const body = JSON.stringify({ event, timestamp: new Date().toISOString(), ...payload });
      const secret = hook["secret"] ? String(hook["secret"]) : null;
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (secret) {
        // HMAC-SHA256 signature — receivers can verify: X-Hub-Signature-256 header
        headers["X-Hub-Signature-256"] = signWebhookPayload(secret, body);
        headers["X-Webhook-ID"] = String(hook["_id"]);
      }
      fetch(String(hook["url"]), { method: "POST", headers, body })
        .catch(err => logger.warn({ err, url: hook["url"] }, "Webhook delivery failed"));
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
