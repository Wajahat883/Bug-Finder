import { Router } from "express";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import { z } from "zod";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const VALID_EVENTS = ["scan.completed", "finding.created", "finding.critical", "finding.high", "remediation.created"] as const;
const createWebhookSchema = z.object({
  url: z.string().url("Must be a valid URL"),
  events: z.array(z.enum(VALID_EVENTS)).min(1, "At least one event is required"),
  secret: z.string().max(256).optional(),
  name: z.string().max(100).optional(),
});
const patchWebhookSchema = z.object({ enabled: z.boolean() });

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
        headers["X-Hub-Signature-256"] = signWebhookPayload(secret, body);
        headers["X-Webhook-ID"] = String(hook["_id"]);
      }
      fetch(String(hook["url"]), { method: "POST", headers, body })
        .then(async (r) => {
          await col("webhooks").updateOne(
            { _id: hook["_id"] } as Record<string,unknown>,
            { $set: { last_triggered: new Date(), last_status: r.status, last_ok: r.ok }, $inc: { delivery_count: 1 } } as Record<string,unknown>
          );
        })
        .catch(err => {
          logger.warn({ err, url: hook["url"] }, "Webhook delivery failed");
          col("webhooks").updateOne(
            { _id: hook["_id"] } as Record<string,unknown>,
            { $set: { last_triggered: new Date(), last_status: 0, last_ok: false } }
          ).catch(() => {});
        });
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
    const parsed = createWebhookSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });
    const { url, events, secret, name } = parsed.data;
    const insert = await col("webhooks").insertOne({ url, events, secret: secret ?? null, name: name ?? url, enabled: true, created_at: new Date(), delivery_count: 0, last_triggered: null });
    const saved = await col("webhooks").findOne({ _id: insert.insertedId }) as Record<string,unknown>;
    res.status(201).json({ ...saved, id: String(saved["_id"]) });
  } catch(err) { res.status(500).json({ error: "Internal server error" }); }
});

router.patch("/webhooks/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const parsed = patchWebhookSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });
    const { enabled } = parsed.data;
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
